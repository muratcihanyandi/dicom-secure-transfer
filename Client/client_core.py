"""DICOM Secure istemci cekirdegi.

Guvenlik modeli (v2):
- Lorenz kaotik sistemi + donanim entropisi (os.urandom) birleserek anahtar
  materyali uretir (HKDF-SHA256 ile turetilir).
- Piksel verisi ChaCha20-Poly1305 AEAD ile sifrelenir: hem gizlilik hem
  butunluk saglanir (tahrifatta InvalidTag firlatilir).
- Her dosya icin HKDF ile ayri alt anahtar + rastgele 12 bayt nonce kullanilir.
- AAD (ek dogrulama verisi) dosya adi, sekil ve dtype'i baglar; dosya
  degistirlirse cozme reddedilir.
- Aktarim TLS uzerinden yapilir; anahtar dosyalari TLS kanalindan gider.
"""

import hashlib
import hmac
import json
import os
import secrets
import socket
import ssl
import time

import numpy as np
import pydicom
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from pydicom.uid import ExplicitVRLittleEndian
from scipy.integrate import solve_ivp

PROTOCOL_VERSION = "v2"
CHUNK_SIZE = 64 * 1024

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(BASE_DIR, "config.json")

DEFAULT_CONFIG = {
    "server_ip": "127.0.0.1",
    "server_port": 5000,
    "tls_enabled": True,
    "tls_ca_path": "../certs/ca.pem",
    "anonymize_metadata": True,
    "dataset_path": "dataset",
    "encrypted_folder": "Encrypted_File",
}

# Gercek DICOM'da hasta kimligini tasiyabilecek etiketler
ANONYMIZE_TAGS = [
    "PatientName", "PatientID", "PatientBirthDate", "PatientSex",
    "PatientAge", "PatientAddress", "AccessionNumber", "StudyID",
    "ReferringPhysicianName", "RequestingPhysician", "InstitutionName",
    "OperatorsName", "PatientTelephoneNumbers",
]


def load_config():
    cfg = dict(DEFAULT_CONFIG)
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                cfg.update(json.load(f))
        except (json.JSONDecodeError, OSError):
            pass  # bozuk config -> varsayilanlarla devam
    return cfg


def save_config(cfg):
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)


def resolve_ca_path(cfg):
    """tls_ca_path'i Client klasorune gore cozup mutlak yol dondurur."""
    ca = cfg.get("tls_ca_path", "")
    if not ca:
        return None
    path = ca if os.path.isabs(ca) else os.path.normpath(os.path.join(BASE_DIR, ca))
    return path if os.path.exists(path) else None


# ------------------------------------------------------------------
# Anahtar uretimi
# ------------------------------------------------------------------

def lorenz_system(t, state, sigma=10.0, rho=28.0, beta=8.0 / 3.0):
    x, y, z = state
    return [
        sigma * (y - x),
        x * (rho - z) - y,
        x * y - beta * z,
    ]


def lorenz_chaos_seed(initial_state=None):
    """Lorenz izinin SHA-256 ozetini dondurur (kagittaki kaotik bilesen)."""
    if initial_state is None:
        # Baslangic durumu da entropiden gelir; sabit degil.
        initial_state = [float(secrets.randbits(32)) / 2**32 for _ in range(3)]
    t_span = (0, 100)
    t_eval = np.linspace(*t_span, 1000)
    sol = solve_ivp(lorenz_system, t_span, initial_state, t_eval=t_eval, method="RK45")
    if not sol.success:
        raise RuntimeError("Lorenz sistemi cozulemedi: " + str(sol.message))
    combined = sol.y[0] + sol.y[1] + sol.y[2]
    return hashlib.sha256(combined.tobytes()).digest()


def derive_master_key(session_id):
    """Oturum ana anahtarini uretir: Lorenz tohumu XOR donanim entropisi -> HKDF."""
    chaos = lorenz_chaos_seed()
    entropy = secrets.token_bytes(32)
    ikm = bytes(a ^ b for a, b in zip(chaos, entropy))

    hkdf = HKDF(algorithm=hashes.SHA256(), length=32,
                salt=session_id.encode("utf-8"), info=b"dicom-secure/v2/master")
    return hkdf.derive(ikm)


def derive_file_key(master_key, session_id, file_name):
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32,
                salt=session_id.encode("utf-8"),
                info=f"dicom-secure/v2/file|{file_name}".encode("utf-8"))
    return hkdf.derive(master_key)


def build_aad(session_id, file_name, shape, dtype):
    payload = {
        "session": session_id,
        "file": file_name,
        "shape": list(shape),
        "dtype": str(dtype),
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


# ------------------------------------------------------------------
# DICOM sifreleme
# ------------------------------------------------------------------

def anonymize(ds):
    for tag in ANONYMIZE_TAGS:
        if tag in ds:
            del ds[tag]
    ds.PatientIdentityRemoved = "YES"
    ds.DeidentificationMethod = "DICOM-Secure v2 (client-side)"


def save_dicom_compat(ds, path):
    """pydicom 2.x ve 3.x uyumlu kaydetme."""
    ds.file_meta.TransferSyntaxUID = ExplicitVRLittleEndian
    try:
        ds.save_as(path, enforce_file_format=True)  # pydicom >= 3.0
    except TypeError:
        ds.is_implicit_VR = False  # pydicom < 3.0
        ds.is_little_endian = True
        ds.save_as(path)


def encrypt_dicom_file(src_path, dst_path, master_key, session_id, anonymize_flag=True):
    """Bir DICOM'un piksel verisini AEAD ile sifreler.

    Donus: (basari, bilgi) — bilgi; .key dosyasina yazilacak JSON verisini
    (key/nonce/aad) ve boyut/ sure gibi metrikleri icerir.
    """
    start = time.perf_counter()
    if not os.path.exists(src_path):
        return False, {"error": f"Kaynak bulunamadi: {src_path}"}

    try:
        ds = pydicom.dcmread(src_path)
        if "PixelData" not in ds:
            return False, {"error": "DICOM dosyasinda piksel verisi yok"}

        if ds.file_meta.TransferSyntaxUID.is_compressed:
            ds.decompress()

        pixel_array = ds.pixel_array
        shape, dtype = pixel_array.shape, pixel_array.dtype
        flat_data = pixel_array.tobytes()

        file_name = os.path.basename(dst_path)
        file_key = derive_file_key(master_key, session_id, file_name)
        nonce = secrets.token_bytes(12)  # ChaCha20-Poly1305 icin 96-bit nonce

        aad = build_aad(session_id, file_name, shape, dtype)
        cipher = ChaCha20Poly1305(file_key)
        encrypted = cipher.encrypt(nonce, flat_data, aad)

        if anonymize_flag:
            anonymize(ds)

        ds.PixelData = encrypted
        save_dicom_compat(ds, dst_path)

        key_info = {
            "version": 2,
            "algorithm": "chacha20-poly1305",
            "session_id": session_id,
            "file": file_name,
            "key": file_key.hex(),
            "nonce": nonce.hex(),
            "aad": json.loads(aad.decode("utf-8")),
            "shape": list(shape),
            "dtype": str(dtype),
        }
        with open(dst_path + ".key", "w", encoding="utf-8") as kf:
            json.dump(key_info, kf, indent=2)

        elapsed = time.perf_counter() - start
        return True, {
            "file": file_name,
            "bytes": len(flat_data),
            "elapsed": elapsed,
            "key_info": key_info,
        }
    except Exception as exc:
        return False, {"error": f"{os.path.basename(src_path)}: {exc}"}


def make_thumbnail(src_path, max_px=96):
    """GUI onizlemesi icin kucuk bir goruntude PIL Image dondurur."""
    from PIL import Image

    ds = pydicom.dcmread(src_path)
    if "PixelData" not in ds:
        return None
    if ds.file_meta.TransferSyntaxUID.is_compressed:
        ds.decompress()
    arr = ds.pixel_array

    if arr.ndim == 2:
        img = Image.fromarray(arr.astype(np.uint8), mode="L")
    elif arr.ndim == 3 and arr.shape[2] == 3:
        img = Image.fromarray(arr.astype(np.uint8), mode="RGB")
    else:
        arr2 = arr.reshape(arr.shape[0], -1)
        img = Image.fromarray((arr2 / max(arr2.max(), 1) * 255).astype(np.uint8), mode="L")

    img.thumbnail((max_px, max_px))
    return img


# ------------------------------------------------------------------
# Aktarim istemcisi (TLS)
# ------------------------------------------------------------------

def _recv_exact(sock, n):
    chunks = bytearray()
    while len(chunks) < n:
        chunk = sock.recv(min(n - len(chunks), CHUNK_SIZE))
        if not chunk:
            raise ConnectionError("Baglanti erken kapandi")
        chunks.extend(chunk)
    return bytes(chunks)


def _recv_line(sock, buffer):
    while b"\n" not in buffer:
        chunk = sock.recv(CHUNK_SIZE)
        if not chunk:
            raise ConnectionError("Baglanti erken kapandi (satir beklenirken)")
        buffer += chunk
    line, buffer = buffer.split(b"\n", 1)
    return line.decode("utf-8").strip(), buffer


def _open_connection(cfg):
    raw = socket.create_connection((cfg["server_ip"], int(cfg["server_port"])), timeout=15)
    raw.settimeout(30)
    if cfg.get("tls_enabled", True):
        ca_path = resolve_ca_path(cfg)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        if ca_path:
            context.load_verify_locations(cafile=ca_path)
            context.check_hostname = False  # IP tabanli pinleme; CA dogrulamasi aktif
        else:
            raw.close()
            raise ConnectionError("TLS acik ama CA sertifikasi bulunamadi. "
                                  "tools/generate_certs.py dosyasini calistirin.")
        return context.wrap_socket(raw, server_hostname=cfg["server_ip"])
    return raw


def send_session(folder_path, meta, cfg, log=None, progress=None):
    """Bir oturum klasorunu (dcm + key) sunucuya gonderir.

    progress(idx, total, sent_bytes, total_bytes) her dosya sonrasi cagrilir.
    Donus: (basari, ozet) — ozet; gonderilen dosya sayisi, bayt, sure, hiz.
    """
    def say(msg):
        if log:
            log(msg)

    files = sorted(
        f for f in os.listdir(folder_path)
        if f.endswith(".dcm") or f.endswith(".key")
    )
    if not files:
        return False, {"error": "Gonderilecek dosya yok"}

    total_bytes = sum(os.path.getsize(os.path.join(folder_path, f)) for f in files)
    start = time.perf_counter()

    try:
        sock = _open_connection(cfg)
        tls_state = "TLS" if cfg.get("tls_enabled", True) else "duz TCP"
        with sock:
            # Surum el sikismasi
            sock.sendall(f"HELLO {PROTOCOL_VERSION}\n".encode("utf-8"))
            reply, buf = _recv_line(sock, b"")
            if reply != f"OK {PROTOCOL_VERSION}":
                return False, {"error": f"Sunucu surum uyusmazligi: {reply}"}

            say(f"Baglanti kuruldu ({tls_state}).")

            # Oturum ustverileri
            sock.sendall(("META:" + json.dumps(meta, ensure_ascii=False) + "\n").encode("utf-8"))
            sock.sendall(b"SESSION_START\n")

            sent_bytes = 0
            for idx, file_name in enumerate(files, start=1):
                file_path = os.path.join(folder_path, file_name)
                size = os.path.getsize(file_path)
                sock.sendall(f"FILENAME:{file_name}\n".encode("utf-8"))
                sock.sendall(f"SIZE:{size}\n".encode("utf-8"))

                with open(file_path, "rb") as f:
                    while True:
                        chunk = f.read(CHUNK_SIZE)
                        if not chunk:
                            break
                        sock.sendall(chunk)
                sent_bytes += size
                if progress:
                    progress(idx, len(files), sent_bytes, total_bytes)
                say(f"{file_name} gonderildi ({size:,} bayt).")

            sock.sendall(b"SESSION_END\n")
            final, buf = _recv_line(sock, buf)
            if not final.startswith("RESULT:"):
                return False, {"error": f"Sunucudan belenmeyen yanit: {final}"}
            result = json.loads(final[len("RESULT:"):])
            say(f"Sunucu onayi: {result.get('received', '?')} dosya alindi.")

        elapsed = time.perf_counter() - start
        return True, {
            "files": len(files),
            "bytes": sent_bytes,
            "elapsed": elapsed,
            "throughput": sent_bytes / elapsed if elapsed > 0 else 0,
            "server_result": result,
        }
    except Exception as exc:
        return False, {"error": str(exc), "elapsed": time.perf_counter() - start}
