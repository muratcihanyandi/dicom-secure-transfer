"""DICOM Secure sunucu cekirdegi.

- TLS (veya config ile kapalysa duz TCP) uzerinden protokol v2 dinler.
- Uzunluk-onekli guvenli cerceveleme kullanir (END_FILE tarayicisi yok).
- Oturum sonunda dosyalari ChaCha20-Poly1305 ile dogrulayarak cozer;
  tahrifat durumunda dosyayi reddeder.
- AI analizini torchvision olmadan (yalniz torch + PIL) yapar.
"""

import hashlib
import json
import os
import re
import socket
import ssl
import threading
import time
from datetime import datetime

import numpy as np
import pydicom
import torch
import torch.nn as nn
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from pydicom.uid import ExplicitVRLittleEndian
from PIL import Image

PROTOCOL_VERSION = "v2"
CHUNK_SIZE = 64 * 1024
TIMESTAMP_FMT = "%H_%M_%S_%d_%m_%Y"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(BASE_DIR, "config.json")

DEFAULT_CONFIG = {
    "listen_ip": "0.0.0.0",
    "listen_port": 5000,
    "tls_enabled": True,
    "cert_path": "../certs/server_cert.pem",
    "key_path": "../certs/server_key.pem",
    "encrypted_folder": "Encrypted",
    "decrypted_folder": "Files",
    "tumor_folder": "Tumor",
    "notumor_folder": "Tumorsuz",
    "temp_folder": "Temp",
    "reports_folder": "Reports",
    "model_path": "tumor_model.pth",
}


def load_config():
    cfg = dict(DEFAULT_CONFIG)
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                cfg.update(json.load(f))
        except (json.JSONDecodeError, OSError):
            pass
    return cfg


def save_config(cfg):
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)


def resolve_path(base_dir_relative):
    path = base_dir_relative
    if not os.path.isabs(path):
        path = os.path.normpath(os.path.join(BASE_DIR, path))
    return path


# ------------------------------------------------------------------
# DICOM cozme
# ------------------------------------------------------------------

def save_dicom_compat(ds, path):
    ds.file_meta.TransferSyntaxUID = ExplicitVRLittleEndian
    try:
        ds.save_as(path, enforce_file_format=True)  # pydicom >= 3.0
    except TypeError:
        ds.is_implicit_VR = False  # pydicom < 3.0
        ds.is_little_endian = True
        ds.save_as(path)


def decrypt_dicom(input_file, output_file):
    """AEAD dogrulamali sifre cozme. Donus: (basari, mesaj)."""
    key_file = input_file + ".key"
    if not os.path.exists(input_file):
        return False, f"Dosya bulunamadi: {input_file}"
    if not os.path.exists(key_file):
        return False, f"Anahtar dosyasi eksik: {key_file}"

    try:
        with open(key_file, "r", encoding="utf-8") as f:
            key_info = json.load(f)
        key = bytes.fromhex(key_info["key"])
        nonce = bytes.fromhex(key_info["nonce"])
        aad = json.dumps(key_info["aad"], sort_keys=True,
                         separators=(",", ":")).encode("utf-8")
    except (KeyError, ValueError, json.JSONDecodeError) as exc:
        return False, f"Anahtar dosyasi okunamadi: {exc}"

    try:
        ds = pydicom.dcmread(input_file)
        if "PixelData" not in ds:
            return False, "DICOM dosyasinda piksel verisi yok"

        encrypted_bytes = ds["PixelData"].value

        cipher = ChaCha20Poly1305(key)
        try:
            plain = cipher.decrypt(nonce, encrypted_bytes, aad)
        except InvalidTag:
            return False, "Butunluk dogrulamasi BASARISIZ: dosya tahrif edilmis veya anahtar yanlis"

        shape = tuple(key_info["shape"])
        dtype = np.dtype(key_info["dtype"])
        expected = int(np.prod(shape)) * dtype.itemsize
        if len(plain) < expected:
            return False, f"Piksel verisi beklenenden kisa ({len(plain)} < {expected})"

        ds.PixelData = plain[:expected]
        save_dicom_compat(ds, output_file)
        return True, output_file
    except Exception as exc:
        return False, f"Cozme hatasi: {exc}"


# ------------------------------------------------------------------
# AI analiz (torchvision'suz onisleme)
# ------------------------------------------------------------------

class CustomTumorModel(nn.Module):
    def __init__(self):
        super().__init__()
        self.conv1 = nn.Conv2d(3, 32, kernel_size=3, stride=1, padding=1)
        self.conv2 = nn.Conv2d(32, 64, kernel_size=3, stride=1, padding=1)
        self.pool = nn.AdaptiveAvgPool2d((64, 64))
        self.fc1_input_size = 64 * 64 * 64
        self.fc1 = nn.Linear(self.fc1_input_size, 128)
        self.fc2 = nn.Linear(128, 2)

    def forward(self, x):
        x = torch.relu(self.conv1(x))
        x = torch.relu(self.conv2(x))
        x = self.pool(x)
        x = x.view(x.size(0), -1)
        x = torch.relu(self.fc1(x))
        x = self.fc2(x)
        return x


def dicom_to_pil(dicom_path):
    """DICOM piksellerini goruntulenebilir PIL Image'e cevirir (8/16 bit, gri/RGB)."""
    ds = pydicom.dcmread(dicom_path)
    if "PixelData" not in ds:
        raise ValueError("Piksel verisi yok")
    if ds.file_meta.TransferSyntaxUID.is_compressed:
        ds.decompress()
    arr = ds.pixel_array

    if arr.dtype != np.uint8:
        lo, hi = float(arr.min()), float(arr.max())
        if hi > lo:
            arr = ((arr.astype(np.float64) - lo) / (hi - lo) * 255.0).astype(np.uint8)
        else:
            arr = np.zeros_like(arr, dtype=np.uint8)

    if arr.ndim == 2:
        return Image.fromarray(arr, mode="L")
    if arr.ndim == 3 and arr.shape[2] == 3:
        return Image.fromarray(arr, mode="RGB")
    raise ValueError(f"Desteklenmeyen sekil: {arr.shape}")


def preprocess(image, size=224):
    """torchvision transform birebir karsiligi: Resize -> ToTensor -> Normalize."""
    img = image.convert("RGB").resize((size, size), Image.BILINEAR)
    arr = np.asarray(img, dtype=np.float32) / 255.0
    arr = (arr - 0.5) / 0.5
    arr = np.transpose(arr, (2, 0, 1))
    return torch.from_numpy(arr.copy()).unsqueeze(0)


class AIAnalyzer:
    """Tumor siniflandirma sarmalayicisi: model yukleme + tahmin + guven."""

    def __init__(self, model_path, device=None, log=None):
        self.device = device or torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.model = CustomTumorModel()
        state = torch.load(model_path, map_location=self.device, weights_only=True)
        self.model.load_state_dict(state)
        self.model.to(self.device)
        self.model.eval()
        self.log = log or (lambda msg: None)

    def predict_image(self, image):
        """PIL Image -> (tumor_var: bool, guven: float)."""
        tensor = preprocess(image).to(self.device)
        with torch.no_grad():
            logits = self.model(tensor)
            probs = torch.softmax(logits, dim=1)[0]
        predicted = int(torch.argmax(probs).item())
        confidence = float(probs[predicted].item())
        return predicted == 1, confidence


# ------------------------------------------------------------------
# Oturum sunucusu (QThread'in degil, saf thread'in calistiracagi dongu)
# ------------------------------------------------------------------

class SessionServer:
    """Protokol v2 dinleme dongusu. Olaylar callback'lerle disariya iletilir."""

    def __init__(self, cfg, on_event=None):
        self.cfg = cfg
        self.on_event = on_event or (lambda kind, data: None)
        self.running = False
        self._server_socket = None
        self._lock = threading.Lock()

    # --- olay yardimcilari ---
    def emit(self, kind, data=None, message=None):
        self.on_event(kind, {"message": message, "data": data or {}})

    def log(self, message):
        self.emit("log", message=message)

    def _build_tls_context(self):
        cert = resolve_path(self.cfg["cert_path"])
        key = resolve_path(self.cfg["key_path"])
        if not (os.path.exists(cert) and os.path.exists(key)):
            raise FileNotFoundError(
                "TLS sertifikalari bulunamadi. tools/generate_certs.py dosyasini calistirin."
            )
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(certfile=cert, keyfile=key)
        return context

    def start(self):
        with self._lock:
            if self.running:
                return
            self.running = True
        threading.Thread(target=self._accept_loop, daemon=True).start()

    def stop(self):
        with self._lock:
            self.running = False
        sock = self._server_socket
        if sock:
            try:
                sock.close()
            except OSError:
                pass

    def _accept_loop(self):
        listen_ip = self.cfg.get("listen_ip", "0.0.0.0")
        port = int(self.cfg.get("listen_port", 5000))

        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_socket = server_socket
        try:
            server_socket.bind((listen_ip, port))
            server_socket.listen(5)
        except OSError as exc:
            self.emit("fatal", message=f"Dinleme portu acilamadi ({listen_ip}:{port}): {exc}")
            return

        if self.cfg.get("tls_enabled", True):
            try:
                tls_context = self._build_tls_context()
            except FileNotFoundError as exc:
                self.emit("fatal", message=str(exc))
                return
            self.log(f"Dinleme basladi: {listen_ip}:{port} (TLS aktif)")
        else:
            tls_context = None
            self.log(f"Dinleme basladi: {listen_ip}:{port} (UYARI: TLS KAPALI)")

        while self.running:
            try:
                conn, addr = server_socket.accept()
            except OSError:
                break  # socket kapandi -> kapanis

            try:
                if tls_context:
                    conn = tls_context.wrap_socket(conn, server_side=True)
            except ssl.SSLError as exc:
                self.log(f"TLS el sikismasi basarisiz ({addr[0]}): {exc}")
                try:
                    conn.close()
                except OSError:
                    pass
                continue

            self.log(f"Baglanti alindi: {addr[0]} ({'TLS' if tls_context else 'duz TCP'})")
            threading.Thread(target=self._handle_connection,
                             args=(conn, addr), daemon=True).start()

        try:
            server_socket.close()
        except OSError:
            pass
        self.log("Dinleme dongusu kapandi.")

    # --- protokol isleme ---
    def _recv_line(self, conn, buffer):
        while b"\n" not in buffer:
            chunk = conn.recv(CHUNK_SIZE)
            if not chunk:
                raise ConnectionError("Baglanti kapandi (satir beklenirken)")
            buffer += chunk
        line, buffer = buffer.split(b"\n", 1)
        return line.decode("utf-8").strip(), buffer

    def _recv_exact(self, conn, n):
        chunks = bytearray()
        while len(chunks) < n:
            chunk = conn.recv(min(n - len(chunks), CHUNK_SIZE))
            if not chunk:
                raise ConnectionError(f"Dosya yarida kesildi ({len(chunks)}/{n})")
            chunks.extend(chunk)
        return bytes(chunks)

    def _handle_connection(self, conn, addr):
        session = {
            "folder": None, "meta": {}, "expected": 0,
            "received_files": 0, "received_bytes": 0,
        }
        try:
            conn.settimeout(30)
            buffer = b""

            while True:
                line, buffer = self._recv_line(conn, buffer)

                if line.startswith("HELLO "):
                    if line != f"HELLO {PROTOCOL_VERSION}":
                        conn.sendall(b"ERR unsupported-version\n")
                        break
                    conn.sendall(f"OK {PROTOCOL_VERSION}\n".encode("utf-8"))

                elif line.startswith("META:"):
                    try:
                        session["meta"] = json.loads(line[5:])
                    except json.JSONDecodeError:
                        self.log("META satiri bozuk, yoksayildi.")

                elif line == "SESSION_START":
                    timestamp = datetime.now().strftime(TIMESTAMP_FMT)
                    enc_root = resolve_path(self.cfg["encrypted_folder"])
                    session["folder"] = os.path.join(enc_root, timestamp)
                    os.makedirs(session["folder"], exist_ok=True)
                    session["timestamp"] = timestamp
                    meta = session["meta"]
                    try:
                        with open(os.path.join(session["folder"], "session_meta.json"),
                                  "w", encoding="utf-8") as mf:
                            json.dump({"timestamp": timestamp,
                                       "client_addr": addr[0], **meta}, mf,
                                      indent=2, ensure_ascii=False)
                    except OSError:
                        self.log("session_meta.json yazilamadi.")
                    self.log(
                        f"Oturum basladi: {timestamp} "
                        f"(bolge={meta.get('region', '?')}, sekans={meta.get('sequence', '?')}, "
                        f"slice={meta.get('slice_count', '?')})"
                    )

                elif line.startswith("FILENAME:"):
                    if not session["folder"]:
                        conn.sendall(b"ERR no-session\n")
                        break
                    file_name = os.path.basename(line[len("FILENAME:"):].strip())
                    size_line, buffer = self._recv_line(conn, buffer)
                    if not size_line.startswith("SIZE:"):
                        raise ConnectionError(f"SIZE beklenirken: {size_line}")
                    size = int(size_line[len("SIZE:"):])
                    data = self._recv_exact(conn, size)
                    with open(os.path.join(session["folder"], file_name), "wb") as f:
                        f.write(data)
                    session["received_files"] += 1
                    session["received_bytes"] += size
                    self.emit("file", message=f"{file_name} alindi ({size:,} bayt)",
                              data={"file": file_name, "size": size,
                                    "index": session["received_files"]})

                elif line == "SESSION_END":
                    self.log(f"Oturum alimi tamamlandi: {session['received_files']} dosya, "
                             f"{session['received_bytes']:,} bayt. Cozme basliyor...")
                    summary = self._decrypt_session(session)
                    conn.sendall(
                        ("RESULT:" + json.dumps(summary, ensure_ascii=False) + "\n")
                        .encode("utf-8")
                    )
                    break

                elif line == "":
                    continue
                else:
                    self.log(f"Bilinmeyen komut yoksayildi: {line[:60]}")

        except (ConnectionError, socket.timeout) as exc:
            self.log(f"Baglanti hatasi ({addr[0]}): {exc}")
        except ssl.SSLError as exc:
            self.log(f"TLS hatasi ({addr[0]}): {exc}")
        except Exception as exc:  # beklenmeyen: logla, baglantiyi kapat
            self.log(f"Beklenmeyen hata ({addr[0]}): {exc}")
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def _decrypt_session(self, session):
        folder = session["folder"]
        out_root = resolve_path(self.cfg["decrypted_folder"])
        out_dir = os.path.join(out_root, session["timestamp"])
        os.makedirs(out_dir, exist_ok=True)

        files = sorted(f for f in os.listdir(folder) if f.endswith(".dcm"))
        results = []
        for file in files:
            out_file = os.path.join(out_dir, file.replace("_encrypted.dcm", "_decrypted.dcm"))
            ok, info = decrypt_dicom(os.path.join(folder, file), out_file)
            results.append({"file": file, "ok": ok, "info": info})
            if ok:
                self.emit("decrypted", message=f"Cozuldu: {out_file}",
                          data={"file": file, "output": out_file})
            else:
                self.emit("decrypt_failed", message=f"Cozulemedi: {file} ({info})",
                          data={"file": file, "error": info})

        ok_count = sum(1 for r in results if r["ok"])
        self.emit("session_done", data={
            "timestamp": session["timestamp"],
            "meta": session["meta"],
            "received_files": session["received_files"],
            "received_bytes": session["received_bytes"],
            "decrypted": ok_count,
            "failed": len(results) - ok_count,
            "output_dir": out_dir,
        })
        return {"received": session["received_files"], "decrypted": ok_count,
                "failed": len(results) - ok_count}
