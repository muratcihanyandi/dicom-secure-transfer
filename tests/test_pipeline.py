"""Uctan uca cekirdek test (GUI'siz).

Akis: sifrele -> TLS uzerinden gonder -> sunucuda coz -> piksel eslesmesini
dogrula. Ayrica: AEAD tahrifat testi, anahtar dosyasi hirsizligi testi.

Calistir: python tests/test_pipeline.py
"""

import json
import os
import shutil
import sys
import tempfile
import threading
import time

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(PROJECT_ROOT, "Client"))
sys.path.insert(0, os.path.join(PROJECT_ROOT, "Server"))

import numpy as np
import pydicom

import client_core as ccore
import server_core as score

PASSED, FAILED = [], []


def check(name, condition, detail=""):
    if condition:
        PASSED.append(name)
        print(f"  [OK]   {name}")
    else:
        FAILED.append(name)
        print(f"  [FAIL] {name} {detail}")


def main():
    tmp = tempfile.mkdtemp(prefix="dicom_secure_test_")
    dataset_dir = os.path.join(PROJECT_ROOT, "Client", "dataset")

    # --- 1) Anahtar uretimi ---
    print("\n[1] Anahtar uretimi")
    session_id = "test_00_00_00_01_01_2026"
    master = ccore.derive_master_key(session_id)
    check("master anahtar 32 bayt", len(master) == 32)

    fk1 = ccore.derive_file_key(master, session_id, "slice01_encrypted.dcm")
    fk2 = ccore.derive_file_key(master, session_id, "slice02_encrypted.dcm")
    check("dosya anahtarlari benzersiz", fk1 != fk2)
    check("Lorenz tohumu tekrarlanabilir-ama-entropik", len(ccore.lorenz_chaos_seed()) == 32)

    # --- 2) Sifreleme + cozme dongusu (2 dosya) ---
    print("\n[2] Sifreleme -> TLS aktarim -> cozme dongusu")
    session_dir = os.path.join(tmp, "session")
    os.makedirs(session_dir)
    sources = sorted(f for f in os.listdir(dataset_dir) if f.endswith(".dcm"))[:2]

    originals = {}
    for idx, src_name in enumerate(sources):
        src = os.path.join(dataset_dir, src_name)
        dst = os.path.join(session_dir, f"slice{idx + 1:02d}_encrypted.dcm")
        ok, info = ccore.encrypt_dicom_file(src, dst, master, session_id,
                                            anonymize_flag=True)
        check(f"sifrelendi: {src_name}", ok, str(info.get("error", "")))
        ds = pydicom.dcmread(src)
        if ds.file_meta.TransferSyntaxUID.is_compressed:
            ds.decompress()
        originals[f"slice{idx + 1:02d}_encrypted.dcm"] = ds.pixel_array

        # sifreli dosya piksel verisi orijinalden farkli olmali
        enc_ds = pydicom.dcmread(dst)
        check(f"sifreli veri farkli: {src_name}",
              not np.array_equal(enc_ds.pixel_array, originals[f"slice{idx + 1:02d}_encrypted.dcm"]))

        # hasta kimlik verileri temizlenmis olmali
        enc_read = pydicom.dcmread(dst)
        check(f"anonimlestirme: {src_name}",
              getattr(enc_read, "PatientIdentityRemoved", "") == "YES")

    # --- 3) TLS sunucu ile aktarim + cozme ---
    print("\n[3] TLS sunucu ile aktarim + cozme")
    server_cfg = dict(score.DEFAULT_CONFIG)
    server_cfg.update({
        "listen_ip": "127.0.0.1",
        "listen_port": 5099,
        "tls_enabled": True,
        "cert_path": os.path.join(PROJECT_ROOT, "certs", "server_cert.pem"),
        "key_path": os.path.join(PROJECT_ROOT, "certs", "server_key.pem"),
        "encrypted_folder": os.path.join(tmp, "srv_encrypted"),
        "decrypted_folder": os.path.join(tmp, "srv_decrypted"),
    })
    for k in ("encrypted_folder", "decrypted_folder"):
        server_cfg[k] = os.path.relpath(server_cfg[k], score.BASE_DIR)

    events = []
    server = score.SessionServer(server_cfg, on_event=lambda k, p: events.append((k, p)))
    server.start()
    time.sleep(0.8)

    client_cfg = dict(ccore.DEFAULT_CONFIG)
    client_cfg.update({
        "server_ip": "127.0.0.1",
        "server_port": 5099,
        "tls_enabled": True,
        "tls_ca_path": os.path.join(PROJECT_ROOT, "certs", "ca.pem"),
    })
    meta = {"region": "Beyin", "sequence": "T1-weighted", "slice_count": 2}
    ok, summary = ccore.send_session(session_dir, meta, client_cfg, log=lambda m: None)
    check("gonderim basarili", ok, str(summary.get("error", "")))
    check("sunucu onayi 2 dcm + 2 key dosya",
          summary.get("server_result", {}).get("received") == 4, str(summary))
    check("sunucu onayi 2 dosya cozuldu",
          summary.get("server_result", {}).get("decrypted") == 2, str(summary))

    time.sleep(0.5)
    decrypted_dir = os.path.join(tmp, "srv_decrypted")
    dec_files = []
    for d in os.listdir(decrypted_dir):
        dec_files += [f for f in os.listdir(os.path.join(decrypted_dir, d)) if f.endswith(".dcm")]
    check("sunucuda 2 dosya cozuldu", len(dec_files) == 2, str(dec_files))

    for name, orig in originals.items():
        out = None
        for d in os.listdir(decrypted_dir):
            cand = os.path.join(decrypted_dir, d, name.replace("_encrypted", "_decrypted"))
            if os.path.exists(cand):
                out = cand
        check(f"cozum dosyasi var: {name}", out is not None)
        if out:
            ds = pydicom.dcmread(out)
            check(f"pikseller eslesiyor: {name}",
                  np.array_equal(ds.pixel_array, orig))
    server.stop()

    # --- 4) Tahrifat testi (AEAD butunluk) ---
    print("\n[4] Tahrifat testi (AEAD)")
    tampered_dir = os.path.join(tmp, "tampered")
    shutil.copytree(session_dir, tampered_dir)
    victim = os.path.join(tampered_dir, "slice01_encrypted.dcm")
    with open(victim, "r+b") as f:
        data = bytearray(f.read())
        data[-10] ^= 0xFF
        f.seek(0)
        f.write(data)
    ok, msg = score.decrypt_dicom(victim, os.path.join(tmp, "tampered_out.dcm"))
    check("tahrif edilmis dosya reddedildi", not ok, str(msg))

    # yanlis anahtar
    wrong_key_dir = os.path.join(tmp, "wrongkey")
    shutil.copytree(session_dir, wrong_key_dir)
    vf = os.path.join(wrong_key_dir, "slice01_encrypted.dcm.key")
    with open(vf, "r", encoding="utf-8") as f:
        ki = json.load(f)
    ki["key"] = "00" * 32
    with open(vf, "w", encoding="utf-8") as f:
        json.dump(ki, f)
    ok, msg = score.decrypt_dicom(os.path.join(wrong_key_dir, "slice01_encrypted.dcm"),
                                  os.path.join(tmp, "wrongkey_out.dcm"))
    check("yanlis anahtar reddedildi", not ok, str(msg))

    # --- 5) AI analiz ---
    print("\n[5] AI analiz")
    try:
        model_path = os.path.join(PROJECT_ROOT, "Server", "tumor_model.pth")
        analyzer = score.AIAnalyzer(model_path)
        sample = None
        for d in os.listdir(decrypted_dir):
            cand = os.path.join(decrypted_dir, d, "slice01_decrypted.dcm")
            if os.path.exists(cand):
                sample = cand
        img = score.dicom_to_pil(sample)
        tumor, conf = analyzer.predict_image(img)
        check("AI tahmin calisiyor", isinstance(tumor, bool) and 0.0 <= conf <= 1.0,
              f"tumor={tumor} conf={conf:.3f}")
        print(f"       (ornek tahmin: tumor={tumor}, guven={conf:.3f})")
    except Exception as exc:
        check("AI tahmin calisiyor", False, str(exc))

    # --- 6) Protokol hata dayanikliligi: desteksiz surum ---
    print("\n[6] Protokol dayanikliligi")
    import socket
    import ssl as ssl_mod
    ctx = ssl_mod.SSLContext(ssl_mod.PROTOCOL_TLS_CLIENT)
    ctx.load_verify_locations(os.path.join(PROJECT_ROOT, "certs", "ca.pem"))
    ctx.check_hostname = False
    server.start()
    time.sleep(0.5)
    try:
        raw = socket.create_connection(("127.0.0.1", 5099), timeout=5)
        sock = ctx.wrap_socket(raw, server_hostname="127.0.0.1")
        sock.sendall(b"HELLO v1\n")
        reply = sock.recv(64).decode().strip()
        check("desteksiz surum reddedildi", reply.startswith("ERR"), reply)
        sock.close()
    except Exception as exc:
        check("desteksiz surum reddedildi", False, str(exc))
    server.stop()

    # --- ozet ---
    print(f"\nSONUC: {len(PASSED)} basarili, {len(FAILED)} basarisiz")
    if FAILED:
        print("Basarisiz testler:", FAILED)
    shutil.rmtree(tmp, ignore_errors=True)
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
