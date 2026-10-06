"""TLS sertifikalarini uretir: yerel CA + sunucu sertifikasi (CA imzali).

Kullanim:
    python tools/generate_certs.py            # certs/ klasorune yazar
    python tools/generate_certs.py --force    # mevcut sertifikalari ezer

CIKTI:
    certs/ca.pem          -> istemcinin pinledigi CA sertifikasi
    certs/server_cert.pem -> sunucu sertifikasi (CA imzali, SAN'li)
    certs/server_key.pem  -> sunucu ozel anahtari (GIZLI, paylasma)
"""

import argparse
import ipaddress
import os
import socket
import sys
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CERTS_DIR = os.path.join(PROJECT_ROOT, "certs")

VALIDITY_DAYS = 825


def local_ip_addresses():
    ips = {"127.0.0.1"}
    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None, socket.AF_INET):
            ips.add(info[4][0])
    except OSError:
        pass
    return sorted(ips, key=lambda s: (s != "127.0.0.1", s))


def build_key():
    return ec.generate_private_key(ec.SECP256R1())


def name(common_name):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def generate_ca(force=False):
    ca_key = build_key()
    subject = issuer = name("DICOM Secure Local CA")
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=VALIDITY_DAYS * 4))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    return ca_key, cert


def generate_server_cert(ca_key, ca_cert, force=False):
    server_key = build_key()
    now = datetime.now(timezone.utc)

    san_names = [x509.DNSName("localhost")]
    for ip in local_ip_addresses():
        san_names.append(x509.IPAddress(ipaddress.ip_address(ip)))

    cert = (
        x509.CertificateBuilder()
        .subject_name(name("dicom-secure-server"))
        .issuer_name(ca_cert.subject)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=VALIDITY_DAYS))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.SubjectAlternativeName(san_names), critical=False
        )
        .add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    return server_key, cert


def write_pem(path, data, force=False):
    if os.path.exists(path) and not force:
        print(f"  ZATEN VAR: {path} (--force ile ezebilirsin)")
        return False
    with open(path, "wb") as f:
        f.write(data)
    print(f"  YAZILDI: {path}")
    return True


def main():
    parser = argparse.ArgumentParser(description="DICOM Secure TLS sertifikalarini uret")
    parser.add_argument("--force", action="store_true", help="Mevcut sertifikalari ez")
    args = parser.parse_args()

    os.makedirs(CERTS_DIR, exist_ok=True)
    print(f"Sertifika klasoru: {CERTS_DIR}")

    ca_key, ca_cert = generate_ca(args.force)
    write_pem(
        os.path.join(CERTS_DIR, "ca.pem"),
        ca_cert.public_bytes(serialization.Encoding.PEM),
        args.force,
    )

    server_key, server_cert = generate_server_cert(ca_key, ca_cert, args.force)
    write_pem(
        os.path.join(CERTS_DIR, "server_cert.pem"),
        server_cert.public_bytes(serialization.Encoding.PEM),
        args.force,
    )
    write_pem(
        os.path.join(CERTS_DIR, "server_key.pem"),
        server_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ),
        args.force,
    )

    print("\nNot: ca.pem dosyasini istemci cihaza kopyala (guvenilir kanaldan!).")
    print("server_key.pem gizlidir; asla istemciye gonderme.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
