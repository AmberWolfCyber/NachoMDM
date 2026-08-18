from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse
import base64
import datetime as dt
import hashlib
import ipaddress


class CryptoDependencyError(RuntimeError):
    pass


@dataclass(slots=True)
class IssuedCertificate:
    pem: str
    der_b64: str
    thumbprint_sha1: str
    subject: str
    valid_to_iso: str


def _crypto():
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
    except ModuleNotFoundError as exc:
        raise CryptoDependencyError(
            "The MDM server needs the 'cryptography' package for X.509 issuance. "
            "Install dependencies with: python -m pip install -r requirements.txt"
        ) from exc
    return x509, hashes, serialization, rsa, ExtendedKeyUsageOID, NameOID


def ensure_lab_pki(config, dns_names: list[str] | None = None) -> None:
    ensure_root_ca(config.ca_cert_file, config.ca_key_file)
    names = dns_names or hostnames_from_config(config)
    ensure_server_certificate(
        config.tls_cert_file,
        config.tls_key_file,
        config.ca_cert_file,
        config.ca_key_file,
        names,
    )


def ensure_root_ca(cert_path: str, key_path: str, common_name: str = "Example MDM Root CA") -> None:
    cert_file = Path(cert_path)
    key_file = Path(key_path)
    if cert_file.exists() and key_file.exists():
        return

    x509, hashes, serialization, rsa, _, NameOID = _crypto()
    cert_file.parent.mkdir(parents=True, exist_ok=True)
    key_file.parent.mkdir(parents=True, exist_ok=True)

    key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Example MDM"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )
    now = dt.datetime.now(dt.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )

    key_file.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def ensure_server_certificate(
    cert_path: str,
    key_path: str,
    ca_cert_path: str,
    ca_key_path: str,
    names: list[str],
) -> None:
    cert_file = Path(cert_path)
    key_file = Path(key_path)
    if cert_file.exists() and key_file.exists():
        return

    x509, hashes, serialization, rsa, ExtendedKeyUsageOID, NameOID = _crypto()
    cert_file.parent.mkdir(parents=True, exist_ok=True)
    key_file.parent.mkdir(parents=True, exist_ok=True)

    ca_cert = load_certificate(ca_cert_path)
    ca_key = load_private_key(ca_key_path)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    common_name = names[0] if names else "localhost"
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Example MDM"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )

    san_entries = []
    for name in sorted(set(names + ["localhost"])):
        try:
            san_entries.append(x509.IPAddress(ipaddress.ip_address(name)))
        except ValueError:
            san_entries.append(x509.DNSName(name))

    now = dt.datetime.now(dt.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=825))
        .add_extension(x509.SubjectAlternativeName(san_entries), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )

    key_file.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def issue_client_certificate_from_pkcs10(
    csr_token: str,
    ca_cert_path: str,
    ca_key_path: str,
    *,
    fallback_common_name: str,
    validity_days: int = 730,
) -> IssuedCertificate:
    x509, hashes, serialization, _, ExtendedKeyUsageOID, NameOID = _crypto()
    csr = load_csr_token(csr_token)
    ca_cert = load_certificate(ca_cert_path)
    ca_key = load_private_key(ca_key_path)
    subject = csr.subject
    if len(subject) == 0:
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, fallback_common_name)])

    now = dt.datetime.now(dt.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=validity_days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    )

    try:
        san = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        builder = builder.add_extension(san.value, critical=False)
    except x509.ExtensionNotFound:
        pass

    cert = builder.sign(ca_key, hashes.SHA256())
    der = cert.public_bytes(serialization.Encoding.DER)
    pem = cert.public_bytes(serialization.Encoding.PEM).decode("ascii")
    return IssuedCertificate(
        pem=pem,
        der_b64=base64.b64encode(der).decode("ascii"),
        thumbprint_sha1=hashlib.sha1(der).hexdigest().upper(),
        subject=cert.subject.rfc4514_string(),
        valid_to_iso=_certificate_not_valid_after_iso(cert),
    )


def load_csr_token(token: str):
    x509, _, _, _, _, _ = _crypto()
    cleaned = "".join(token.strip().split())
    candidates: list[bytes] = []
    if "BEGINCERTIFICATEREQUEST" not in cleaned.upper():
        try:
            candidates.append(base64.b64decode(cleaned, validate=False))
        except Exception:
            pass
    candidates.append(token.encode("ascii", errors="ignore"))

    last_error: Exception | None = None
    for candidate in candidates:
        try:
            if candidate.startswith(b"-----BEGIN"):
                return x509.load_pem_x509_csr(candidate)
            return x509.load_der_x509_csr(candidate)
        except Exception as exc:
            last_error = exc
    raise ValueError(f"Could not parse PKCS#10 CSR: {last_error}")


def load_certificate(path: str):
    x509, _, _, _, _, _ = _crypto()
    data = Path(path).read_bytes()
    if data.startswith(b"-----BEGIN"):
        return x509.load_pem_x509_certificate(data)
    return x509.load_der_x509_certificate(data)


def load_private_key(path: str):
    _, _, serialization, _, _, _ = _crypto()
    return serialization.load_pem_private_key(Path(path).read_bytes(), password=None)


def pem_cert_to_der_b64(path_or_pem: str) -> str:
    _, _, serialization, _, _, _ = _crypto()
    if "-----BEGIN CERTIFICATE-----" in path_or_pem:
        cert = load_certificate_from_pem(path_or_pem)
    else:
        cert = load_certificate(path_or_pem)
    der = cert.public_bytes(serialization.Encoding.DER)
    return base64.b64encode(der).decode("ascii")


def load_certificate_from_pem(pem: str):
    x509, _, _, _, _, _ = _crypto()
    return x509.load_pem_x509_certificate(pem.encode("ascii"))


def cert_thumbprint_from_pem(pem: str) -> str:
    _, _, serialization, _, _, _ = _crypto()
    cert = load_certificate_from_pem(pem)
    return hashlib.sha1(cert.public_bytes(serialization.Encoding.DER)).hexdigest().upper()


def cert_thumbprint_from_file(path: str) -> str:
    _, _, serialization, _, _, _ = _crypto()
    cert = load_certificate(path)
    return hashlib.sha1(cert.public_bytes(serialization.Encoding.DER)).hexdigest().upper()


def peer_cert_thumbprint(peer_der: bytes | None) -> str | None:
    if not peer_der:
        return None
    return hashlib.sha1(peer_der).hexdigest().upper()


def _certificate_not_valid_after_iso(cert) -> str:
    valid_after_utc = getattr(cert, "not_valid_after_utc", None)
    if valid_after_utc is not None:
        return valid_after_utc.isoformat()
    return cert.not_valid_after.replace(tzinfo=dt.timezone.utc).isoformat()


def hostnames_from_config(config) -> list[str]:
    names: set[str] = {"localhost", "127.0.0.1"}
    for value in (config.public_base_url, config.enrollment_base_url, config.management_base_url):
        host = urlparse(value).hostname
        if host:
            names.add(host)
    return sorted(names)


def sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest().upper()
