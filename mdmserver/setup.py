from __future__ import annotations

import getpass
import json
import os
import sys
from pathlib import Path
from typing import Any
from urllib.parse import quote


LETSENCRYPT_LIVE = Path("/etc/letsencrypt/live")


def run_setup(config_path: str = "config.json") -> None:
    print()
    print("=" * 56)
    print("         MDM Server Setup Wizard")
    print("=" * 56)
    print()

    target = Path(config_path).resolve()
    if target.exists():
        if not _confirm(f"{target} already exists. Overwrite?", default=False):
            print("Aborted.")
            return

    hostname, tls_cert, tls_key = _step_tls()
    port = _step_port()
    base_url = f"https://{hostname}" if port == 443 else f"https://{hostname}:{port}"
    auth_policy, users, federated_stub = _step_auth()
    agent_enabled = _step_agent()
    verbose = _confirm("Enable verbose protocol logging?", default=True)

    config: dict[str, Any] = {
        "host": "0.0.0.0",
        "port": port,
        "public_base_url": base_url,
        "enrollment_base_url": base_url,
        "management_base_url": base_url,
        "provider_id": "ExampleMDM",
        "provider_name": "Example MDM",
        "auth_policy": auth_policy,
        "enrollment_version": "5.0",
        "enrollment_context": "user",
        "default_encoding": "application/vnd.syncml.dm+xml",
        "state_dir": "state",
        "package_dir": "packages",
        "tls_cert_file": tls_cert,
        "tls_key_file": tls_key,
        "ca_cert_file": "state/certs/mdm-root-ca.crt",
        "ca_key_file": "state/certs/mdm-root-ca.key",
        "require_syncml_mtls": False,
        "allow_anonymous_enrollment": auth_policy == "Federated",
        "verbose_file_logging": verbose,
        "log_dir": "state/logs",
        "federated_auth_stub": federated_stub,
        "federated_dev_token": "Nw==",
        "users": users,
        "agent": {
            "enabled": agent_enabled,
            "auto_package": True,
            "product_id": "{F9EAAEA7-1AD3-4943-A7B5-A33C41664211}",
            "job_id": "{11111111-2222-3333-4444-555555555556}",
            "version": "1.0.0",
            "url": "",
            "sha256": "",
            "command_line": "/quiet /norestart",
            "timeout_minutes": 10,
            "retry_count": 3,
            "retry_interval_minutes": 5,
            "download_from_aad": False,
        },
    }

    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
    print(f"\nWrote {target}")

    packages_dir = target.parent / "packages"
    packages_dir.mkdir(parents=True, exist_ok=True)

    _step_generate_ca(target)

    print()
    print("=" * 56)
    print("  Setup complete")
    print("=" * 56)
    print()
    print("  Next steps:")
    print(f"    1. Review your config:  {target}")
    if agent_enabled:
        print(f"    2. Drop an MSI into {packages_dir}/")
    print(f"    {'3' if agent_enabled else '2'}. Start the server:")
    print(f"       sudo python3 -m mdmserver serve --config {target}")
    print()
    print(f"  Windows enrollment URL:")
    print(f"    {base_url}/EnrollmentServer/Discovery.svc")
    print()
    encoded_base = quote(base_url, safe="")
    example_user = next(iter(users), "user@example.com") if users else "user@example.com"
    print(f"  Trigger enrollment via URL handler:")
    print(f"    ms-device-enrollment:?mode=mdm&username={quote(example_user, safe='')}&servername={encoded_base}")
    print()


def _step_tls() -> tuple[str, str, str]:
    print("--- TLS Certificate ---")
    print()

    certs = _scan_letsencrypt()
    if certs:
        print("Let's Encrypt certificates found:\n")
        for i, (domain, cert, key) in enumerate(certs, 1):
            print(f"  {i}) {domain}")
            print(f"     cert: {cert}")
            print(f"     key:  {key}")
            print()

        print(f"  {len(certs) + 1}) Enter paths manually")
        print()

        choice = _choose(
            "Select a certificate",
            range(1, len(certs) + 2),
        )
        if choice <= len(certs):
            domain, cert_path, key_path = certs[choice - 1]
            hostname = _prompt("Hostname for this server", default=domain)
            _check_cert_readable(cert_path, key_path)
            return hostname, cert_path, key_path

    elif LETSENCRYPT_LIVE.exists():
        print("No certificates found in /etc/letsencrypt/live/.")
        print()
    else:
        print("/etc/letsencrypt/live/ not found.")
        print("Run certbot first to obtain a Let's Encrypt certificate,")
        print("or enter certificate paths manually below.")
        print()

    return _step_tls_manual()


def _step_tls_manual() -> tuple[str, str, str]:
    hostname = _prompt("Server hostname (FQDN)")
    cert_path = _prompt("Path to TLS certificate (fullchain.pem)")
    key_path = _prompt("Path to TLS private key (privkey.pem)")

    if not Path(cert_path).exists():
        print(f"  Warning: {cert_path} does not exist yet.")
    if not Path(key_path).exists():
        print(f"  Warning: {key_path} does not exist yet.")

    _check_cert_readable(cert_path, key_path)
    return hostname, cert_path, key_path


def _step_port() -> int:
    print()
    print("--- Port ---")
    print()
    raw = _prompt("HTTPS port", default="443")
    try:
        port = int(raw)
        if not 1 <= port <= 65535:
            raise ValueError
        return port
    except ValueError:
        print("  Invalid port, using 443.")
        return 443


def _step_auth() -> tuple[str, dict[str, str], bool]:
    print()
    print("--- Authentication ---")
    print()
    print("  1) Federated (anonymous enrollment, easiest for testing)")
    print("  2) OnPremise (username/password prompt on Windows)")
    print()
    choice = _choose("Auth policy", [1, 2])

    if choice == 1:
        return "Federated", {}, True

    print()
    users: dict[str, str] = {}
    while True:
        email = _prompt("Enrollment username (email format)")
        password = _prompt_password("Password for this user")
        users[email] = password
        print(f"  Added user: {email}")
        if not _confirm("Add another user?", default=False):
            break
    return "OnPremise", users, False


def _step_agent() -> bool:
    print()
    print("--- MSI Agent Deployment ---")
    print()
    print("The server can push an MSI installer to enrolled devices.")
    print("You can enable this later by editing the config.")
    print()
    return _confirm("Enable MSI agent deployment?", default=False)


def _step_generate_ca(config_path: Path) -> None:
    print()
    print("--- MDM Certificate Authority ---")
    print()
    print("The MDM server needs its own CA to issue client enrollment")
    print("certificates. This is separate from your TLS certificate.")
    print()
    if _confirm("Generate the MDM CA now?", default=True):
        from .config import load_config
        from .crypto import ensure_root_ca

        config = load_config(str(config_path))
        Path(config.state_dir).mkdir(parents=True, exist_ok=True)
        ensure_root_ca(config.ca_cert_file, config.ca_key_file)
        print(f"  CA certificate: {config.ca_cert_file}")
        print(f"  CA private key: {config.ca_key_file}")



def _scan_letsencrypt() -> list[tuple[str, str, str]]:
    if not LETSENCRYPT_LIVE.is_dir():
        return []

    results = []
    try:
        entries = sorted(LETSENCRYPT_LIVE.iterdir())
    except PermissionError:
        print("  Warning: cannot read /etc/letsencrypt/live/ (permission denied).")
        print("  Try running this wizard with sudo or as root.")
        print()
        return []

    for entry in entries:
        if not entry.is_dir() or entry.name.startswith("."):
            continue
        if entry.name == "README":
            continue
        cert = entry / "fullchain.pem"
        key = entry / "privkey.pem"
        if cert.exists() and key.exists():
            results.append((entry.name, str(cert), str(key)))
    return results


def _check_cert_readable(cert_path: str, key_path: str) -> None:
    for path in (cert_path, key_path):
        p = Path(path)
        if p.exists() and not os.access(p, os.R_OK):
            print(f"  Warning: {path} exists but is not readable by this user.")
            print(f"  The server process will need read access to this file.")


def _prompt(label: str, default: str | None = None) -> str:
    suffix = f" [{default}]" if default else ""
    while True:
        value = input(f"  {label}{suffix}: ").strip()
        if value:
            return value
        if default is not None:
            return default
        print("    A value is required.")


def _prompt_password(label: str) -> str:
    while True:
        value = getpass.getpass(f"  {label}: ").strip()
        if value:
            return value
        print("    A password is required.")


def _confirm(label: str, default: bool = True) -> bool:
    hint = "Y/n" if default else "y/N"
    value = input(f"  {label} [{hint}]: ").strip().lower()
    if not value:
        return default
    return value in ("y", "yes")


def _choose(label: str, options: range | list) -> int:
    options_list = list(options)
    while True:
        raw = input(f"  {label} [{options_list[0]}-{options_list[-1]}]: ").strip()
        try:
            value = int(raw)
            if value in options_list:
                return value
        except ValueError:
            pass
        print(f"    Please enter a number between {options_list[0]} and {options_list[-1]}.")
