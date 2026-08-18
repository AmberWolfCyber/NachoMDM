from __future__ import annotations

import argparse

from . import __version__
from .config import load_config, write_default_config
from .crypto import ensure_lab_pki, sha256_file
from .server import serve
from .setup import run_setup


def main() -> None:
    parser = argparse.ArgumentParser(prog="python -m mdmserver")
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)

    setup_cmd = sub.add_parser("setup", help="interactive setup wizard")
    setup_cmd.add_argument("--config", default="config.json")

    init_config = sub.add_parser("init-config", help="write a starter JSON config")
    init_config.add_argument("--path", default="config.json")

    init_pki = sub.add_parser("init-pki", help="create a lab CA and TLS certificate")
    init_pki.add_argument("--config", default="config.json")

    hash_agent = sub.add_parser("hash-agent", help="print SHA-256 for an MSI/package")
    hash_agent.add_argument("path")

    serve_cmd = sub.add_parser("serve", help="run the HTTPS MDM server")
    serve_cmd.add_argument("--config", default="config.json")

    args = parser.parse_args()
    if args.command == "setup":
        run_setup(args.config)
        return
    if args.command == "init-config":
        write_default_config(args.path)
        print(f"Wrote {args.path}")
        return
    if args.command == "init-pki":
        config = load_config(args.config)
        ensure_lab_pki(config)
        print(f"CA certificate: {config.ca_cert_file}")
        print(f"Server certificate: {config.tls_cert_file}")
        print("Install the CA certificate into Trusted Root Certification Authorities on test Windows clients.")
        return
    if args.command == "hash-agent":
        print(sha256_file(args.path))
        return
    if args.command == "serve":
        config = load_config(args.config)
        serve(config)
        return


if __name__ == "__main__":
    main()
