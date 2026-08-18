from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import quote
from typing import Any
import hashlib
import json
import string


@dataclass(slots=True)
class AgentConfig:
    enabled: bool = False
    auto_package: bool = True
    product_id: str = "{11111111-2222-3333-4444-555555555555}"
    job_id: str = "{11111111-2222-3333-4444-555555555555}"
    version: str = "1.0.0"
    url: str = ""
    sha256: str = ""
    command_line: str = "/quiet /norestart"
    timeout_minutes: int = 10
    retry_count: int = 3
    retry_interval_minutes: int = 5
    download_from_aad: bool = False


@dataclass(slots=True)
class ServerConfig:
    host: str = "0.0.0.0"
    port: int = 8443
    public_base_url: str = "https://localhost:8443"
    enrollment_base_url: str = "https://localhost:8443"
    management_base_url: str = "https://localhost:8443"
    provider_id: str = "ExampleMDM"
    provider_name: str = "Example MDM"
    auth_policy: str = "OnPremise"
    enrollment_version: str = "5.0"
    enrollment_context: str = "user"
    default_encoding: str = "application/vnd.syncml.dm+xml"
    state_dir: str = "state"
    package_dir: str = "packages"
    tls_cert_file: str = "state/certs/server.crt"
    tls_key_file: str = "state/certs/server.key"
    ca_cert_file: str = "state/certs/mdm-root-ca.crt"
    ca_key_file: str = "state/certs/mdm-root-ca.key"
    require_syncml_mtls: bool = False
    allow_anonymous_enrollment: bool = False
    verbose_file_logging: bool = False
    log_dir: str = "state/logs"
    federated_auth_stub: bool = False
    federated_dev_token: str = "Nw=="
    users: dict[str, str] = field(default_factory=dict)
    agent: AgentConfig = field(default_factory=AgentConfig)

    @property
    def discovery_path(self) -> str:
        return "/EnrollmentServer/Discovery.svc"

    @property
    def enrollment_path(self) -> str:
        return "/EnrollmentServer/DeviceEnrollmentWebService.svc"

    @property
    def syncml_path(self) -> str:
        return "/omadm/Windows.ashx"

    @property
    def auth_path(self) -> str:
        if self.federated_auth_stub:
            return "/windowsfederated/"
        return "/auth/login"

    @property
    def enrollment_service_url(self) -> str:
        return join_url(self.enrollment_base_url, self.enrollment_path)

    @property
    def enrollment_policy_service_url(self) -> str:
        return self.enrollment_service_url

    @property
    def authentication_service_url(self) -> str:
        return join_url(self.public_base_url, self.auth_path)

    @property
    def syncml_url(self) -> str:
        return join_url(self.management_base_url, self.syncml_path)

    @property
    def database_path(self) -> str:
        return str(Path(self.state_dir) / "mdm.sqlite3")


def join_url(base: str, path: str) -> str:
    return base.rstrip("/") + "/" + path.lstrip("/")


def configure_agent_package(config: ServerConfig) -> Path | None:
    if not config.agent.enabled:
        return None

    selected = None
    if config.agent.auto_package:
        selected = first_msi_package(config.package_dir)
        if selected:
            config.agent.url = join_url(
                config.management_base_url,
                f"/packages/{quote(selected.name, safe='')}",
            )
            config.agent.sha256 = _sha256_file(selected)

    _validate_agent_package(config, selected)
    return selected


def first_msi_package(package_dir: str) -> Path | None:
    root = Path(package_dir)
    if not root.is_dir():
        return None
    msis = sorted(
        (path for path in root.glob("*.msi") if path.is_file()),
        key=lambda path: path.name.lower(),
    )
    return msis[0] if msis else None


def _resolve_path(config_dir: Path, value: str) -> str:
    path = Path(value)
    if path.is_absolute():
        return str(path)
    return str((config_dir / path).resolve())


def load_config(path: str | Path) -> ServerConfig:
    config_path = Path(path).resolve()
    with config_path.open("r", encoding="utf-8") as handle:
        raw: dict[str, Any] = json.load(handle)

    agent_raw = raw.pop("agent", {}) or {}
    config = ServerConfig(**raw)
    config.agent = AgentConfig(**agent_raw)

    config_dir = config_path.parent
    config.state_dir = _resolve_path(config_dir, config.state_dir)
    config.package_dir = _resolve_path(config_dir, config.package_dir)
    config.log_dir = _resolve_path(config_dir, config.log_dir)
    config.tls_cert_file = _resolve_path(config_dir, config.tls_cert_file)
    config.tls_key_file = _resolve_path(config_dir, config.tls_key_file)
    config.ca_cert_file = _resolve_path(config_dir, config.ca_cert_file)
    config.ca_key_file = _resolve_path(config_dir, config.ca_key_file)
    return config


def write_default_config(path: str | Path) -> None:
    target = Path(path)
    if target.exists():
        raise FileExistsError(str(target))
    example = Path(__file__).resolve().parent.parent / "config.example.json"
    target.write_text(example.read_text(encoding="utf-8"), encoding="utf-8")


def _validate_agent_package(config: ServerConfig, selected: Path | None) -> None:
    if config.agent.url.strip() and _is_sha256_hex(config.agent.sha256):
        return
    if config.agent.auto_package and selected is None:
        raise ValueError(
            "agent.enabled is true, but no .msi file was found in package_dir "
            f"({config.package_dir}). Put one MSI in that folder, or set "
            "agent.auto_package to false and configure agent.url and agent.sha256."
        )
    raise ValueError(
        "agent.enabled is true, but agent.url or agent.sha256 is missing or invalid. "
        "Set agent.auto_package to true with an MSI in package_dir, or configure both "
        "values manually."
    )


def _is_sha256_hex(value: str) -> bool:
    cleaned = value.strip()
    return len(cleaned) == 64 and all(char in string.hexdigits for char in cleaned)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest().upper()
