from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse
import base64
import html
import mimetypes
import ssl
import sys
import threading
import traceback
import uuid

from . import crypto, provisioning, soap, syncml
from .config import ServerConfig, configure_agent_package
from .store import Store
from .tracing import TraceLogger


class MDMHTTPServer(ThreadingHTTPServer):
    def __init__(
        self,
        server_address,
        handler_class,
        config: ServerConfig,
        store: Store,
        tracer: TraceLogger,
    ):
        super().__init__(server_address, handler_class)
        self.config = config
        self.store = store
        self.tracer = tracer
        self.federated_stub_identities: dict[str, str] = {}
        self.federated_stub_lock = threading.Lock()


class MDMRequestHandler(BaseHTTPRequestHandler):
    server_version = "PythonMDM/0.1"

    @property
    def config(self) -> ServerConfig:
        return self.server.config

    @property
    def store(self) -> Store:
        return self.server.store

    @property
    def tracer(self) -> TraceLogger:
        return self.server.tracer

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        lower = path.lower()
        self.tracer.event(
            "http_get",
            {
                "client": self.client_address[0],
                "path": path,
                "query": parsed.query,
                "user_agent": self.headers.get("User-Agent", ""),
            },
        )
        if lower in {"/", "/healthz", self.config.discovery_path.lower()}:
            self._send_text(200, "OK\n")
            return
        if _is_auth_path(lower):
            self._handle_auth_get(parsed.query)
            return
        if lower.startswith("/packages/"):
            self._serve_package(path)
            return
        self._send_text(404, "Not found\n")

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path.lower()
        self.tracer.event(
            "http_post",
            {
                "client": self.client_address[0],
                "path": parsed.path,
                "query": parsed.query,
                "content_type": self.headers.get("Content-Type", ""),
                "soap_action": self.headers.get("SOAPAction", ""),
                "user_agent": self.headers.get("User-Agent", ""),
            },
        )
        if path in {"/", "/enrollmentserver", "/enrollmentserver/", self.config.discovery_path.lower()}:
            self._handle_discovery()
            return
        if path == self.config.enrollment_path.lower():
            self._handle_enrollment_service()
            return
        if path == self.config.syncml_path.lower():
            self._handle_syncml(parsed.query)
            return
        self._send_text(404, "Not found\n")

    def _handle_auth_get(self, query: str) -> None:
        params = parse_qs(query)
        app_return_url = params.get("appru", ["ms-app://windows.immersivecontrolpanel"])[0]
        login_hint = params.get("login_hint", params.get("username", [""]))[0]
        token = self.config.federated_dev_token or f"dev-federated-token:{login_hint}:{uuid.uuid4()}"
        if self.config.federated_auth_stub and login_hint:
            self._remember_federated_stub_identity(token, login_hint)
        print(
            f"Federated auth request: login_hint={login_hint!r}, "
            f"return_url={app_return_url!r}, stub={self.config.federated_auth_stub}",
            flush=True,
        )
        self.tracer.event(
            "federated_auth_request",
            {
                "client": self.client_address[0],
                "login_hint": login_hint,
                "return_url": app_return_url,
                "stub": self.config.federated_auth_stub,
            },
        )
        body = f"""<!DOCTYPE>
<html>
  <head>
    <title>Working...</title>
    <script>
      function formSubmit() {{ document.forms[0].submit(); }}
      window.onload = formSubmit;
    </script>
  </head>
  <body>
    <form method="post" action="{html.escape(app_return_url, quote=True)}">
      <p><input type="hidden" name="wresult" value="{html.escape(token, quote=True)}"/></p>
      <input type="submit"/>
    </form>
  </body>
</html>"""
        self._send(
            200,
            "text/html; charset=utf-8",
            body.encode("utf-8"),
            headers={
                "Cache-Control": "no-cache, must-revalidate",
                "Pragma": "no-cache",
                "Expires": "0",
                "X-Content-Type-Options": "nosniff",
            },
        )

    def _handle_discovery(self) -> None:
        raw = self._read_body()
        try:
            parsed = soap.parse_soap(raw, self._soap_action_header())
            request = soap.parse_discovery_request(parsed)
            response = soap.build_discover_response(self.config, request, parsed.message_id)
            print(
                f"Discovery: email={request.email!r}, requested={request.request_version!r}, "
                f"offered={request.auth_policies}, selected={soap.choose_auth_policy(self.config.auth_policy, request.auth_policies)!r}",
                flush=True,
            )
            self.store.record_event(
                None,
                "discovery",
                {
                    "email": request.email,
                    "request_version": request.request_version,
                    "device_type": request.device_type,
                    "auth_policies": request.auth_policies,
                },
            )
            self.tracer.exchange(
                "discovery",
                request_body=raw,
                response_body=response,
                meta={
                    "client": self.client_address[0],
                    "path": self.path,
                    "email": request.email,
                    "request_version": request.request_version,
                    "device_type": request.device_type,
                    "auth_policies": request.auth_policies,
                    "selected_auth_policy": soap.choose_auth_policy(
                        self.config.auth_policy,
                        request.auth_policies,
                    ),
                    "http_status": 200,
                },
            )
            self._send_soap(200, response)
        except Exception as exc:
            fault = soap.build_fault(str(exc))
            self.tracer.exchange(
                "discovery-error",
                request_body=raw,
                response_body=fault,
                meta={
                    "client": self.client_address[0],
                    "path": self.path,
                    "error": str(exc),
                    "http_status": 500,
                },
            )
            self._send_soap(500, fault)

    def _handle_enrollment_service(self) -> None:
        raw = self._read_body()
        try:
            parsed = soap.parse_soap(raw, self._soap_action_header())
            token_types = [value_type.rsplit("/", 1)[-1] for value_type, _ in parsed.binary_tokens]
            print(
                f"Enrollment SOAP: action={parsed.action!r}, username={parsed.username!r}, "
                f"token_types={token_types}",
                flush=True,
            )
            if parsed.action == soap.ACTION_GET_POLICIES or parsed.action.endswith("/IPolicy/GetPolicies"):
                self._authenticate_enrollment(parsed)
                response = soap.build_xcep_response(parsed.message_id, self.config.enrollment_version)
                print("Enrollment SOAP: returned XCEP policy", flush=True)
                self.tracer.exchange(
                    "xcep-get-policies",
                    request_body=raw,
                    response_body=response,
                    meta={
                        "client": self.client_address[0],
                        "path": self.path,
                        "soap_action": parsed.action,
                        "username": parsed.username,
                        "token_types": token_types,
                        "http_status": 200,
                    },
                )
                self._send_soap(200, response)
                return
            if parsed.action == soap.ACTION_WSTEP_RST or parsed.action.endswith("/RST/wstep"):
                self._authenticate_enrollment(parsed)
                response = self._handle_wstep(parsed, raw, token_types)
                self._send_soap(200, response)
                return
            fault = soap.build_fault(f"Unsupported SOAP action: {parsed.action}", parsed.message_id)
            self.tracer.exchange(
                "enrollment-unsupported-action",
                request_body=raw,
                response_body=fault,
                meta={
                    "client": self.client_address[0],
                    "path": self.path,
                    "soap_action": parsed.action,
                    "username": parsed.username,
                    "token_types": token_types,
                    "http_status": 400,
                },
            )
            self._send_soap(400, fault)
        except PermissionError as exc:
            print(f"Enrollment rejected: {exc}", flush=True)
            fault = soap.build_fault(str(exc))
            self.tracer.exchange(
                "enrollment-rejected",
                request_body=raw,
                response_body=fault,
                meta={
                    "client": self.client_address[0],
                    "path": self.path,
                    "error": str(exc),
                    "http_status": 401,
                },
            )
            self._send_soap(401, fault)
        except Exception as exc:
            traceback.print_exc()
            fault = soap.build_fault(str(exc))
            self.tracer.exchange(
                "enrollment-error",
                request_body=raw,
                response_body=fault,
                meta={
                    "client": self.client_address[0],
                    "path": self.path,
                    "error": str(exc),
                    "http_status": 500,
                },
            )
            self._send_soap(500, fault)

    def _handle_wstep(self, parsed: soap.ParsedSoap, raw: bytes, token_types: list[str]) -> str:
        csr_token = soap.extract_pkcs10_token(parsed)
        device_id = (
            parsed.additional_context.get("DeviceID")
            or parsed.additional_context.get("DeviceName")
            or f"device-{uuid.uuid4()}"
        )
        email = (
            parsed.username
            or parsed.additional_context.get("UPN")
            or self._identity_from_federated_stub_token(parsed)
            or _identity_from_dev_token(parsed)
            or "anonymous@example.invalid"
        )
        issued = crypto.issue_client_certificate_from_pkcs10(
            csr_token,
            self.config.ca_cert_file,
            self.config.ca_key_file,
            fallback_common_name=device_id,
        )
        provisioning_xml = provisioning.build_provisioning_document(
            self.config,
            issued,
            email,
            device_id,
        )
        provisioning_b64 = base64.b64encode(provisioning_xml.encode("utf-8")).decode("ascii")
        enrollment_id = self.store.record_enrollment(
            email=email,
            device_id=device_id,
            provider_id=self.config.provider_id,
            cert_thumbprint=issued.thumbprint_sha1,
            cert_subject=issued.subject,
            client_cert_pem=issued.pem,
            auth_policy=self.config.auth_policy,
            additional_context=parsed.additional_context,
        )
        self.store.record_event(
            enrollment_id,
            "enrolled",
            {
                "email": email,
                "device_id": device_id,
                "cert_thumbprint": issued.thumbprint_sha1,
                "cert_subject": issued.subject,
                "valid_to": issued.valid_to_iso,
            },
        )
        print(
            f"Enrollment complete: id={enrollment_id}, email={email!r}, "
            f"device_id={device_id!r}, thumbprint={issued.thumbprint_sha1}",
            flush=True,
        )
        response = soap.build_wstep_response(provisioning_b64, parsed.message_id)
        self.tracer.exchange(
            "wstep-rst",
            request_body=raw,
            response_body=response,
            meta={
                "client": self.client_address[0],
                "path": self.path,
                "soap_action": parsed.action,
                "username": parsed.username,
                "token_types": token_types,
                "enrollment_id": enrollment_id,
                "email": email,
                "device_id": device_id,
                "cert_thumbprint": issued.thumbprint_sha1,
                "cert_subject": issued.subject,
                "http_status": 200,
            },
        )
        self.tracer.artifact(
            "wstep-provisioning-document",
            provisioning_xml,
            extension=".wap.xml",
            meta={
                "enrollment_id": enrollment_id,
                "email": email,
                "device_id": device_id,
                "cert_thumbprint": issued.thumbprint_sha1,
                "syncml_url": self.config.syncml_url,
                "provider_id": self.config.provider_id,
            },
        )
        return response

    def _handle_syncml(self, query: str) -> None:
        raw = self._read_body()
        peer_thumbprint = crypto.peer_cert_thumbprint(self.connection.getpeercert(binary_form=True))
        enrollment = self.store.get_enrollment_by_thumbprint(peer_thumbprint) if peer_thumbprint else None
        if self.config.require_syncml_mtls and enrollment is None:
            self.store.record_event(
                None,
                "syncml_rejected",
                {"reason": "missing_or_unknown_client_certificate", "thumbprint": peer_thumbprint or ""},
            )
            self._send_text(403, "Client certificate is required for SyncML\n")
            return

        try:
            request = syncml.parse_syncml(raw)
            syncml_match = "client_certificate" if enrollment else ""
            if enrollment is None and not self.config.require_syncml_mtls and request.source:
                enrollment = self.store.get_latest_enrollment_by_device_id(request.source)
                syncml_match = "device_id" if enrollment else "none"
            agent_state = None
            if enrollment:
                self.store.touch_enrollment(enrollment.id)
                agent_state = syncml.classify_agent_alerts(request, self.config.agent.product_id)
                if agent_state:
                    self.store.mark_agent_state(enrollment.id, agent_state)
                    enrollment.agent_state = agent_state
            response, agent_command_sent = syncml.build_syncml_response(self.config, request, enrollment)
            if enrollment and agent_command_sent:
                self.store.mark_agent_state(enrollment.id, "sent")

            mode = parse_qs(query).get("mode", [""])[0]
            self.store.record_sync_session(
                enrollment_id=enrollment.id if enrollment else None,
                cert_thumbprint=peer_thumbprint,
                session_id=request.session_id,
                msg_id=request.msg_id,
                source=request.source,
                target=request.target,
                mode=mode,
                request_xml=raw.decode("utf-8", errors="replace"),
                response_xml=response,
            )
            self.tracer.exchange(
                "syncml",
                request_body=raw,
                response_body=response,
                meta={
                    "client": self.client_address[0],
                    "path": self.path,
                    "query": query,
                    "peer_thumbprint": peer_thumbprint or "",
                    "syncml_match": syncml_match,
                    "enrollment_id": enrollment.id if enrollment else None,
                    "agent_enabled": self.config.agent.enabled,
                    "agent_state": enrollment.agent_state if enrollment else "",
                    "session_id": request.session_id,
                    "msg_id": request.msg_id,
                    "source": request.source,
                    "target": request.target,
                    "mode": mode,
                    "agent_command_sent": agent_command_sent,
                    "http_status": 200,
                },
            )
            self._send(200, self.config.default_encoding, response.encode("utf-8"))
        except Exception as exc:
            self.store.record_event(
                enrollment.id if enrollment else None,
                "syncml_error",
                {"error": str(exc), "thumbprint": peer_thumbprint or ""},
            )
            text = f"SyncML error: {exc}\n"
            self.tracer.exchange(
                "syncml-error",
                request_body=raw,
                response_body=text,
                meta={
                    "client": self.client_address[0],
                    "path": self.path,
                    "query": query,
                    "peer_thumbprint": peer_thumbprint or "",
                    "error": str(exc),
                    "http_status": 500,
                },
            )
            self._send_text(500, text)

    def _authenticate_enrollment(self, parsed: soap.ParsedSoap) -> None:
        policy = self.config.auth_policy
        if self.config.allow_anonymous_enrollment:
            return
        if policy == "OnPremise":
            expected = self.config.users.get(parsed.username)
            if not expected or expected != parsed.password:
                raise PermissionError("Invalid OnPremise enrollment credentials")
            return
        if policy == "Federated":
            if self.config.federated_auth_stub:
                self.tracer.event(
                    "federated_auth_stub_accept",
                    {
                        "client": self.client_address[0],
                        "soap_action": parsed.action,
                        "token_count": len(parsed.binary_tokens),
                    },
                )
                return
            has_token = any("DeviceEnrollmentUserToken" in value_type for value_type, _ in parsed.binary_tokens)
            if not has_token:
                raise PermissionError("Federated enrollment token is required")
            return
        if policy == "Certificate":
            if not parsed.binary_tokens:
                raise PermissionError("Certificate enrollment token is required")
            return

    def _serve_package(self, path: str) -> None:
        relative = unquote(path[len("/packages/") :]).replace("\\", "/")
        root = Path(self.config.package_dir).resolve()
        target = (root / relative).resolve()
        if root not in target.parents and target != root:
            self._send_text(403, "Forbidden\n")
            return
        if not target.is_file():
            self._send_text(404, "Package not found\n")
            return
        content_type = mimetypes.guess_type(str(target))[0] or "application/octet-stream"
        #data = target.read_bytes()
        self._send_file(200, content_type, target)

    def _soap_action_header(self) -> str:
        return self.headers.get("SOAPAction") or self.headers.get("Content-Type", "")

    def _read_body(self) -> bytes:
        length = int(self.headers.get("Content-Length", "0"))
        return self.rfile.read(length)

    def _send_soap(self, status: int, xml: str) -> None:
        self._send(status, "application/soap+xml; charset=utf-8", xml.encode("utf-8"))

    def _send_text(self, status: int, text: str) -> None:
        self._send(status, "text/plain; charset=utf-8", text.encode("utf-8"))

    def _send(
        self,
        status: int,
        content_type: str,
        body: bytes,
        *,
        headers: dict[str, str] | None = None,
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def _send_file(self, status: int, content_type: str, path: Path) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(path.stat().st_size))
        self.end_headers()
    
        with path.open("rb") as f:
            while chunk := f.read(64 * 1024):  # 64 KB chunks
                try:
                    self.wfile.write(chunk)
                except (ssl.SSLEOFError, BrokenPipeError):
                    # Client closed the connection; safe to ignore
                    break

    def _remember_federated_stub_identity(self, token: str, identity: str) -> None:
        variants = set(_token_text_variants(token))
        with self.server.federated_stub_lock:
            for variant in variants:
                self.server.federated_stub_identities[variant] = identity

    def _identity_from_federated_stub_token(self, parsed: soap.ParsedSoap) -> str:
        with self.server.federated_stub_lock:
            identities = dict(self.server.federated_stub_identities)
        for _, token in parsed.binary_tokens:
            for candidate in _token_text_variants(token):
                identity = identities.get(candidate)
                if identity:
                    return identity
        return ""

    def log_message(self, fmt: str, *args) -> None:
        sys.stderr.write("%s - - [%s] %s\n" % (self.client_address[0], self.log_date_time_string(), fmt % args))


def serve(config: ServerConfig) -> None:
    Path(config.state_dir).mkdir(parents=True, exist_ok=True)
    Path(config.package_dir).mkdir(parents=True, exist_ok=True)
    agent_package = configure_agent_package(config)
    crypto.ensure_lab_pki(config)
    store = Store(config.database_path)
    tracer = TraceLogger(enabled=config.verbose_file_logging, log_dir=config.log_dir)
    if config.agent.enabled:
        tracer.event(
            "agent_config",
            {
                "auto_package": config.agent.auto_package,
                "package_path": str(agent_package) if agent_package else "",
                "url": config.agent.url,
                "sha256": config.agent.sha256,
            },
        )
    httpd = MDMHTTPServer((config.host, int(config.port)), MDMRequestHandler, config, store, tracer)

    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(config.tls_cert_file, config.tls_key_file)
    context.load_verify_locations(cafile=config.ca_cert_file)
    context.verify_mode = ssl.CERT_OPTIONAL if config.require_syncml_mtls else ssl.CERT_NONE
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)

    print(f"Serving MDM on https://{config.host}:{config.port}")
    print(f"Discovery: {config.public_base_url}{config.discovery_path}")
    print(f"Enrollment: {config.enrollment_service_url}")
    print(f"SyncML: {config.syncml_url}")
    if config.agent.enabled:
        if agent_package:
            print(f"Agent MSI auto-selected: {agent_package}")
        else:
            print("Agent MSI: using configured URL/hash")
        print(f"Agent package URL: {config.agent.url}")
        print(f"Agent package SHA-256: {config.agent.sha256}")
    if config.verbose_file_logging:
        print(f"Verbose protocol logging: {config.log_dir}")
        print("WARNING: trace files may include credentials, tokens, and provisioning secrets.")
    if config.allow_anonymous_enrollment:
        print("WARNING: anonymous enrollment is enabled; do not use this setting outside a lab.")
    if config.federated_auth_stub:
        print("WARNING: federated auth stub is enabled; all federated enrollment tokens are accepted.")
    httpd.serve_forever()


def _is_auth_path(path: str) -> bool:
    normalized = path.rstrip("/") or "/"
    return normalized in {"/auth/login", "/windowsfederated"}


def _identity_from_dev_token(parsed: soap.ParsedSoap) -> str:
    for _, token in parsed.binary_tokens:
        for candidate in _token_text_variants(token):
            if not candidate.startswith("dev-federated-token:"):
                continue
            parts = candidate.split(":", 3)
            if len(parts) >= 3 and parts[1]:
                return parts[1]
    return ""


def _token_text_variants(token: str) -> list[str]:
    values: list[str] = []

    def add(value: str) -> None:
        if not value or value in values:
            return
        values.append(value)
        unquoted = unquote(value)
        if unquoted != value:
            add(unquoted)
        stripped = unquoted.rstrip("/")
        if stripped != unquoted:
            add(stripped)

    add(token)
    try:
        decoded = base64.b64decode(token, validate=True).decode("utf-8", errors="ignore")
        add(decoded)
    except Exception:
        pass
    return values
