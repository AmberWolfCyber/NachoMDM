# Python Windows MDM Server

This project is a Python implementation of the Windows MDM enrollment and management flow, serving an MSI to the machine enroling.

IMPORTANT RESTRICTION: The victim account starting the enrolment must be a member of the local administrators group on the machine. No UAC elevation is required.

It implements:

- MDM discovery at `/EnrollmentServer/Discovery.svc`.
- `MS-MDE2` SOAP discovery responses.
- `OnPremise` enrollment authentication with WS-Security `UsernameToken`.
- XCEP `GetPolicies` response for client certificate policy.
- WSTEP `RequestSecurityToken` handling with PKCS#10 CSR parsing.
- Local MDM CA issuance of client-auth certificates.
- Base64 `wap-provisioningdoc` generation with `CertificateStore`, `APPLICATION`, and `DMClient` bootstrap settings.
- OMA-DM/SyncML endpoint at `/omadm/Windows.ashx`.
- SyncML inventory `Get` commands.
- Optional first-sync MSI agent deployment through `EnterpriseDesktopAppManagement/MSI/{ProductID}/DownloadInstall`.
- SQLite audit/state database under `state/mdm.sqlite3`.

This is intended for controlled lab use first. A production MDM still needs tenant administration, hardened identity, revocation, WBXML coverage, broader CSP support, compliance logic, and operational monitoring.

## Quick Start (Ubuntu VPS)

Prerequisites: Python 3.11+, a Let's Encrypt certificate for your domain.

```bash
# Install dependencies
python3 -m pip install -r requirements.txt

# Run the setup wizard
sudo python3 -m mdmserver setup
```

The wizard will:

1. Scan `/etc/letsencrypt/live/` and let you pick a certificate
2. Configure your hostname, port, and auth policy
3. Generate the MDM certificate authority
4. Optionally create a systemd service

Once complete, start the server:

```bash
sudo python3 -m mdmserver serve --config config.json
```

This will print out the enrolment URL handler.

## Manual Setup

If you prefer to configure everything by hand, or are not using Let's Encrypt:

```bash
python3 -m mdmserver init-config --path config.json
```

Edit `config.json`:

- Set `public_base_url`, `enrollment_base_url`, and `management_base_url` to the HTTPS name the Windows device will reach.
- Set `tls_cert_file` and `tls_key_file` to your TLS certificate and key.
- Set a test username/password under `users`.
- Leave `auth_policy` as `Federated` for anonymous login.
- Set `allow_anonymous_enrollment` to `true` to accept any enrollment credentials.
- Set `agent.enabled` and the MSI product/job IDs only after basic enrollment works.
- Set `federated_auth_stub` to `true`

Generate a lab CA (and self-signed TLS cert if you don't have one):

```bash
python3 -m mdmserver init-pki --config config.json
```

## Run

```bash
sudo python3 -m mdmserver serve --config config.json
```

The default config listens on `https://0.0.0.0:443`. For real Windows enrollment, the URL in config must match the certificate subject/SAN and the name the Windows client uses.

### Verbose Logging

If `verbose_file_logging` is `true`, the server writes protocol traces under
`state/logs` by default. These traces include:

- `events.ndjson` - one JSON event per line.
- `*-discovery.request.xml` and `*-discovery.response.xml`.
- `*-xcep-get-policies.request.xml` and `*-xcep-get-policies.response.xml`.
- `*-wstep-rst.request.xml` and `*-wstep-rst.response.xml`.
- `*-wstep-provisioning-document.wap.xml` - decoded provisioning document sent to Windows.
- `*-syncml.request.xml` and `*-syncml.response.xml` after the first DM session starts.

The trace files are intentionally raw and can include credentials, tokens, issued
certificates, and DM shared secrets. Use them only in a lab and delete them before
sharing a machine or reusing secrets.


### Authentication Modes

With `auth_policy` set to `OnPremise`, Windows normally shows a username/password
prompt. If `allow_anonymous_enrollment` is `true`, the server accepts whatever is
entered there, including dummy credentials.

To avoid the password prompt in many Windows builds, set:

```json
"auth_policy": "Federated",
"allow_anonymous_enrollment": true,
"federated_auth_stub": true,
"federated_dev_token": "Nw=="
```

The built-in `/windowsfederated/` endpoint auto-completes a dev federated login and
posts a test `wresult` token back to the Windows enrollment app, following the same
basic browser handoff pattern used by anonymous federated enrollment flows. The older
`/auth/login` path is also accepted as an alias. When `federated_auth_stub` is
enabled, the enrollment service accepts the federated XCEP and WSTEP requests without
validating the token. This is for local testing only and must not be used for a
production MDM service.

## MSI Agent Deployment

For a device-scope MSI agent:

1. Put one MSI under `packages/`.
2. Enable the agent and set the MSI product/job IDs:

```json
"agent": {
  "enabled": true,
  "auto_package": true,
  "product_id": "{YOUR-MSI-PRODUCT-CODE-GUID}",
  "job_id": "{YOUR-MSI-PRODUCT-CODE-GUID}",
  "version": "1.0.0",
  "url": "",
  "sha256": "",
  "command_line": "/quiet /norestart",
  "timeout_minutes": 10,
  "retry_count": 3,
  "retry_interval_minutes": 5,
  "download_from_aad": false
}
```

When `agent.auto_package` is `true`, server startup selects the first `*.msi`
in `package_dir` by filename, sets the download URL to
`{management_base_url}/packages/{filename}`, and calculates the SHA-256 hash of
that exact file. The selected path, URL, and hash are printed at startup and
written to verbose event logs when `verbose_file_logging` is enabled.

To host a package somewhere else, set `agent.auto_package` to `false` and fill
`agent.url` and `agent.sha256` manually. You can still calculate the hash with:

```
python3 -m mdmserver hash-agent .\packages\example-agent.msi
```

The server sends the MSI deployment during SyncML after enrollment, using:

```text
./Device/Vendor/MSFT/EnterpriseDesktopAppManagement/MSI/{ProductID}/DownloadInstall
```

The server later polls `Status`, `LastError`, `LastErrorDesc`, and `Version`.

## Files

- `mdmserver/server.py` - HTTPS routes and protocol dispatch.
- `mdmserver/soap.py` - SOAP parsing and response builders.
- `mdmserver/provisioning.py` - `wap-provisioningdoc` generation.
- `mdmserver/syncml.py` - OMA-DM SyncML parsing and command generation.
- `mdmserver/crypto.py` - CA/server/client certificate handling.
- `mdmserver/store.py` - SQLite state and audit events.
- `docs/windows-mdm-server-protocol.md` - protocol research and implementation notes.

## Troubleshooting

On the Windows client, check:

```text
Applications and Services Logs/Microsoft/Windows/DeviceManagement-Enterprise-Diagnostics-Provider
```

On the server, inspect:

```text
state/mdm.sqlite3
```


