# ShadowNet deployment runbook

## Current release boundary

A hardened research and shadow-mode pilot for one trusted SOC team. Operators share this organization's replay and telemetry resources. The service is not multi-tenant. No autonomous blocking is implemented. Model recall and independent validation remain release blockers for operational alerting. Software readiness is not a certification of security or prediction quality.

## Verified locally on 24 September 2026

- 51 automated tests and the synthetic pilot integrity workflow pass on Python 3.12.14.
- The installed upgraded dependency audit reports zero known vulnerabilities, down from 52 advisories across 11 packages in the old environment. This does not prove absence of vulnerabilities.
- An isolated production process passes authentication, trained inference, restart persistence, audit and token-revocation checks. Sixty-four concurrent liveness requests succeed at concurrency eight. This is a smoke test, not a throughput SLO.
- Use `.venv-enterprise`, not the old Python 3.9 `.venv`. Runtime versions are pinned in `requirements.txt` and `requirements.lock.txt`. The old environment remains untouched for rollback comparison.
- `make production-check` reruns the isolated startup/restart smoke check using temporary storage. It does not alter deployment accounts or existing data.

Evidence: [`release-evidence/summary.json`](release-evidence/summary.json). The CI workflow now gates tests, a fresh dependency audit and a non-root container startup/restart test. Those remote CI jobs have not been executed in this session.

## On-premises pilot deployment

1. Review the committed checkpoint and its expected SHA-256. Never load an untrusted PyTorch checkpoint. The application verifies the configured release digest before deserialization.
2. Copy `.env.example` to `.env`. Generate a random secret locally, for example with `python -c 'import secrets; print(secrets.token_urlsafe(48))'`. Store it in your secret manager, and set `SHADOWNET_TOKEN_SECRET`. Do not paste it into chat or logs.
3. Set `SHADOWNET_TRUSTED_HOSTS` to the served DNS name plus `localhost,127.0.0.1` for health checks. Set approved Kafka broker endpoints only if required. Production Kafka connections require verified TLS. Configure the Kafka transport settings below and restrict broker metadata egress at the network layer before wider integration.
4. Run `docker compose up --build -d`. Compose binds only to loopback. Terminate HTTPS at the organization's reverse proxy. Require TLS 1.2 or newer, configure the correct certificate, request and idle timeouts, connection/rate limits, and a maximum request body of 251 MiB. Only trust forwarded headers from your configured proxy. Set network policy so this host can reach only approved telemetry systems.
5. Create the first admin with `docker compose exec shadownet python -m scripts.manage_users YOUR_ADMIN --role admin`. The password prompt is hidden. Create viewer and operator accounts through the admin API as needed. Do not use shared privileged credentials.
6. Verify `/api/health` and `/api/ready`. Test login, a representative capture, OOD suppression, a token revocation and audit integrity. Retain the fixed-test report alongside the checkpoint digest.

The image runs as UID 10001, with a read-only root filesystem, dropped capabilities and persistent `/app/data`. Local profiles live in `/app/data/calibrations`, never in the image's model directory. Uploads, users and audit data persist in the named volume. Protect that volume as sensitive data. The prototype development mode remains available for localhost work.

## Capacity and lifecycle

One Uvicorn worker only. WebSocket/replay sessions and Kafka bridges reside in process memory. Do not scale replicas behind a load balancer until session routing, external state storage and consumer ownership are designed. `WEB_CONCURRENCY` is validated in production, but do not override the supplied Uvicorn command with extra workers.

Defaults: 32 concurrent HTTP connections, 32 replay sessions, 32 telemetry streams, 250 MiB capture content per upload, 2 MiB non-upload request bodies, 8 KiB WebSocket messages, at most 60 replay seconds per advance, and 30-minute inactive-session expiry. Telemetry gaps over 720 five-second windows require a new stream. Windows over 50,000 telemetry records or 100,000 PCAP packets fail closed. These are protective limits, not measured throughput guarantees.

Calibration accepts at most 16 captures per request and one fitting job at a time. Individual calibration captures are limited to 500,000 packets and 24 hours. Entire calibration captures must have uniform labels. Do not submit mixed benign/attack timelines with one label.

Run a periodic disk-usage check. Graceful shutdown closes readers, removes active replay uploads and stops bridges. Abrupt termination can leave orphaned upload files. Delete only orphaned upload files during a maintenance window with the service stopped. Session IDs are invalid after restart. Do not delete users, audit data or profiles during that cleanup.

## Authentication and audit

Bearer tokens expire after one hour, and each WebSocket advance rechecks token validity. Logout revokes all current tokens for that account. Replacing a password or role also invalidates previous tokens. Use admin privileges for user creation, calibration and broker connection. Viewers cannot advance replays.

Login attempts persist in SQLite and are limited over five minutes by account, client and a global ceiling. A reverse proxy can concentrate client addresses, so tune proxy configuration and measure shared-client behavior. This protects the local service but is not an enterprise identity system. OIDC/SAML, MFA, centralized access reviews and recovery procedures remain future integration work.

Audit appends use a serialized SQLite transaction so concurrent requests form one chain. Keyed integrity detects modified entries. It cannot prove a chain was not truncated at the end unless its latest hash is anchored outside the database. Export audit logs to a separately controlled, append-only store before production use. A database write failure can occur after a business action succeeds: avoid blind automatic retries of mutations. If HTTP mutation auditing fails, the API returns 503 with a request ID and an explicit warning that the operation may have completed; inspect the operation state before retrying. API mutations and successful WebSocket advances are audited, but this is not comprehensive security-event coverage.

## Monitoring and recovery

- Liveness: `/api/health` returns HTTP 200 when the process can respond.
- Readiness: `/api/ready` returns 503 for failed model/OOD, packaged-data, database or audit checks. Its `claims_allowed` remains false. Audit verification streams rows with bounded memory and is cached for up to five seconds per process to avoid rescanning the full history on every probe; model and database checks run on every request. The admin audit-verification endpoint always performs a fresh full scan. Schedule probes with a timeout appropriate to the retained audit history.
- Correlation: HTTP responses include `X-Request-ID`. Application logging records method, path, status and duration without request bodies, passwords or bearer tokens. Collect process logs through your standard logging platform. Configure the `shadownet.api` logger at INFO if the host logging configuration filters it out.
- Monitor CPU/RSS, open descriptors, disk utilization, 429/5xx rates, inference latency, stream lag and rejected records. Full metrics export and SLO dashboards are still pending.
- Model failure: preserve the failed release and diagnostic logs. Roll back the image, approved checkpoint and compatible calibration profiles together. Never switch to demo output as a model fallback.

## Backup and restore

Stop ingestion during a backup window. Stop the container, snapshot the complete data volume and separately escrow the stable token/audit secret. Encrypt the backup and restrict access. Restart and check readiness. For an online backup, use SQLite's backup API rather than copying a live database file in isolation.

For a minimal application recovery snapshot, use the CLI below with the original
`SHADOWNET_TOKEN_SECRET` already set in the environment. Pause ingestion and
profile changes first. Parent directories must exist; destinations must not.

```sh
.venv-enterprise/bin/python scripts/manage_backup.py backup --source /path/to/data --destination /path/to/backups/release-001
.venv-enterprise/bin/python scripts/manage_backup.py restore --source /path/to/backups/release-001 --destination /path/to/recovered-data
```

The snapshot includes SQLite accounts, revocation versions, login limits, audit
history, and calibration JSON files. It excludes captures, transient sessions,
model weights and secrets. Keep the matching image/checkpoint and original secret
separately. The HMAC manifest authenticates file hashes and the audit count; it
is not encryption or an external audit anchor. Store snapshots on encrypted,
access-controlled storage. Restore checks all hashes, database integrity and audit
history before publishing a new directory. Existing destinations are never
replaced. A crash during publication may leave an empty reserved destination;
inspect it before removing it and retrying. Restoring an older snapshot also
restores older account/password and token-revocation state: reconcile changes made
since that backup before exposing the restored service.

Test restore on a separate isolated host: restore the volume with UID 10001 ownership, provide the original secret and approved checkpoint, start the same release, verify readiness, verify the audit chain, verify users and profiles, and run a fresh representative replay. Do not reconnect real Kafka consumers during a recovery test. Losing the audit secret prevents verification of historical entries. Rotating the secret requires an explicit audit-key migration design.

## Evidence required before claiming enterprise readiness

1. Untouched representative local sessions showing acceptable early-warning coverage and false alerts/hour against baselines. Current coverage is 14/215 onsets, with severe external classifier failure.
2. Load, endurance, crash-recovery and restore tests on target hardware, with an agreed capacity/SLO budget.
3. A current dependency/container vulnerability audit, patched compatible packages and an SBOM. The upgraded Python 3.12 environment reports zero known dependency vulnerabilities as of 24 September 2026. Linux/container packages and the base image still need their target-specific audit. See `release-evidence/dependency-audit.json`.
4. Independent penetration testing and identity integration, secrets rotation, centralized audit anchoring and incident-response ownership.
5. Privacy and retention policy for raw telemetry, endpoint/identity data and captured payloads. Apply encryption at rest at the storage layer.
6. Real-broker TLS/SASL verification, egress restrictions, consumer failure monitoring and measured redelivery behavior. Commit-after-ingest is not exactly-once delivery.
7. Tenant isolation and external state management if the scope expands beyond one organization. Calibration profiles require stronger provenance and version migration for general release.

Docker Desktop is now installed locally. The Linux/arm64 demo image built successfully and passed localhost authenticated HTTP/WebSocket replay checks before and after container restart. It runs as UID 10001 with a read-only root filesystem. Remote CI and target production-host verification remain outstanding.

### Forecast contract and calibration compatibility

This release always returns `operating_mode: research_shadow_mode`,
`operational_alerting_enabled: false`, and `forecast[].alert: false`.
`forecast[].shadow_alert` records an experimental threshold crossing only when
OOD checks accept the input. It must not trigger operational actions.
`uncertainty.alerts_suppressed` is always true; `suppression_reasons` explains
validation and OOD restrictions. Use `uncertainty.status` for distribution status.
No environment variable enables operational alerting in this release.

Calibration profiles require schema version 2, the exact checkpoint SHA-256,
validation-only provenance, correctly sized finite vectors, positive temperatures,
probability thresholds in [0, 1], and ordered OOD bounds. Regenerate legacy
profiles with the updated calibration CLI. Invalid profiles fail model startup
closed; remove or regenerate the affected profile before restarting.

Run `.venv-enterprise/bin/python scripts/verify_inference_endurance.py --seconds 30 --workers 4`
for a bounded concurrent model exercise. Its synthetic input checks finite JSON
outputs and shadow-only behavior; it does not measure detection accuracy or
certify HTTP/Kafka capacity. Results are saved to `data/workflow/inference-endurance.json`.

### Telemetry consistency and Kafka worker health

`GET /api/telemetry/streams/{id}` returns a synchronized stream, inference-history,
and host-graph snapshot. Events rejected because their window already closed are
also excluded from host evidence. Status polling does not extend the idle-session TTL.

The `kafka` object reports `state` (`disconnected`, `starting`, `running`, `failed`,
or `stopped`), `connected` (worker liveness), and `error_type` (exception class only).
Worker liveness does not prove broker connectivity or message freshness. A failed
worker remains visible until its stream is deleted; investigate server logs, then
create a new stream and explicitly reconnect. There is no automatic retry loop.

Offsets are committed after a batch is ingested successfully. Polling, parsing,
or ingestion failures stop the worker without committing that batch. A commit
failure can cause redelivery, and stream/model history remains process-local:
these guarantees are neither durable processing nor exactly-once semantics.
Kafka tests use a controlled consumer double; a real-broker failure/recovery test
is still required before production integration.

Production disables `/docs`, `/redoc`, and `/openapi.json`. Early HTTP authorization failures and handled unexpected errors receive the same request ID, no-store policy, and security headers as successful API responses. Unexpected error details remain in server logs and are not returned to clients.

### Kafka TLS and credentials

Transport settings come only from deployment environment variables. Production
defaults to `SSL` and rejects `PLAINTEXT`; development can use plaintext on an
isolated test network. TLS checks the broker hostname and certificate chain and
requires TLS 1.2 or newer. There is no certificate-verification bypass.

- `SHADOWNET_KAFKA_SECURITY_PROTOCOL`: `SSL` or `SASL_SSL` in production.
- `SHADOWNET_KAFKA_CA_FILE`: optional PEM CA bundle; otherwise use system trust.
- `SHADOWNET_KAFKA_CERT_FILE` and `SHADOWNET_KAFKA_KEY_FILE`: optional client certificate and private key, configured together for mutual TLS.
- `SHADOWNET_KAFKA_SASL_MECHANISM`: `SCRAM-SHA-512` (default for SASL), `SCRAM-SHA-256`, or `PLAIN` over TLS.
- `SHADOWNET_KAFKA_USERNAME` and `SHADOWNET_KAFKA_PASSWORD_FILE`: SASL identity and mounted UTF-8 secret file. A final newline is removed. Non-container deployments may instead use `SHADOWNET_KAFKA_PASSWORD`; configuring both password sources is rejected.

Compose passes container paths through but does not mount host secrets by default.
Use a local Compose override to mount certificates and password files read-only at
those paths, readable by UID 10001. Do not place private keys or passwords in the
image or source tree. Restart/reconnect after rotating credentials or certificates.
The broker allowlist covers bootstrap endpoints only: Kafka metadata can advertise
additional brokers, so deployment firewall rules must enforce the intended egress.
Unit tests verify TLS settings and consumer wiring using a test double; certificate
handshake, broker authorization and redelivery require a real-broker integration test.
