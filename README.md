# TethysGuard

TethysGuard is a cybersecurity monitoring and threat-detection platform built as a practical SOC portfolio project. The current backend receives security events, stores them in SQLite, applies explainable detection rules, creates alerts, and supports a basic analyst workflow.

## Current features

- FastAPI REST API
- SQLite event and alert storage
- Explainable detection rules for malware, port scans, unauthorized access, suspicious authentication, and brute-force activity
- Automatic alert generation
- Rule IDs, evidence, confidence, risk scores, and detection timestamps
- MITRE ATT&CK mappings for supported detections
- Threshold-based failed-login detection to reduce noisy alerts
- Multi-event correlation for brute force, repeated scans, attack sequences, and suspicious host activity
- Alert deduplication, suppression, and event grouping
- Related-event evidence for alert investigation
- Alert lookup and status updates
- Alert status audit history
- Analyst assignment, append-only investigation notes, and a paginated activity timeline
- False-positive resolution and reopening with preserved audit history
- Paginated event and alert search
- Severity, status, source IP, event type, and date filters
- Dashboard statistics
- Interactive OpenAPI documentation
- Batch telemetry ingestion with per-record validation results
- SSH authentication message normalization and brute-force detection
- Local account login/logout, password changes, and revocable server-side sessions
- Viewer, analyst, and admin permissions enforced by the API
- Admin account creation, role changes, and disabling; account-linked investigation history

## Project structure

```text
TethysGuard/
|-- Backend/
|   |-- routes/        # API endpoints
|   |-- auth.py        # Password hashing, sessions, and role dependencies
|   |-- config.py      # Environment-based settings
|   |-- correlation.py # Multi-event correlation rules
|   |-- database.py    # SQLite connections and schema setup
|   |-- detection.py   # Detection rules
|   |-- ingestion.py   # Telemetry adapters and batch processing
|   |-- investigation.py # Assignment, notes, and activity history
|   |-- main.py        # FastAPI application setup
|   |-- manage_users.py # Local first-admin bootstrap and password recovery
|   |-- schemas.py     # Request and response models
|   `-- services.py    # Application and database operations
|-- Frontend/          # React/TypeScript SOC dashboard and UI tests
|-- tests/             # Automated API tests
|-- examples/          # Synthetic telemetry for local demonstrations
|-- .env.example       # Safe configuration example
|-- requirements.txt   # Runtime dependencies
`-- requirements-dev.txt
```

## Setup

Python 3.10 or newer is required.

### Windows PowerShell

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements-dev.txt
```

### macOS or Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements-dev.txt
```

## Create your first admin

After activating your Python environment, run from the repository root:

```powershell
python -m Backend.manage_users bootstrap --username admin
```

Enter and confirm your own password at the hidden prompt (15–128 characters). There is no
default password or public registration. Bootstrap works only when there are no accounts.
Use the same `TETHYSGUARD_DATABASE_PATH` for this command and the server if you override it.
Back up a valued database before upgrading; startup adds auth tables and a nullable activity
user reference without deleting/rebuilding existing tables. Old history stays unverified.

For local password recovery (requires access to the machine/database):

```powershell
python -m Backend.manage_users reset-password --username admin
```

This revokes that user's sessions but does not enable a disabled account or change its role.
Passwords are never command-line arguments. Protect access to the database and local shell.

## Run the backend

Run this command from the repository root:

```powershell
python -m uvicorn Backend.main:app --reload
```

Open the API documentation at <http://127.0.0.1:8000/docs>.

## Run the tests

```powershell
python -m pytest
```

The tests use temporary SQLite databases and do not modify the local development database.

## Configuration

The defaults work for local development. Optional environment variables are documented in `.env.example`:

- `TETHYSGUARD_APP_NAME`
- `TETHYSGUARD_APP_VERSION`
- `TETHYSGUARD_DATABASE_PATH`
- `TETHYSGUARD_CORS_ORIGINS`
- `TETHYSGUARD_MAX_REQUEST_BODY_BYTES`
- `TETHYSGUARD_FAILED_LOGIN_THRESHOLD`
- `TETHYSGUARD_FAILED_LOGIN_WINDOW_MINUTES`
- `TETHYSGUARD_CORRELATION_WINDOW_MINUTES`
- `TETHYSGUARD_REPEATED_SCAN_THRESHOLD`
- `TETHYSGUARD_SUSPICIOUS_HOST_THRESHOLD`
- `TETHYSGUARD_ALERT_SUPPRESSION_MINUTES`
- `TETHYSGUARD_COOKIE_SECURE` (false for local HTTP only; true for HTTPS)

The application reads environment variables directly. It does not automatically load `.env` files yet.

Existing installations retain access to their original database: if `Backend/tethysguard.db` does not exist, the application reuses `Backend/aegissoc.db` when present. New installations use `Backend/tethysguard.db`. Legacy `AEGISSOC_` environment variables remain supported; `TETHYSGUARD_` values take precedence. Set the database path explicitly when both files exist.

## API endpoints

| Method | Endpoint | Purpose |
|---|---|---|
| `GET` | `/` | API information |
| `GET` | `/health` | Health check |
| `POST` | `/api/events` | Submit a security event |
| `POST` | `/api/ingest/batch` | Import native events or SSH authentication messages |
| `GET` | `/api/events` | Retrieve events |
| `GET` | `/api/alerts` | Retrieve alerts |
| `GET` | `/api/alerts/{alert_id}` | Retrieve one alert |
| `GET` | `/api/alerts/{alert_id}/events` | Retrieve events related to an alert |
| `PATCH` | `/api/alerts/{alert_id}` | Update alert status |
| `GET` | `/api/alerts/{alert_id}/history` | Retrieve alert status history |
| `PATCH` | `/api/alerts/{alert_id}/assignment` | Assign or unassign an alert |
| `POST` | `/api/alerts/{alert_id}/notes` | Append an analyst note |
| `GET` | `/api/alerts/{alert_id}/timeline` | Retrieve paginated investigation activity |
| `GET` | `/api/dashboard/stats` | Retrieve dashboard statistics |
| `POST` | `/api/auth/login` | Sign in and set the session cookie |
| `GET` | `/api/auth/me` | Current account and session CSRF token |
| `POST` | `/api/auth/logout` | Revoke the current session |
| `POST` | `/api/auth/password` | Change own password and revoke all own sessions |
| `GET` | `/api/auth/assignees` | Active analyst/admin accounts (analysts/admins only) |
| `GET/POST` | `/api/auth/users` | List/create accounts (admin only) |
| `PATCH` | `/api/auth/users/{user_id}` | Change role/active state (admin only) |

All data APIs require login. Root, health, OpenAPI docs, and login remain public.
Backend role checks apply even if someone bypasses the frontend:

| Capability | Viewer | Analyst | Admin |
|---|---|---|---|
| Read dashboard, events, alerts, history | Yes | Yes | Yes |
| Notes, assignments, status/resolution changes | No | Yes | Yes |
| Submit events / batch telemetry | No | No | Yes |
| Manage accounts | No | No | Yes |
| Change own password / log out | Yes | Yes | Yes |

Role changes and disabling revoke the target user's sessions. The last active admin cannot
be disabled or demoted. No account deletion endpoint exists; usernames cannot be renamed/reused.

## Pagination and filters

Event and alert list endpoints return at most 50 records by default and support a maximum page size of 100.

Example requests:

```text
GET /api/events?limit=25&offset=0&severity=high&sort_by=timestamp&sort_order=desc
GET /api/events?source_ip=192.0.2.10&event_type=port_scan
GET /api/alerts?status=open&severity=critical&search=malware
```

Both list responses include `count`, `total`, `limit`, and `offset`, used by the dashboard page controls.

## Development status

### Phase 1 - Initial SOC backend prototype

Completed:

- FastAPI application and health endpoint
- SQLite event and alert storage
- Security event ingestion
- Rule-based detection and automatic alerts
- Alert investigation status workflow
- Dashboard statistics API

### Phase 2 - Backend foundation

Completed:

- Reproducible dependency setup
- Modular backend package structure
- Environment-based configuration
- Safer database connections and foreign-key enforcement
- Request and response schemas
- Automated API and detection tests
- Root-level run command and setup documentation

### Phase 3 - API hardening and data validation

Completed:

- Strict IP, severity, status, text-length, and payload validation
- Input normalization and unknown-field rejection
- Pagination, filtering, sorting, and search
- Additive database constraints and indexes
- Database-aware health checks
- Alert status audit history

### Phase 4 - Detection engineering

Completed:

- Explainable rule IDs and metadata
- Detection evidence and confidence
- Risk scoring
- MITRE ATT&CK mappings
- Threshold-based failed-login detection
- Multiple rule matches for one event when appropriate
- Detection tests for malware, port scans, unauthorized access, suspicious authentication, brute force, and critical events

### Phase 5 - Event correlation

Completed:

- Time-window grouping by source IP, username, and host
- Brute-force correlation across related failed-login events
- Reconnaissance followed by authentication activity detection
- Repeated network-scan correlation
- Suspicious host activity correlation
- Alert deduplication, suppression, and grouping
- Related-event storage and retrieval for investigations
- Deterministic correlation and API tests

### Phase 6 - Telemetry ingestion

Completed:

- Batch JSON ingestion through `POST /api/ingest/batch`
- Native security-event and SSH authentication adapters
- Per-record validation errors with zero-based indices
- Reuse of detection, correlation, suppression, and investigation evidence
- Synthetic SSH demo data and automated ingestion tests

See [PROGRESS.md](PROGRESS.md) for ingestion limitations and development progress.

### Phase 7 - SOC dashboard frontend

- React and TypeScript dashboard with totals, severity/status charts, and recent activity
- Searchable, paginated alert/event tables with severity and status filters
- Alert investigation with evidence, MITRE context, related events, and status updates
- Central API client, loading/empty/error states, and responsive layout
- Manual refresh and HTTP/REST integration; live delivery is a later phase

### Phase 8 - Analyst investigation workflow

- Assign/unassign alerts and display ownership in the alert queue
- Append analyst notes with timestamps and actor labels
- Paginated newest-first timeline showing creation, assignment, notes, and status changes
- False-positive resolution, normal resolution, and reopening
- Atomic workflow/audit writes, legacy-history backfill, and regression tests

### Phase 9 - Authentication and role-based permissions

- Login/logout, password changes, and first-admin CLI bootstrap
- Salted scrypt password hashes; hashed random session tokens in SQLite
- HttpOnly/SameSite cookies, CSRF tokens, explicit-origin checks, and login throttling
- Backend role enforcement, admin account management, and account-linked investigation actions
- Role-aware frontend, session restoration/expiry handling, and security regression tests

Next: Phase 10 real-time monitoring.

## Run the SOC dashboard

Start FastAPI using the backend command above, then open a second terminal:

```powershell
cd Frontend
npm ci
npm run dev
```

Use Node.js 24 LTS. Open http://localhost:5173. Vite proxies `/api` to http://127.0.0.1:8000.
Sign in with the admin account you created. Use **Manage users** to add analyst/viewer accounts.
The frontend reads real backend data. An empty database shows empty states; use the SSH sample below to add demo activity.
Open an alert, change its status, and click **Save status** to persist the change and record the backend audit history.
Search and filter controls reset pagination. The Overview refresh button reloads the totals and recent activity.

```powershell
npm run build
npm run lint
npm test
```

The production build is written to `Frontend/dist`. Production hosting needs an SPA fallback to `index.html`
and an `/api` reverse proxy, or a `VITE_API_BASE_URL` set before building (see `Frontend/.env.example`).
Prefer a same-origin `/api` reverse proxy. If using separate origins, configure the exact frontend
origin in the CORS allowlist; wildcard origins are rejected. SameSite=Strict requires same-site
frontend/backend hosts (do not mix localhost and 127.0.0.1 for direct API URLs).
For HTTPS, set `TETHYSGUARD_COOKIE_SECURE=true`; local HTTP defaults are not suitable for deployment.
Authentication is implemented, but this is still a local portfolio app, not a production-hardened SOC.

## Try an investigation

1. Start the backend and frontend, sign in as an analyst/admin, then open an alert from **Alerts**.
2. Select an active analyst/admin assignee and choose **Save assignment**. Your acting identity comes from your login.
3. Change the status to **Investigating** and save it.
4. Write the evidence you checked in **Investigation note**, then choose **Add note**.
5. Resolve the alert normally or choose **False Positive**. Reload the page to check persistence.
6. Check the timeline for each action. Reopen the alert if more investigation is needed.

Choose **Unassigned** to unassign the alert. Notes support up to 4,000 characters.
Notes render as plain text and cannot be edited or deleted
through the API. Use a follow-up note for corrections. The existing request byte limit still applies.

False positives use `status: "resolved"` plus `resolution: "false_positive"`.
This preserves existing database status constraints, filters, and dashboard counts; false positives
are included in the resolved count. Reopening clears the resolution, not the notes or history.
A status update with no resolution clears any previous false-positive classification.

Example request bodies:

```json
{"assigned_to": "analyst"}
```

Send this to `PATCH /api/alerts/1/assignment` after creating an active analyst account named `analyst`; use `null` to unassign.

```json
{"body": "Checked host logs; this was an authorized lab scan."}
```

Send this to `POST /api/alerts/1/notes`.

```json
{"status": "resolved", "resolution": "false_positive"}
```

Send this to `PATCH /api/alerts/1`. All mutations need the session cookie and CSRF header.
Legacy `actor` fields are accepted but ignored: identity is always taken from the session.
Timeline requests accept `limit` (default 25, maximum 100) and `offset`.
The old `/history` endpoint continues to return status transitions only.

Startup adds nullable assignment/resolution fields and a new activity table without rebuilding
or deleting existing tables. Old status history is imported once as `Unknown (legacy)`;
new workflow actions and their audit entries commit together. Back up any valued database
before upgrading, as with any schema change.

New actions include an immutable account ID and username snapshot; old names are retained as
legacy/unverified labels. Database history is still not tamper-proof. Multiple editors use last-write-wins updates.
Notes are not idempotent: if a request times out, refresh the timeline before retrying to avoid duplicates.

## Authentication details and limits

- Passwords: salted scrypt using Python's standard library (`N=16384, r=8, p=5`).
- Sessions: random 256-bit tokens, only their SHA-256 digests stored in SQLite; 8-hour absolute expiry.
- Browser sessions use HttpOnly, SameSite=Strict cookies; no auth tokens in localStorage.
- Authenticated writes require `X-CSRF-Token` from login or `GET /api/auth/me`.
- Login requires `X-TethysGuard-Request: 1`; browser Origin headers must match the configured allowlist.
- API responses are no-store; validation errors do not echo submitted passwords.
- Login allows 5 attempts per username and 20 per directly connected source IP within 5 minutes
  (successful attempts also count). Forwarded IP headers are not trusted. Behind a proxy, clients
  share its source-IP limit; production deployment needs a reviewed proxy/rate-limiting design.
- Account creation/changes, successful login/logout, and password changes are recorded in `account_audit`.
  Login attempt records are retained for the rate-limit window, not a permanent failure audit.
- No MFA, SSO, password-breach lookup, service-account API keys, or email recovery yet. Sessions have no
  sliding/idle timeout. Database/file permissions, HTTPS, backups, monitoring, and deployment hardening remain necessary.

The password/session choices follow the [OWASP Password Storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
and [Session Management](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html) guidance;
this does not imply a complete security certification.

## Import telemetry

With the backend running, sign in as an admin and submit the synthetic sample from PowerShell.
The credential prompt keeps the password out of command history; do not print or share the session/header variables.

```powershell
$credential = Get-Credential -UserName admin -Message "TethysGuard admin login"
$loginBody = @{ username = $credential.UserName; password = $credential.GetNetworkCredential().Password } | ConvertTo-Json
$login = Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8000/api/auth/login -ContentType 'application/json' -Headers @{ 'X-TethysGuard-Request' = '1' } -Body $loginBody -SessionVariable session
$loginBody = $null
$credential = $null
$headers = @{ 'X-CSRF-Token' = $login.csrf_token }
$batch = Get-Content -Raw examples/ssh-auth-batch.json
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8000/api/ingest/batch -ContentType 'application/json' -Body $batch -WebSession $session -Headers $headers
Invoke-RestMethod -Uri http://127.0.0.1:8000/api/alerts -WebSession $session
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8000/api/auth/logout -WebSession $session -Headers $headers
```

On a fresh database with default thresholds, five failed logins create a `TG-AUTH-001` brute-force alert. The sixth record is a successful login from a different IP and creates no alert. These are synthetic documentation IP addresses; no network traffic is generated.

Each request selects one `source` and supplies 1–100 `records`:

- `security_event`: each record uses the same fields as `POST /api/events`.
- `ssh_auth`: each record contains `host` and `message`. Supply the sshd message body, such as `Failed password for invalid user admin from 192.0.2.10 port 52101 ssh2`, without the syslog timestamp or process prefix. Supported forms are `Failed` or `Accepted`, with `password` or `publickey`; optional key details after `ssh2` are preserved. This is a deliberately limited parser, not a complete syslog collector.

Responses contain `received`, `accepted`, `rejected`, `results`, and `errors`. Each result or error identifies the original zero-based record `index`. Accepted results include event IDs, new alert IDs, and suppression/grouping details. Malformed records are rejected without storing them, while valid records continue. A valid envelope returns HTTP 200 even when every record is rejected; invalid envelopes return 422.

The existing request-size limit still applies (16 KiB by default), so split larger batches even when they contain fewer than 100 records. Events use arrival timestamps: submitting old logs together can produce correlation alerts that would not reflect their original timing. Each accepted event commits independently; a database failure returns 500 and earlier records may already be stored. Retrying records creates new events, although matching active alerts can be suppressed. Authentication is required, but replay/idempotency protection is still future work.
