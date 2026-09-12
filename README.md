# AegisSOC

AegisSOC is a cybersecurity monitoring and threat-detection platform built as a practical SOC portfolio project. The current backend receives security events, stores them in SQLite, applies explainable detection rules, creates alerts, and supports a basic analyst workflow.

## Current features

- FastAPI REST API
- SQLite event and alert storage
- Rule-based detection for malware, port scans, unauthorized access, and failed logins
- Automatic alert generation
- Alert lookup and status updates
- Dashboard statistics
- Interactive OpenAPI documentation

## Project structure

```text
AegisSOC/
|-- Backend/
|   |-- routes/        # API endpoints
|   |-- config.py      # Environment-based settings
|   |-- database.py    # SQLite connections and schema setup
|   |-- detection.py   # Detection rules
|   |-- main.py        # FastAPI application setup
|   |-- schemas.py     # Request and response models
|   `-- services.py    # Application and database operations
|-- tests/             # Automated API tests
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

- `AEGISSOC_APP_NAME`
- `AEGISSOC_APP_VERSION`
- `AEGISSOC_DATABASE_PATH`
- `AEGISSOC_CORS_ORIGINS`

The application reads environment variables directly. It does not automatically load `.env` files yet.

## API endpoints

| Method | Endpoint | Purpose |
|---|---|---|
| `GET` | `/` | API information |
| `GET` | `/health` | Health check |
| `POST` | `/api/events` | Submit a security event |
| `GET` | `/api/events` | Retrieve events |
| `GET` | `/api/alerts` | Retrieve alerts |
| `GET` | `/api/alerts/{alert_id}` | Retrieve one alert |
| `PATCH` | `/api/alerts/{alert_id}` | Update alert status |
| `GET` | `/api/dashboard/stats` | Retrieve dashboard statistics |

## Development status

### Phase 1 - Initial SOC backend prototype

Completed before the structured roadmap began:

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

Planned next:

- Strict input validation
- Pagination, filtering, sorting, and search
- Database constraints and indexes
- Database-aware health checks
- Alert status audit history

Advanced detection, event correlation, realistic telemetry ingestion, and the React dashboard are planned for later phases.
