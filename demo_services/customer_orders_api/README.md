# Customer Orders API — SentinelOps Fresh Service Acceptance Fixture

A standalone microservice built with FastAPI and Uvicorn for simulating a fresh customer application registered into SentinelOps AI.

## Purpose

This service is completely independent of the SentinelOps backend, database, and existing demo services. It acts as an acceptance fixture for onboarding a brand-new application into SentinelOps to test:
- Service registration and baseline health check probing.
- Prometheus metrics scraping.
- Failure detection and incident creation.
- AI investigation and root-cause analysis.
- Generic capability discovery (`inspect_service_health`, etc.).
- Controlled failure injection and recovery verification.

---

## Service Specifications

- **Default Address:** `http://127.0.0.1:9000`
- **Health Check Endpoint:** `http://127.0.0.1:9000/health` (or `http://127.0.0.1:9000/api/v1/health`)
- **Prometheus Metrics:** `http://127.0.0.1:9000/metrics`
- **Failure Simulation Status:** `http://127.0.0.1:9000/demo/status`
- **Failure Simulation Injection:** `POST http://127.0.0.1:9000/demo/simulate-failure`
- **Failure Recovery Reset:** `POST http://127.0.0.1:9000/admin/recovery/reset`
- **Business Domain Endpoints:** `GET http://127.0.0.1:9000/api/v1/orders`

---

## Setup & Running Instructions

### 1. Install Dependencies

Open PowerShell and navigate to the service directory:

```powershell
Set-Location -Path "D:\Sentinal_AI\demo_services\customer_orders_api"
& "D:\Sentinal_AI\backend\.venv\Scripts\python.exe" -m pip install -r requirements.txt
```

### 2. Run Automated Tests

Run the test suite using pytest:

```powershell
Set-Location -Path "D:\Sentinal_AI\demo_services\customer_orders_api"
& "D:\Sentinal_AI\backend\.venv\Scripts\python.exe" -m pytest test_customer_orders_api.py -v
```

### 3. Start the Service

Start the application on `127.0.0.1:9000` (using single Uvicorn worker for in-memory failure state consistency):

```powershell
Set-Location -Path "D:\Sentinal_AI\demo_services\customer_orders_api"
& "D:\Sentinal_AI\backend\.venv\Scripts\python.exe" -m uvicorn main:app --host 127.0.0.1 --port 9000 --workers 1
```

---

## API Endpoints Reference

### 1. Root Information
- **`GET /`**
- Returns service identity, version, and endpoints overview.

### 2. Health Probing
- **`GET /health`** (and alias **`GET /api/v1/health`**)
- **When healthy:** HTTP 200 OK
  ```json
  {
    "status": "healthy",
    "service": "Customer Orders API",
    "operational_status": "operational",
    "failure_active": false,
    "timestamp": "2026-11-03T11:45:00Z"
  }
  ```
- **When failure is active:** HTTP 503 Service Unavailable
  ```json
  {
    "status": "unhealthy",
    "service": "Customer Orders API",
    "operational_status": "degraded",
    "failure_active": true,
    "failure_reason": "Database connection pool timeout under load",
    "error_count": 1,
    "timestamp": "2026-11-03T11:46:00Z"
  }
  ```

### 3. Failure Simulation Status
- **`GET /demo/status`**
- Inspects simulation state without mutating:
  ```json
  {
    "service": "Customer Orders API",
    "failure_active": true,
    "failure_reason": "Database connection pool timeout under load",
    "operational_status": "degraded",
    "error_count": 1,
    "failure_started_at": "2026-11-03T11:45:30Z"
  }
  ```

### 4. Inject Simulated Failure
- **`POST /demo/simulate-failure`**
- Activates deterministic failure mode. Accepts optional reason:
  ```json
  {
    "reason": "Simulated database connection pool exhaustion"
  }
  ```

### 5. Reset Failure State
- **`POST /admin/recovery/reset`**
- Resets in-memory failure flag and restores `/health` to HTTP 200.

### 6. Prometheus Metrics Scrape
- **`GET /metrics`**
- Exposes Prometheus text-format telemetry:
  - `http_requests_total`
  - `http_5xx_errors_total`
  - `http_request_duration_seconds`

### 7. Orders Domain Endpoints
- **`GET /api/v1/orders`** — List sample orders.
- **`GET /api/v1/orders/{order_id}`** — Retrieve order by ID.
