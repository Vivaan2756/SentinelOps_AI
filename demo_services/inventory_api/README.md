# Inventory Management API

A minimal, independently runnable Python FastAPI microservice designed for SentinelOps multi-service integration testing.

---

## Service Overview

- **Service Name**: Inventory Management API
- **Framework**: Python 3.11+ / FastAPI
- **Default Host / Port**: `127.0.0.1:7000`
- **Telemetry Format**: Prometheus exposition text format
- **Isolation**: 100% independent of SentinelOps backend codebase, models, database, and remediation engines. No recovery, restart, or remediation endpoints are implemented.

---

## API Endpoints

| Method | Path | Description | Sample Output |
| :--- | :--- | :--- | :--- |
| `GET` | `/` | Service identification & status | `{"service": "Inventory Management API", "version": "1.0.0", "status": "running"}` |
| `GET` | `/api/v1/health` | Authoritative health check | `{"status": "healthy", "service": "Inventory Management API"}` |
| `GET` | `/health` | Compatibility health alias | `{"status": "healthy", "service": "Inventory Management API"}` |
| `GET` | `/metrics` | Prometheus telemetry | Exposes `http_requests_total`, `http_5xx_errors_total`, `http_request_duration_seconds` |
| `GET` | `/api/v1/items` | List sample inventory items | JSON array of inventory items |
| `GET` | `/api/v1/items/{id}` | Get inventory item by ID | JSON item object or HTTP 404 |

---

## Quickstart & Run Instructions (PowerShell)

### Option A: Using Dedicated Virtual Environment

```powershell
# 1. Navigate to the service directory
Set-Location -Path "D:\Sentinal_AI\demo_services\inventory_api"

# 2. Create a Python virtual environment (if not already created)
python -m venv .venv

# 3. Activate the virtual environment
.\.venv\Scripts\Activate.ps1

# 4. Install dependencies
pip install -r requirements.txt

# 5. Start the service on 127.0.0.1:7000
uvicorn main:app --host 127.0.0.1 --port 7000
```

### Option B: Using Existing SentinelOps Python Environment

```powershell
# 1. Navigate to the service directory
Set-Location -Path "D:\Sentinal_AI\demo_services\inventory_api"

# 2. Start the service using the project virtual environment
& "D:\Sentinal_AI\backend\.venv\Scripts\python.exe" -m uvicorn main:app --host 127.0.0.1 --port 7000
```

Or run directly:
```powershell
& "D:\Sentinal_AI\backend\.venv\Scripts\python.exe" main.py
```

---

## Testing & Verification Commands

### 1. Root Service Identification
```powershell
Invoke-RestMethod -Uri "http://127.0.0.1:7000/" | ConvertTo-Json
```
**Expected Response:**
```json
{
  "service": "Inventory Management API",
  "version": "1.0.0",
  "status": "running",
  "description": "Independent Inventory Management API for SentinelOps integration testing"
}
```

### 2. Health Endpoint
```powershell
Invoke-RestMethod -Uri "http://127.0.0.1:7000/api/v1/health" | ConvertTo-Json
```
**Expected Response:**
```json
{
  "status": "healthy",
  "service": "Inventory Management API"
}
```

### 3. Prometheus Metrics Endpoint
```powershell
(Invoke-WebRequest -Uri "http://127.0.0.1:7000/metrics").Content
```
**Expected Output Preview:**
```text
# HELP http_requests_total Total count of HTTP requests processed by Inventory Management API
# TYPE http_requests_total counter
http_requests_total{endpoint="/api/v1/health",method="GET",status_code="200"} 1.0

# HELP http_5xx_errors_total Total count of HTTP 5xx server errors emitted by Inventory Management API
# TYPE http_5xx_errors_total counter
http_5xx_errors_total{endpoint="/api/v1/health",method="GET"} 0.0

# HELP http_request_duration_seconds HTTP request latency in seconds for Inventory Management API endpoints
# TYPE http_request_duration_seconds histogram
http_request_duration_seconds_bucket{endpoint="/api/v1/health",le="0.005",method="GET"} 1.0
...
```

### 4. Sample Inventory Item Queries
```powershell
# List inventory items
Invoke-RestMethod -Uri "http://127.0.0.1:7000/api/v1/items" | ConvertTo-Json

# Query item inv_001
Invoke-RestMethod -Uri "http://127.0.0.1:7000/api/v1/items/inv_001" | ConvertTo-Json
```

---

## Automated Unit Testing

Run unit tests directly with `pytest`:
```powershell
Set-Location -Path "D:\Sentinal_AI\demo_services\inventory_api"
& "D:\Sentinal_AI\backend\.venv\Scripts\pytest.exe" test_inventory_api.py -v
```
