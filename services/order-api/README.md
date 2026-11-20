# Order API Demo Microservice (Render & Local Deployment)

Sample workload designed for SentinelOps AI incident detection, monitoring, and autonomous remediation demonstration.

---

## 1. Verified Endpoints & Specification

| Method | Endpoint | Auth Required | Description | Response Codes |
| :--- | :--- | :--- | :--- | :--- |
| `GET` | `/health` | **No** (Public) | Health check probe. Returns 200 when healthy, 500 when failure mode is active. | `200 OK`, `500 Internal Server Error` |
| `GET` | `/metrics` | **No** (Public) | Prometheus metrics exposition format. | `200 OK` |
| `GET` | `/orders` | **No** | List orders. Fails with 500 when failure mode is active. | `200 OK`, `500 Internal Server Error` |
| `POST` | `/orders` | **No** | Create order. Fails with 500 when failure mode is active. | `201 Created`, `500 Internal Server Error` |
| `GET` | `/demo/status` | **No** | Inspect current failure simulation status and error counter. | `200 OK` |
| `POST` | `/demo/simulate-failure` | **Yes** (when token set) | Injects deterministic in-memory failure (HTTP 500 database pool timeout). | `200 OK`, `401 Unauthorized` |
| `POST` | `/demo/restore` | **Yes** (when token set) | Restores normal healthy operation. Gracefully idempotent on repeated calls. | `200 OK`, `401 Unauthorized` |
| `POST` | `/demo/restore/{token}` | **Yes** (when token set) | Path-authenticated alias for `/demo/restore`. | `200 OK`, `401 Unauthorized` |

---

## 2. Environment Variables

| Variable | Default (Local) | Render Recommended | Description |
| :--- | :--- | :--- | :--- |
| `DEMO_ADMIN_TOKEN` | *None* | `generateValue: true` or strong secret | Secret token required to invoke `/demo/simulate-failure` and `/demo/restore`. If unset, auth is disabled for local dev. |
| `ORDER_API_SECRET_TOKEN` | *None* | *None* | Alias for `DEMO_ADMIN_TOKEN`. |
| `PORT` | `8001` | Dynamic (`$PORT`) | HTTP listening port provided automatically by Render. |
| `HOST` | `0.0.0.0` | `0.0.0.0` | Host bind address. |
| `PYTHON_VERSION` | `3.13` | `3.13.0` | Python runtime version. |

---

## 3. Deployment Options on Render

### Option A: Render Blueprint (Recommended)
1. In the Render Dashboard, click **New +** -> **Blueprint**.
2. Connect your Git repository (`Sentinal_AI`).
3. Render automatically detects the root `render.yaml`.
4. Render creates the `sentinelops-order-api-demo` Web Service, assigns a random `DEMO_ADMIN_TOKEN`, and deploys.

### Option B: Manual Web Service Configuration
1. In Render Dashboard, click **New +** -> **Web Service**.
2. Settings:
   - **Name:** `sentinelops-order-api-demo`
   - **Root Directory:** `services/order-api`
   - **Runtime:** `Python 3`
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:** `uvicorn service.main:app --host 0.0.0.0 --port $PORT`
   - **Health Check Path:** `/health`
3. Environment Variables:
   - `DEMO_ADMIN_TOKEN`: `<your-secure-random-token>`
   - `PYTHON_VERSION`: `3.13.0`

---

## 4. Testing & Verification via Real HTTP Requests

Replace `https://sentinelops-order-api-demo.onrender.com` with your Render service URL and `<TOKEN>` with your configured `DEMO_ADMIN_TOKEN`.

### 4.1 Verify Initial Healthy State
```bash
curl -i https://sentinelops-order-api-demo.onrender.com/health
```
**Expected Response:** `HTTP/1.1 200 OK`
```json
{
  "status": "healthy",
  "service": "order-api",
  "version": "1.0.0",
  "timestamp": "2026-11-13T20:00:00.000000+00:00"
}
```

### 4.2 Verify Administrative Authentication Protection
```bash
# Attempt failure injection without token (rejected)
curl -i -X POST https://sentinelops-order-api-demo.onrender.com/demo/simulate-failure
```
**Expected Response:** `HTTP/1.1 401 Unauthorized`

### 4.3 Inject Simulated Failure (Authenticated)
```bash
# Using X-Demo-Token header
curl -i -X POST https://sentinelops-order-api-demo.onrender.com/demo/simulate-failure \
  -H "X-Demo-Token: <TOKEN>" \
  -d '{"reason": "Simulated database connection pool exhaustion"}' \
  -H "Content-Type: application/json"
```
**Expected Response:** `HTTP/1.1 200 OK`
```json
{
  "status": "failure_injected",
  "failure_active": true,
  "failure_reason": "Simulated database connection pool exhaustion",
  "message": "Order API is now failing with HTTP 500 database timeouts."
}
```

### 4.4 Verify Failure Detected on Public Health Endpoint
```bash
curl -i https://sentinelops-order-api-demo.onrender.com/health
```
**Expected Response:** `HTTP/1.1 500 Internal Server Error`
```json
{
  "status": "unhealthy",
  "service": "order-api",
  "error": "Simulated database connection pool exhaustion",
  "timestamp": "..."
}
```

### 4.5 Execute Recovery Action (Authenticated)
```bash
# Using Authorization Bearer token header
curl -i -X POST https://sentinelops-order-api-demo.onrender.com/demo/restore \
  -H "Authorization: Bearer <TOKEN>"
```
**Expected Response:** `HTTP/1.1 200 OK`
```json
{
  "status": "restored",
  "failure_active": false,
  "message": "Order API has been restored to normal healthy operation."
}
```

### 4.6 Verify Independent Health Recovery
```bash
curl -i https://sentinelops-order-api-demo.onrender.com/health
```
**Expected Response:** `HTTP/1.1 200 OK`

### 4.7 Verify Repeated Recovery Is Gracefully Idempotent
```bash
# Second recovery call when already healthy
curl -i -X POST https://sentinelops-order-api-demo.onrender.com/demo/restore \
  -H "X-Demo-Token: <TOKEN>"
```
**Expected Response:** `HTTP/1.1 200 OK`
```json
{
  "status": "already_healthy",
  "failure_active": false,
  "message": "Order API is already operating normally. No action needed."
}
```
