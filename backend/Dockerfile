# SentinelOps AI - Backend Control Plane (FastAPI)
# Multi-stage hardened minimal runtime container without Docker SDK access

FROM python:3.13-slim AS base

# Create dedicated unprivileged user (1000:1000)
RUN groupadd -g 1000 sentinelops && \
    useradd -u 1000 -g sentinelops -s /sbin/nologin -m sentinelops

WORKDIR /app

# Install application dependencies without Docker daemon client
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source code
COPY backend/app /app/app
COPY backend/alembic /app/alembic
COPY backend/alembic.ini /app/alembic.ini

# Create persistent data directories for OperationRegistry (SQLite) and OperationJournal (SOJ1)
RUN mkdir -p /var/lib/sentinelops/registry /var/lib/sentinelops/journal && \
    chown -R sentinelops:sentinelops /var/lib/sentinelops /app && \
    chmod 0750 /var/lib/sentinelops /var/lib/sentinelops/registry /var/lib/sentinelops/journal

USER 1000:1000

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app \
    SENTINELOPS_BROKER_SOCKET=/var/run/sentinelops/broker.sock

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
