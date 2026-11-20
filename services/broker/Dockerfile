# ==============================================================================
# DEPRECATED - SentinelOps Stage 3B Legacy Broker Retirement
# ==============================================================================
# This Dockerfile is retained for historical/unit test reference only.
# Under Option C, SentinelOps execution topology permanently retires the standalone
# Docker broker daemon and its /var/run/docker.sock privileged mount.
# The active execution topology uses direct unprivileged HTTP recovery
# (IsolatedHttpRecoveryRunner) inside the worker container without Docker socket access.
# ==============================================================================
# Standalone Restricted Docker Broker Daemon (Historical Reference)

FROM python:3.13-slim AS base

# Create dedicated group sentinelops (GID 1000) for shared IPC socket permissions
RUN groupadd -g 1000 sentinelops

WORKDIR /app

# Install minimal backend dependencies + docker SDK for container broker daemon
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir docker>=7.1.0

# Copy application source code
COPY backend/app /app/app

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app \
    SENTINELOPS_BROKER_SOCKET=/var/run/sentinelops/broker.sock

# Entrypoint runs the standalone broker daemon
ENTRYPOINT ["python", "-m", "app.execution.broker_daemon"]
