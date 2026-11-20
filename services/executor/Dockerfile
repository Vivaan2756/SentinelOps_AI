# SentinelOps AI Remediation Executor Image
# Multi-stage hardened minimal runtime container

FROM python:3.13-slim AS base

# Create dedicated non-root user and group (1000:1000)
RUN groupadd -g 1000 sentinelops && \
    useradd -u 1000 -g sentinelops -s /sbin/nologin -m sentinelops

WORKDIR /app

# Install minimal dependencies without caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy static runner module
COPY runner.py /app/executor/runner.py

# Ensure read-only file permissions
RUN chmod -R 555 /app

# Run strictly as unprivileged user
USER 1000:1000

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Pinned immutable entrypoint
ENTRYPOINT ["python", "-m", "executor.runner"]
CMD []
