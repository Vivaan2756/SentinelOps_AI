"""Remediation Execution Worker Lifecycle Management (Phase 1 / P0.3).

Integrates the existing Option C DurableExecutionWorker with FastAPI lifespan:
- Automatically starts polling for eligible approved executions on application startup.
- Enforces single active polling loop per backend process.
- Non-blocking execution on dedicated background worker thread.
- Recovers transient exceptions without terminating the polling loop.
- Gracefully halts job-claiming and awaits in-flight execution completion on application shutdown.
- Preserves all Option C Stage 3.3 invariants (Ed25519 signing, RBAC, SSRF validation, verification).
"""

import asyncio
import logging
import os
import threading
from typing import Callable, Optional

from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.session import SessionLocal
from app.execution.runner import ExecutionRunnerInterface
from app.execution.worker import DurableExecutionWorker, get_worker_db_session_factory

logger = logging.getLogger("sentinelops.remediation.worker")


class RemediationWorker:
    """
    Lifespan-integrated manager for the Option C DurableExecutionWorker.
    Guarantees bounded polling, lifecycle safety, and clean shutdown.
    """

    def __init__(
        self,
        *,
        poll_interval: Optional[float] = None,
        enabled: Optional[bool] = None,
        shutdown_grace_period: Optional[float] = None,
        worker: Optional[DurableExecutionWorker] = None,
        db_factory: Optional[Callable[[], Session]] = None,
        runner: Optional[ExecutionRunnerInterface] = None,
    ):
        self.poll_interval = (
            poll_interval
            if poll_interval is not None
            else getattr(settings, "WORKER_POLL_INTERVAL_SECONDS", 2.0)
        )
        self.enabled = (
            enabled
            if enabled is not None
            else getattr(settings, "WORKER_ENABLED", True)
        )
        self.shutdown_grace_period = (
            shutdown_grace_period
            if shutdown_grace_period is not None
            else getattr(settings, "WORKER_SHUTDOWN_GRACE_PERIOD_SECONDS", 10.0)
        )
        self._worker: Optional[DurableExecutionWorker] = worker
        self._db_factory = db_factory
        self._runner = runner
        self._lock = asyncio.Lock()
        self._running = False

    @property
    def is_running(self) -> bool:
        """Return True if background worker thread is active and running."""
        return self._running and self._worker is not None and self._worker.is_running

    def get_worker(self) -> DurableExecutionWorker:
        """Resolve or lazily initialize the underlying DurableExecutionWorker instance."""
        if self._worker is not None:
            return self._worker

        # Mark process as running embedded worker so control-plane signing key is preserved
        os.environ["SENTINELOPS_EMBEDDED_WORKER"] = "true"

        # Resolve database session factory
        if self._db_factory is not None:
            resolved_db = self._db_factory
        else:
            if os.environ.get("WORKER_DATABASE_URL"):
                try:
                    resolved_db = get_worker_db_session_factory()
                except Exception as e:
                    logger.warning(
                        "Failed to initialize dedicated worker DB session factory (%s); falling back to SessionLocal.",
                        e,
                    )
                    resolved_db = SessionLocal
            else:
                resolved_db = SessionLocal

        self._worker = DurableExecutionWorker(
            poll_interval=self.poll_interval,
            shutdown_grace_period=self.shutdown_grace_period,
            db_factory=resolved_db,
            runner=self._runner,
        )
        return self._worker

    def set_worker(self, worker: Optional[DurableExecutionWorker]) -> None:
        """Explicitly inject a worker instance (primarily for testing with mocks/stubs)."""
        self._worker = worker

    def poll_and_execute(self, execution_id: Optional[str] = None) -> Optional[str]:
        """
        Synchronously poll and execute a single eligible job (or specified execution_id).
        Delegates directly to DurableExecutionWorker.run_once().
        """
        worker = self.get_worker()
        return worker.run_once(execution_id=execution_id)

    async def start(self) -> None:
        """Start the background execution worker polling loop in lifespan."""
        async with self._lock:
            if not self.enabled:
                logger.info("Autonomous remediation execution worker is disabled in configuration.")
                return

            if self.is_running:
                logger.warning("Remediation execution worker is already running; skipping duplicate start.")
                return

            worker = self.get_worker()
            # Start worker polling loop on background thread (non-blocking)
            worker.start()
            self._running = True
            logger.info(
                "Autonomous remediation execution worker started (worker_id=%s, poll_interval=%.1fs)",
                worker.worker_id,
                self.poll_interval,
            )

    async def stop(self, timeout: Optional[float] = None) -> bool:
        """Stop worker cleanly during application shutdown."""
        async with self._lock:
            if not self._running or self._worker is None:
                self._running = False
                return True

            self._running = False
            effective_timeout = timeout or self.shutdown_grace_period
            logger.info("Stopping remediation execution worker (timeout=%.1fs)...", effective_timeout)

            # Delegate stop to background thread to avoid blocking the asyncio event loop during thread.join()
            clean = await asyncio.to_thread(self._worker.stop, timeout=effective_timeout)
            logger.info("Remediation execution worker stopped (clean=%s).", clean)
            return clean


# Default singleton instance for application lifespan integration
remediation_worker = RemediationWorker()
