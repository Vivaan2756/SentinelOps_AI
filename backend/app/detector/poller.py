"""Autonomous background detector poller for continuous health and telemetry evaluation."""

import asyncio
from typing import Set, Optional
from sqlalchemy.orm import Session
import httpx
from app.db.session import SessionLocal
from app.models.service import Service
from app.detector.runner import run_evaluation_for_service
from app.core.config import settings
from app.core.logging import get_logger

logger = get_logger("sentinelops.detector.poller")


class BackgroundDetectorPoller:
    """
    Autonomous background detector poller.
    - Continuously evaluates active registered services across all workspaces.
    - Enforces bounded concurrency via asyncio.Semaphore.
    - Prevents overlapping evaluations for the same service via in-flight tracking.
    - Isolates individual service failures to prevent crashes in the polling loop.
    - Respects configurable polling intervals and concurrency limits.
    - Integrates with FastAPI lifespan for clean startup and cancellation/shutdown.
    """

    def __init__(
        self,
        poll_interval: Optional[float] = None,
        max_concurrency: Optional[int] = None,
        enabled: Optional[bool] = None,
    ):
        self.poll_interval = (
            poll_interval
            if poll_interval is not None
            else settings.DETECTOR_POLL_INTERVAL_SECONDS
        )
        self.max_concurrency = (
            max_concurrency
            if max_concurrency is not None
            else settings.DETECTOR_MAX_CONCURRENCY
        )
        self.enabled = (
            enabled if enabled is not None else settings.DETECTOR_POLLER_ENABLED
        )

        self._running = False
        self._task: Optional[asyncio.Task] = None
        self._semaphore = asyncio.Semaphore(self.max_concurrency)
        self._evaluating_services: Set[str] = set()
        self._lock = asyncio.Lock()
        self._client: Optional[httpx.AsyncClient] = None

    @property
    def is_running(self) -> bool:
        """Returns True if the background polling loop is actively running."""
        return self._running and self._task is not None and not self._task.done()

    async def start(self) -> None:
        """Start the background polling loop task."""
        if not self.enabled:
            logger.info("Autonomous background detector poller is disabled in configuration.")
            return

        if self.is_running:
            logger.warning("Background detector poller is already running.")
            return

        self._running = True
        self._client = httpx.AsyncClient(timeout=settings.DETECTOR_TIMEOUT_SECONDS)
        self._task = asyncio.create_task(self._poll_loop(), name="sentinelops-detector-poller")
        logger.info(
            "Autonomous detector poller started (interval=%.1fs, max_concurrency=%d)",
            self.poll_interval,
            self.max_concurrency,
        )

    async def stop(self) -> None:
        """Cancel and await background poller task and cleanup resources."""
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            except Exception as e:
                logger.error("Error awaiting background poller cancellation: %s", e)
            self._task = None

        if self._client:
            await self._client.aclose()
            self._client = None

        logger.info("Autonomous detector poller stopped successfully.")

    async def poll_once(self) -> int:
        """
        Execute a single poll cycle across all active registered services.
        Loads only active services from database and executes bounded concurrent evaluations.
        Returns the number of services successfully evaluated.
        """
        # Load only active services from database
        db: Session = SessionLocal()
        try:
            active_services = (
                db.query(Service.id, Service.name, Service.workspace_id)
                .filter(Service.is_active == True)
                .all()
            )
        except Exception as e:
            logger.error("Failed to query active services for background polling: %s", e)
            return 0
        finally:
            db.close()

        if not active_services:
            logger.debug("No active services registered for background polling.")
            return 0

        # Launch bounded concurrent evaluations
        tasks = [
            self._evaluate_service_guarded(s_id, s_name, ws_id)
            for s_id, s_name, ws_id in active_services
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)
        evaluated_count = sum(1 for r in results if r is True)
        return evaluated_count

    async def _evaluate_service_guarded(
        self, service_id: str, service_name: str, workspace_id: str
    ) -> bool:
        """
        Evaluates a single service with bounded concurrency and overlap prevention.
        Returns True if evaluation executed, False if skipped due to overlap or failure.
        """
        async with self._lock:
            if service_id in self._evaluating_services:
                logger.info(
                    "Skipping background poll for service '%s' (%s): evaluation already in progress.",
                    service_name,
                    service_id,
                )
                return False
            self._evaluating_services.add(service_id)

        try:
            async with self._semaphore:
                # Open isolated DB session for this service evaluation
                db: Session = SessionLocal()
                try:
                    res = await run_evaluation_for_service(
                        service_id=service_id,
                        db=db,
                        client=self._client,
                        timeout_seconds=settings.DETECTOR_TIMEOUT_SECONDS,
                    )
                    logger.debug(
                        "Background poll completed for service '%s' (%s): is_healthy=%s, action=%s",
                        service_name,
                        service_id,
                        res.is_healthy,
                        res.lifecycle_action,
                    )
                    return True
                except Exception as exc:
                    logger.error(
                        "Error evaluating service '%s' (%s) in workspace '%s': %s",
                        service_name,
                        service_id,
                        workspace_id,
                        exc,
                        exc_info=False,
                    )
                    return False
                finally:
                    db.close()
        finally:
            async with self._lock:
                self._evaluating_services.discard(service_id)

    async def _poll_loop(self) -> None:
        """Main continuous polling loop respecting poll_interval."""
        while self._running:
            try:
                await self.poll_once()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(
                    "Unexpected error in background detector polling loop: %s",
                    e,
                    exc_info=True,
                )

            try:
                await asyncio.sleep(self.poll_interval)
            except asyncio.CancelledError:
                break


# Global singleton poller instance
detector_poller = BackgroundDetectorPoller()
