"""Standalone CLI Daemon Entry Point for SentinelOps AI Execution Watchdog (Milestone D).

Usage:
    python -m app.execution.watchdog_daemon [--poll-interval SECONDS] [--batch-size BATCH] [--workspace-id ID]

Environment Variables:
    WATCHDOG_POLL_INTERVAL: float, default 5.0
    WATCHDOG_BATCH_SIZE: int, default 50
    WATCHDOG_HEARTBEAT_TIMEOUT: float, default 60.0
    WATCHDOG_SHUTDOWN_GRACE: float, default 30.0
    WATCHDOG_RESUME_VERIFICATION: bool, default False
    WATCHDOG_WORKSPACE_ID: optional str
"""

import argparse
import logging
import os
import signal
import sys
import time

from app.core.config import settings
from app.core.logging import get_logger
from app.db.session import SessionLocal
from app.execution.watchdog import ExecutionWatchdog

logger = get_logger("watchdog_daemon")


def parse_args():
    parser = argparse.ArgumentParser(
        description="SentinelOps AI Execution Watchdog & Recovery Daemon"
    )
    parser.add_argument(
        "--poll-interval",
        type=float,
        default=float(os.getenv("WATCHDOG_POLL_INTERVAL", "5.0")),
        help="Polling interval in seconds between sweeps (default: 5.0s)",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=int(os.getenv("WATCHDOG_BATCH_SIZE", "50")),
        help="Maximum candidate executions to reconcile per sweep (default: 50)",
    )
    parser.add_argument(
        "--heartbeat-timeout",
        type=float,
        default=float(os.getenv("WATCHDOG_HEARTBEAT_TIMEOUT", "60.0")),
        help="Threshold in seconds of lost worker heartbeat to declare worker dead (default: 60.0s)",
    )
    parser.add_argument(
        "--shutdown-grace",
        type=float,
        default=float(os.getenv("WATCHDOG_SHUTDOWN_GRACE", "30.0")),
        help="Seconds to wait during graceful shutdown (default: 30.0s)",
    )
    parser.add_argument(
        "--resume-verification",
        action="store_true",
        default=os.getenv("WATCHDOG_RESUME_VERIFICATION", "false").lower() in ("true", "1", "yes"),
        help="Enable read-only verification resumption for unexpired cycles (default: False)",
    )
    parser.add_argument(
        "--workspace-id",
        type=str,
        default=os.getenv("WATCHDOG_WORKSPACE_ID", None),
        help="Scope watchdog to a specific tenant workspace ID (default: all)",
    )
    return parser.parse_args()


def main():
    args = parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
    )

    logger.info(
        "Initializing SentinelOps AI Watchdog Daemon "
        "(poll_interval=%.1fs, batch_size=%d, heartbeat_timeout=%.1fs, resume_verification=%s, workspace=%s)",
        args.poll_interval,
        args.batch_size,
        args.heartbeat_timeout,
        args.resume_verification,
        args.workspace_id or "ALL",
    )

    watchdog = ExecutionWatchdog(
        db_factory=SessionLocal,
        poll_interval=args.poll_interval,
        batch_size=args.batch_size,
        heartbeat_timeout_seconds=args.heartbeat_timeout,
        shutdown_grace_period=args.shutdown_grace,
        resume_verification=args.resume_verification,
        workspace_id=args.workspace_id,
    )

    def handle_signal(sig, frame):
        sig_name = signal.Signals(sig).name if hasattr(signal, "Signals") else str(sig)
        logger.info("Signal %s received. Initiating graceful watchdog shutdown...", sig_name)
        watchdog.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    try:
        watchdog.run_forever()
    except Exception as e:
        logger.error("Fatal error in watchdog daemon: %s", str(e), exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
