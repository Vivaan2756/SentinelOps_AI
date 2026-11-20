"""Broker Daemon Entrypoint (DEPRECATED - Stage 3B Legacy Broker Retirement).

Retained for historical testing reference only. Under Option C, execution is
performed directly by the unprivileged IsolatedHttpRecoveryRunner. The standalone
broker daemon and Docker socket access are retired.
Can be executed as:
    python -m app.execution.broker_daemon
"""

import logging
import os
import signal
import sys
import time

from app.execution.broker_server import BrokerServer
from app.execution.exceptions import BrokerSecurityViolation
from app.execution.manifest_journal import BrokerManifestJournal
from app.execution.public_keys import BrokerPublicKeyRegistry

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("sentinelops.broker_daemon")


def main() -> None:
    # Zero private-key material assertion: broker daemon must fail closed if private key is present
    if os.environ.get("SENTINELOPS_MANIFEST_PRIVATE_KEY"):
        logger.critical(
            "FATAL SECURITY VIOLATION: SENTINELOPS_MANIFEST_PRIVATE_KEY detected in broker environment! "
            "The broker must NEVER possess or access private signing key material. Aborting startup."
        )
        raise BrokerSecurityViolation(
            "SENTINELOPS_MANIFEST_PRIVATE_KEY detected in broker environment. Refusing to start."
        )

    socket_path = os.environ.get("SENTINELOPS_BROKER_SOCKET", "/var/run/sentinelops/broker.sock")
    logger.info(f"Starting SentinelOps RestrictedDockerBroker daemon on socket: {socket_path}")

    auth_uids_env = os.environ.get("SENTINELOPS_AUTHORIZED_UIDS", "1000")
    authorized_uids = {int(uid.strip()) for uid in auth_uids_env.split(",") if uid.strip()}

    socket_gid = int(os.environ.get("SENTINELOPS_SOCKET_GID", "1000"))

    # Initialize persistent replay journal and public-key registry
    journal = BrokerManifestJournal()
    public_key_registry = BrokerPublicKeyRegistry()
    logger.info(
        f"Broker initialized with {len(public_key_registry)} configured public verification keys: "
        f"{sorted(public_key_registry.all_key_ids())}"
    )

    server = BrokerServer(
        socket_path=socket_path,
        authorized_uids=authorized_uids,
        socket_gid=socket_gid,
        journal=journal,
        public_key_registry=public_key_registry,
    )

    # Signal handlers for graceful termination
    def handle_signal(sig, frame):
        logger.info(f"Received signal {sig}. Stopping broker daemon...")
        server.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    try:
        server.start()
        logger.info("RestrictedDockerBroker daemon running. Awaiting connections...")
        while True:
            try:
                server.serve_once()
            except Exception as e:
                logger.error(f"Error handling connection: {e}")
    except KeyboardInterrupt:
        logger.info("Keyboard interrupt received.")
    finally:
        server.stop()
        logger.info("Broker daemon stopped.")


if __name__ == "__main__":
    main()
