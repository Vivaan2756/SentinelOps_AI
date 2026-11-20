"""Standalone Restricted Docker Broker Server (DEPRECATED - Stage 3B Legacy Broker Retirement).

Retained for unit test compatibility. Under Option C, execution is performed
directly by the unprivileged IsolatedHttpRecoveryRunner. The standalone broker
daemon and Docker socket access are permanently retired from deployment topology.
"""

import json
import logging
import os
import socket
import struct
import sys
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from pydantic import ValidationError

from app.execution.broker import (
    BrokerExecuteRequest,
    BrokerExecuteResponse,
    RestrictedDockerBroker,
)
from app.execution.exceptions import (
    BrokerSecurityViolation,
    BrokerUnavailableError,
    ExecutionEnvironmentUnavailable,
)
from app.execution.manifest_journal import BrokerManifestJournal
from app.execution.public_keys import BrokerPublicKeyRegistry

logger = logging.getLogger("sentinelops.broker_server")


def _reject_duplicate_keys(pairs: List[Tuple[str, Any]]) -> Dict[str, Any]:
    """Reject duplicate JSON keys during parsing."""
    res: Dict[str, Any] = {}
    for k, v in pairs:
        if k in res:
            raise ValueError(f"Duplicate key '{k}' detected in JSON payload.")
        res[k] = v
    return res

# Default socket path for the broker daemon
DEFAULT_SOCKET_PATH = os.environ.get(
    "SENTINELOPS_BROKER_SOCKET",
    "/var/run/sentinelops/broker.sock",
)

# Maximum allowed size for a single incoming IPC request payload (64 KB)
MAX_REQUEST_BYTES = 64 * 1024

# 4-byte network unsigned int header
HEADER_STRUCT = "!I"
HEADER_SIZE = struct.calcsize(HEADER_STRUCT)


def _recv_exact(sock: socket.socket, num_bytes: int) -> bytes:
    """Read exactly num_bytes from socket or raise ConnectionError."""
    chunks = []
    received = 0
    while received < num_bytes:
        chunk = sock.recv(min(num_bytes - received, 4096))
        if not chunk:
            raise ConnectionError(f"Connection closed prematurely. Received {received}/{num_bytes} bytes.")
        chunks.append(chunk)
        received += len(chunk)
    return b"".join(chunks)


class BrokerServer:
    """
    Standalone Unix Domain Socket Server for Restricted Docker Broker.
    Runs in an isolated process/container with exclusive Docker socket access.
    """

    def __init__(
        self,
        socket_path: Optional[str] = None,
        broker: Optional[RestrictedDockerBroker] = None,
        authorized_uids: Optional[Set[int]] = None,
        max_request_bytes: int = MAX_REQUEST_BYTES,
        client_timeout: float = 30.0,
        custom_peer_verifier: Optional[Callable[[socket.socket], Tuple[bool, str, Dict[str, int]]]] = None,
        socket_gid: Optional[int] = None,
        journal: Optional[BrokerManifestJournal] = None,
        public_key_registry: Optional[BrokerPublicKeyRegistry] = None,
    ):
        self.socket_path = socket_path or DEFAULT_SOCKET_PATH
        if broker is not None:
            self.broker = broker
        else:
            self.broker = RestrictedDockerBroker(
                journal=journal,
                public_key_registry=public_key_registry,
            )
        if authorized_uids is not None:
            self.authorized_uids = authorized_uids
        else:
            auth_env = os.environ.get("SENTINELOPS_AUTHORIZED_UIDS")
            if auth_env is not None:
                self.authorized_uids = {int(u.strip()) for u in auth_env.split(",") if u.strip()}
            else:
                self.authorized_uids = {1000}
        self.max_request_bytes = max_request_bytes
        self.client_timeout = client_timeout
        self.custom_peer_verifier = custom_peer_verifier
        if socket_gid is not None:
            self.socket_gid = socket_gid
        else:
            gid_env = os.environ.get("SENTINELOPS_SOCKET_GID")
            self.socket_gid = int(gid_env.strip()) if gid_env is not None and gid_env.strip() else 1000
        self._server_socket: Optional[socket.socket] = None
        self._is_running = False

    def verify_peer_credentials(self, conn: socket.socket) -> Tuple[bool, str, Dict[str, int]]:
        """
        Verify calling process identity using SO_PEERCRED on Linux.
        Rejects unauthorized UIDs to prevent privilege escalation.
        """
        if self.custom_peer_verifier is not None:
            return self.custom_peer_verifier(conn)

        # Linux SO_PEERCRED support
        if hasattr(socket, "SO_PEERCRED"):
            try:
                creds = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
                pid, uid, gid = struct.unpack("3i", creds)
                peer_info = {"pid": pid, "uid": uid, "gid": gid}

                if self.authorized_uids is not None and uid not in self.authorized_uids:
                    return False, f"Unauthorized peer UID {uid} (authorized: {sorted(self.authorized_uids)})", peer_info
                return True, "Authorized", peer_info
            except Exception as e:
                return False, f"Failed to retrieve peer credentials: {str(e)}", {}

        # Non-Linux host (Windows development native test mode)
        # Note: In production, the broker runs inside a Linux container where SO_PEERCRED is enforced.
        return True, "SO_PEERCRED not supported on host OS (Linux container boundary required for production)", {}

    def start(self) -> None:
        """
        Bind and start listening on the restricted Unix domain socket.
        Enforces directory ownership, permissions, and stale socket cleanup.
        """
        if self._is_running:
            return

        if not hasattr(socket, "AF_UNIX"):
            raise BrokerSecurityViolation(
                "Unix domain sockets (AF_UNIX) are not supported on this native Windows runtime. "
                "The broker service must run inside the Linux container boundary or WSL2."
            )

        # 1. Reject symlinked socket path to prevent hijacking
        if os.path.islink(self.socket_path):
            raise BrokerSecurityViolation(
                f"Socket path '{self.socket_path}' is a symbolic link. Potential hijack attempt rejected."
            )

        # 2. Ensure parent directory exists with restricted permissions (0750) and GID 1000
        parent_dir = os.path.dirname(os.path.abspath(self.socket_path))
        if parent_dir:
            if not os.path.exists(parent_dir):
                try:
                    os.makedirs(parent_dir, mode=0o750, exist_ok=True)
                except OSError as e:
                    logger.warning(f"Could not set mode 0750 on '{parent_dir}': {e}")
            else:
                try:
                    os.chmod(parent_dir, 0o750)
                except OSError as e:
                    logger.warning(f"Could not enforce mode 0750 on '{parent_dir}': {e}")

            if self.socket_gid is not None and hasattr(os, "chown"):
                try:
                    os.chown(parent_dir, -1, self.socket_gid)
                except OSError as e:
                    logger.warning(f"Could not set group {self.socket_gid} on directory '{parent_dir}': {e}")

        # 3. Detect and handle stale socket safely
        if os.path.exists(self.socket_path):
            if os.path.islink(self.socket_path):
                raise BrokerSecurityViolation("Socket path is a symlink.")

            # Test connecting to check if an active broker is already running
            test_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)

            try:
                test_sock.connect(self.socket_path)
                test_sock.close()
                raise BrokerSecurityViolation(
                    f"Another active broker is already listening on '{self.socket_path}'."
                )
            except (ConnectionRefusedError, FileNotFoundError):
                # Stale socket from dead process: safe to unlink
                try:
                    os.unlink(self.socket_path)
                    logger.info(f"Cleaned up stale socket file: {self.socket_path}")
                except OSError as e:
                    raise BrokerSecurityViolation(f"Failed to remove stale socket: {e}")
            finally:
                test_sock.close()

        # 4. Create and bind Unix domain socket
        self._server_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._server_socket.bind(self.socket_path)

        # 5. Set restrictive file permissions on socket file (0660) and GID 1000
        try:
            os.chmod(self.socket_path, 0o660)
        except OSError as e:
            logger.warning(f"Could not set mode 0660 on socket file: {e}")

        if self.socket_gid is not None and hasattr(os, "chown"):
            try:
                os.chown(self.socket_path, -1, self.socket_gid)
            except OSError as e:
                logger.warning(f"Could not set group {self.socket_gid} on socket file: {e}")

        self._server_socket.listen(10)
        self._is_running = True
        logger.info(f"RestrictedDockerBroker listening on Unix socket: {self.socket_path}")

        # Clean up any orphaned containers from previous unexpected crashes
        try:
            self.broker.cleanup_orphaned_containers()
        except Exception as e:
            logger.warning(f"Initial orphan container cleanup warning: {e}")

        # Reconcile in-flight claims from previous broker crash
        if getattr(self.broker, "journal", None) is not None:
            try:
                reconciled = self.broker.journal.reconcile_unresolved_claims()
                if reconciled:
                    logger.warning(
                        f"Reconciled {len(reconciled)} unresolved claims from previous crash to OUTCOME_UNKNOWN."
                    )
            except Exception as e:
                logger.error(f"Failed to reconcile journal on broker startup: {e}")
                raise

    def handle_connection(self, conn: socket.socket) -> None:
        """Process a single client connection with length-prefixed framing and timeouts."""
        conn.settimeout(self.client_timeout)
        try:
            # 1. Peer credential verification
            is_auth, auth_msg, peer_info = self.verify_peer_credentials(conn)
            if not is_auth:
                logger.warning(f"Rejecting unauthorized connection: {auth_msg}")
                err_payload = json.dumps({
                    "error": "Unauthorized peer process",
                    "detail": auth_msg,
                }).encode("utf-8")
                header = struct.pack(HEADER_STRUCT, len(err_payload))
                conn.sendall(header + err_payload)
                return

            # 2. Read length prefix
            header = _recv_exact(conn, HEADER_SIZE)
            payload_len = struct.unpack(HEADER_STRUCT, header)[0]

            # 3. Request size limit check (max 64 KB)
            if payload_len <= 0 or payload_len > self.max_request_bytes:
                logger.warning(f"Request payload size {payload_len} exceeds max limit {self.max_request_bytes}")
                err_payload = json.dumps({
                    "error": "Request size limit exceeded",
                    "detail": f"Payload size {payload_len} exceeds maximum allowed of {self.max_request_bytes} bytes.",
                }).encode("utf-8")
                header = struct.pack(HEADER_STRUCT, len(err_payload))
                conn.sendall(header + err_payload)
                return

            # 4. Read full request payload
            raw_payload = _recv_exact(conn, payload_len)
            try:
                decoded_str = raw_payload.decode("utf-8")
            except UnicodeDecodeError as e:
                logger.warning(f"Invalid UTF-8 payload rejected: {e}")
                err_payload = json.dumps({
                    "error": "BrokerSecurityViolation",
                    "detail": f"Payload must be valid UTF-8: {e}",
                }).encode("utf-8")
                conn.sendall(struct.pack(HEADER_STRUCT, len(err_payload)) + err_payload)
                return

            try:
                request_dict = json.loads(decoded_str, object_pairs_hook=_reject_duplicate_keys)
            except (json.JSONDecodeError, ValueError) as e:
                logger.warning(f"Malformed JSON or duplicate keys rejected: {e}")
                err_payload = json.dumps({
                    "error": "BrokerSecurityViolation",
                    "detail": f"Malformed JSON or duplicate keys detected: {e}",
                }).encode("utf-8")
                conn.sendall(struct.pack(HEADER_STRUCT, len(err_payload)) + err_payload)
                return

            try:
                request = BrokerExecuteRequest.model_validate(request_dict)
            except ValidationError as e:
                logger.warning(f"BrokerExecuteRequest schema validation failed: {e}")
                err_payload = json.dumps({
                    "error": "BrokerSecurityViolation",
                    "detail": f"Request schema validation failed: {e}",
                }).encode("utf-8")
                conn.sendall(struct.pack(HEADER_STRUCT, len(err_payload)) + err_payload)
                return

            # 5. Dispatch action to core broker engine
            response = self.broker.execute_action(request)
            resp_dict = response.model_dump()

            # 6. Send framed response back to client
            resp_bytes = json.dumps(resp_dict).encode("utf-8")
            resp_header = struct.pack(HEADER_STRUCT, len(resp_bytes))
            conn.sendall(resp_header + resp_bytes)

        except BrokerSecurityViolation as e:
            err_payload = json.dumps({"error": "BrokerSecurityViolation", "detail": str(e)}).encode("utf-8")
            try:
                conn.sendall(struct.pack(HEADER_STRUCT, len(err_payload)) + err_payload)
            except Exception:
                pass
        except ExecutionEnvironmentUnavailable as e:
            err_payload = json.dumps({"error": "ExecutionEnvironmentUnavailable", "detail": str(e)}).encode("utf-8")
            try:
                conn.sendall(struct.pack(HEADER_STRUCT, len(err_payload)) + err_payload)
            except Exception:
                pass
        except BrokerUnavailableError as e:
            err_payload = json.dumps({"error": "BrokerUnavailableError", "detail": str(e)}).encode("utf-8")
            try:
                conn.sendall(struct.pack(HEADER_STRUCT, len(err_payload)) + err_payload)
            except Exception:
                pass
        except Exception as e:
            err_payload = json.dumps({"error": "BrokerExecutionError", "detail": str(e)}).encode("utf-8")
            try:
                conn.sendall(struct.pack(HEADER_STRUCT, len(err_payload)) + err_payload)
            except Exception:
                pass
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def serve_once(self) -> None:
        """Accept and handle a single incoming connection (useful for tests)."""
        if not self._is_running or not self._server_socket:
            raise BrokerUnavailableError("Server is not listening.")
        conn, _ = self._server_socket.accept()
        self.handle_connection(conn)

    def stop(self) -> None:
        """Gracefully close socket and unlink socket file."""
        self._is_running = False
        if self._server_socket:
            try:
                self._server_socket.close()
            except Exception:
                pass
            self._server_socket = None

        if os.path.exists(self.socket_path):
            try:
                os.unlink(self.socket_path)
            except Exception:
                pass
