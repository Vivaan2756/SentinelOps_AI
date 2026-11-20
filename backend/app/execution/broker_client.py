"""Unix Domain Socket Broker Client (DEPRECATED - Stage 3B Legacy Broker Retirement).

Retained for unit test compatibility. Under Option C, execution is performed
directly by the unprivileged IsolatedHttpRecoveryRunner. Standalone broker socket
IPC is permanently retired from deployment topology.
"""

import json
import logging
import os
import socket
import struct
from typing import Optional

from app.execution.broker import (
    BrokerExecuteRequest,
    BrokerExecuteResponse,
)
from app.execution.exceptions import (
    BrokerSecurityViolation,
    BrokerUnavailableError,
    ExecutionEnvironmentUnavailable,
)

logger = logging.getLogger("sentinelops.broker_client")

# Default socket path matches the broker server
DEFAULT_SOCKET_PATH = os.environ.get(
    "SENTINELOPS_BROKER_SOCKET",
    "/var/run/sentinelops/broker.sock",
)

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


class UnixSocketBrokerClient:
    """
    Client for dispatching execution requests to the isolated RestrictedDockerBroker daemon.
    Does not touch /var/run/docker.sock directly.
    """

    def __init__(
        self,
        socket_path: Optional[str] = None,
        timeout: float = 35.0,
    ):
        self.socket_path = socket_path or DEFAULT_SOCKET_PATH
        self.timeout = timeout

    def is_broker_available(self) -> bool:
        """Check if broker Unix socket exists and is responsive."""
        if not hasattr(socket, "AF_UNIX"):
            return False
        if not os.path.exists(self.socket_path):
            return False
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(2.0)
        try:
            sock.connect(self.socket_path)
            sock.close()
            return True
        except Exception:
            return False

    def execute_action(self, request: BrokerExecuteRequest) -> BrokerExecuteResponse:
        """
        Send execution request over Unix socket to broker daemon and return structured response.
        Fails closed with BrokerUnavailableError if daemon is unreachable.
        """
        if not hasattr(socket, "AF_UNIX"):
            raise BrokerUnavailableError(
                "Unix domain sockets (AF_UNIX) are not supported on this native Windows runtime. "
                "The broker service must run inside the Linux container boundary or WSL2."
            )

        if not os.path.exists(self.socket_path):
            raise BrokerUnavailableError(
                f"Broker socket not found at '{self.socket_path}'. Standalone broker daemon is not running."
            )


        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)

        try:
            sock.connect(self.socket_path)
        except (ConnectionRefusedError, FileNotFoundError, OSError) as e:
            sock.close()
            raise BrokerUnavailableError(
                f"Failed to connect to RestrictedDockerBroker at '{self.socket_path}': {str(e)}"
            )

        try:
            # 1. Serialize request payload
            req_dict = request.model_dump()
            req_bytes = json.dumps(req_dict).encode("utf-8")

            # 2. Send 4-byte length prefix + payload
            header = struct.pack(HEADER_STRUCT, len(req_bytes))
            sock.sendall(header + req_bytes)

            # 3. Read 4-byte response length prefix
            resp_header = _recv_exact(sock, HEADER_SIZE)
            resp_len = struct.unpack(HEADER_STRUCT, resp_header)[0]

            # 4. Read response payload
            raw_resp = _recv_exact(sock, resp_len)
            resp_dict = json.loads(raw_resp.decode("utf-8"))

            # 5. Check if broker returned an error payload
            if "error" in resp_dict:
                err_msg = resp_dict.get("detail", resp_dict["error"])
                if resp_dict.get("error") == "BrokerSecurityViolation" or "Unauthorized" in resp_dict.get("error", ""):
                    raise BrokerSecurityViolation(err_msg)
                raise BrokerUnavailableError(f"Broker returned error: {err_msg}")

            return BrokerExecuteResponse.model_validate(resp_dict)

        except (socket.timeout, TimeoutError) as e:
            raise BrokerUnavailableError(f"Broker timed out during execution: {str(e)}")
        except ConnectionError as e:
            raise BrokerUnavailableError(f"Connection to broker lost during execution: {str(e)}")
        finally:
            try:
                sock.close()
            except Exception:
                pass
