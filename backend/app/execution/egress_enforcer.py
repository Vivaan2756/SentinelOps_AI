"""Production Network Egress Enforcer & Rule Abstraction for Phase 2A.1 Stage 7.1.3.

Targeted Egress Enforcer Re-entrancy, IPv6 ND & Authority Correction:
- SEC-7.1.2-01: Corrected rollback re-entrancy deadlock. install_egress_rules() delegates to
  _cleanup_egress_rules_unlocked() while holding _CrossProcessLock, eliminating self-deadlock.
- SEC-7.1.2-02: Preserved essential IPv6 Neighbor Discovery by prepending narrowly scoped
  ACCEPT rules for ICMPv6 Neighbor Solicitation (135) and Neighbor Advertisement (136) in
  the host-isolation INPUT subchain before the final DROP rule.
- SEC-7.1.2-03: Hardened host network namespace authority verification with multi-indicator
  container detection; fails closed if containerized execution is detected.
- SEC-7.1.2-04: Deterministic and safe lock path resolution via SENTINELOPS_FIREWALL_LOCK_PATH
  (default /var/run/sentinelops/firewall.lock) with strict parent directory and symlink validation.

Architectural Boundary Notice:
In Phase 2A.1 Stage 6, the broker daemon runs with network_mode: "none". Docker socket
access does not automatically grant host network namespace or iptables administration
privileges. The exact host firewall access mechanism (e.g. host-network privileged helper,
dedicated CNI plugin, or host-level sidecar) is a deployment dependency to be addressed in Stage 7.2.
Stage 7.1.3 establishes the verified rule abstraction, bidirectional packet routing, safe re-entrancy,
and fail-closed authority core.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
import hashlib
import ipaddress
import logging
import os
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple, Union

logger = logging.getLogger("sentinelops.execution.egress_enforcer")

# Strict sanitization pattern for execution identifiers in firewall comments
EXECUTION_ID_PATTERN = re.compile(r"^[a-zA-Z0-9_-]{1,64}$")
COMMENT_PREFIX = "sentinelops-exec-"

DEFAULT_IPTABLES_WAIT_SECONDS = 5
DEFAULT_SUBPROCESS_TIMEOUT_SECONDS = 10.0
DEFAULT_LOCK_TIMEOUT_SECONDS = 15.0
DEFAULT_FIREWALL_LOCK_PATH = "/var/run/sentinelops/firewall.lock"

# Forbidden cloud metadata endpoints from Stage 6 SSRF policy (network.py)
FORBIDDEN_METADATA_IPS: Set[str] = {
    "169.254.169.254",  # AWS / Azure / GCP IMDSv1/v2 IPv4
    "169.254.170.2",    # AWS ECS task metadata
    "100.100.100.200",  # Alibaba Cloud metadata
    "fd00:ec2::254",    # AWS EC2 IMDS IPv6
}

CGNAT_NETWORK = ipaddress.ip_network("100.64.0.0/10")
IPV6_ULA_NETWORK = ipaddress.ip_network("fc00::/7")


# ============================================================================
# Exceptions
# ============================================================================


class EgressEnforcerError(Exception):
    """Base exception for all egress enforcer errors."""


class InvalidRuleConfigurationError(EgressEnforcerError):
    """Raised when rule parameters (execution ID, IPs, port, protocol) fail validation."""


class FirewallCommandError(EgressEnforcerError):
    """Raised when an underlying firewall command (iptables/ip6tables) fails or returns non-zero."""


class FirewallVerificationError(EgressEnforcerError):
    """Raised when installed rules cannot be verified in the kernel packet filter table."""


class UnsupportedPlatformError(EgressEnforcerError):
    """Raised when genuine kernel enforcement is required but unsupported on current platform."""


class UnsafeFirewallStateError(EgressEnforcerError):
    """Raised when firewall state is uncertain or cleanup after installation failure fails."""


# ============================================================================
# Data Models
# ============================================================================


@dataclass(frozen=True)
class RuleInstallationResult:
    """Immutable outcome of an egress rule installation transaction."""

    execution_id: str
    is_enforcing: bool
    installed_ipv4_rules: List[str]
    installed_ipv6_rules: List[str]
    installed_at: float
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class RuleVerificationResult:
    """Outcome of kernel rule presence verification."""

    execution_id: str
    is_verified: bool
    is_enforcing: bool
    verified_ipv4_rules: List[str]
    verified_ipv6_rules: List[str]
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class RuleCleanupResult:
    """Outcome of rule removal."""

    execution_id: str
    cleaned_ipv4_count: int
    cleaned_ipv6_count: int
    is_fully_cleaned: bool
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class StaleReconciliationResult:
    """Outcome of startup stale-rule reconciliation."""

    purged_execution_ids: List[str]
    purged_rules_count: int
    details: Dict[str, Any] = field(default_factory=dict)


# ============================================================================
# Helpers
# ============================================================================


def _execution_chain_name(chain_prefix: str, execution_id: str) -> str:
    """
    Generate deterministic, collision-resistant sub-chain name fitting within 28 characters.
    Linux iptables user-defined chain limit: 28 characters (XT_EXTENSION_MAX_NAMELEN - 1).
    Format: {chain_prefix}-{sha256(execution_id)[:16]}
    Example: 'SO-F-a1b2c3d4e5f60718' (length 21 <= 28)
    """
    h = hashlib.sha256(execution_id.encode("utf-8")).hexdigest()[:16]
    return f"{chain_prefix}-{h}"


def _extract_exact_comment(tokens: List[str]) -> Optional[str]:
    """Parse tokens to find the exact argument value immediately following '--comment'."""
    for i, token in enumerate(tokens):
        if token == "--comment" and i + 1 < len(tokens):
            return tokens[i + 1]
    return None


def _is_host_ipv6_disabled() -> bool:
    """Check sysctl /proc/sys/net/ipv6/conf/all/disable_ipv6 if present."""
    try:
        proc_path = "/proc/sys/net/ipv6/conf/all/disable_ipv6"
        if os.path.exists(proc_path):
            with open(proc_path, "r", encoding="utf-8") as f:
                return f.read().strip() == "1"
    except Exception:
        pass
    return False


def resolve_firewall_lock_path(lock_path: Optional[str] = None) -> str:
    """
    Resolve and validate the cross-process firewall lock path (SEC-7.1.2-04).
    Deterministically resolves from:
    1. Explicit lock_path parameter if provided.
    2. SENTINELOPS_FIREWALL_LOCK_PATH environment variable if set.
    3. DEFAULT_FIREWALL_LOCK_PATH ('/var/run/sentinelops/firewall.lock').

    Rejects relative, empty, whitespace-only, or malformed paths.
    """
    if lock_path is None:
        lock_path = os.environ.get("SENTINELOPS_FIREWALL_LOCK_PATH", DEFAULT_FIREWALL_LOCK_PATH)

    if not lock_path or not isinstance(lock_path, str) or not lock_path.strip():
        raise InvalidRuleConfigurationError("Firewall lock path cannot be empty or non-string.")

    cleaned = lock_path.strip()
    is_abs = os.path.isabs(cleaned) or (sys.platform == "win32" and cleaned.startswith(("/", "\\")))
    if not is_abs:
        raise InvalidRuleConfigurationError(
            f"Firewall lock path must be an absolute path, got relative path: '{cleaned}'"
        )
    return os.path.abspath(cleaned)


class _CrossProcessLock:
    """
    Cross-process file lock ensuring multi-command iptables transactions are serialized
    across processes on Linux (AUD-7.1.1-04, SEC-7.1.2-04).
    """

    def __init__(self, lock_path: Optional[str] = None, timeout: float = DEFAULT_LOCK_TIMEOUT_SECONDS):
        self.lock_path = resolve_firewall_lock_path(lock_path)
        self.timeout = timeout
        self._fd: Optional[int] = None

    def __enter__(self):
        # 1. Validate parent directory (SEC-7.1.2-04)
        parent_dir = os.path.dirname(self.lock_path)
        if not os.path.exists(parent_dir):
            raise UnsafeFirewallStateError(
                f"Parent directory '{parent_dir}' for lock file '{self.lock_path}' does not exist. Failing closed."
            )
        if os.path.islink(parent_dir):
            raise UnsafeFirewallStateError(
                f"Parent directory '{parent_dir}' for lock file '{self.lock_path}' is an unsafe symbolic link."
            )

        # Validate parent directory descriptor where O_DIRECTORY / O_NOFOLLOW supported
        if hasattr(os, "O_DIRECTORY") and sys.platform != "win32":
            dir_flags = os.O_RDONLY | os.O_DIRECTORY
            if hasattr(os, "O_NOFOLLOW"):
                dir_flags |= os.O_NOFOLLOW
            try:
                dir_fd = os.open(parent_dir, dir_flags)
                try:
                    dir_stat = os.fstat(dir_fd)
                    if not stat.S_ISDIR(dir_stat.st_mode):
                        raise UnsafeFirewallStateError(f"Parent path '{parent_dir}' is not a directory.")
                finally:
                    os.close(dir_fd)
            except OSError as e:
                raise UnsafeFirewallStateError(f"Failed to safely open parent directory '{parent_dir}': {e}") from e
        else:
            try:
                parent_stat = os.stat(parent_dir)
                if not stat.S_ISDIR(parent_stat.st_mode):
                    raise UnsafeFirewallStateError(f"Parent path '{parent_dir}' is not a directory.")
            except OSError as e:
                raise UnsafeFirewallStateError(f"Failed to inspect parent directory '{parent_dir}': {e}") from e

        # 2. Reject symlinks for lock file itself before open
        if os.path.islink(self.lock_path):
            raise UnsafeFirewallStateError(
                f"Lock file path '{self.lock_path}' is an unsafe symbolic link. Aborting lock acquisition."
            )

        file_flags = os.O_CREAT | os.O_RDWR
        if hasattr(os, "O_NOFOLLOW"):
            file_flags |= os.O_NOFOLLOW

        try:
            self._fd = os.open(self.lock_path, file_flags, 0o600)
        except OSError as e:
            raise UnsafeFirewallStateError(f"Failed to open cross-process firewall lock '{self.lock_path}': {e}") from e

        # 3. Validate opened lock file descriptor using fstat
        try:
            fd_stat = os.fstat(self._fd)
            if not stat.S_ISREG(fd_stat.st_mode):
                os.close(self._fd)
                self._fd = None
                raise UnsafeFirewallStateError(
                    f"Lock file descriptor for '{self.lock_path}' is not a regular file."
                )
        except OSError as e:
            os.close(self._fd)
            self._fd = None
            raise UnsafeFirewallStateError(f"Failed to fstat lock file descriptor: {e}") from e

        # Re-verify symlink after open to defend against TOCTOU race
        if os.path.islink(self.lock_path):
            os.close(self._fd)
            self._fd = None
            raise UnsafeFirewallStateError(f"Lock file '{self.lock_path}' was replaced with a symlink.")

        # 4. Acquire lock with timeout
        start_time = time.time()
        locked = False
        while time.time() - start_time < self.timeout:
            try:
                import fcntl
                fcntl.flock(self._fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                locked = True
                break
            except (BlockingIOError, OSError):
                time.sleep(0.05)
            except ImportError:
                # Non-Unix platform where fcntl is unavailable
                locked = True
                break

        if not locked:
            os.close(self._fd)
            self._fd = None
            raise UnsafeFirewallStateError(
                f"Failed to acquire cross-process firewall lock '{self.lock_path}' within {self.timeout}s."
            )
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self._fd is not None:
            try:
                import fcntl
                fcntl.flock(self._fd, fcntl.LOCK_UN)
            except Exception:
                pass
            try:
                os.close(self._fd)
            except Exception:
                pass
            self._fd = None


# ============================================================================
# Interface Contract
# ============================================================================


class EgressEnforcerInterface(ABC):
    """Abstract contract for container network egress enforcement."""

    @property
    @abstractmethod
    def is_enforcing(self) -> bool:
        """True if provider actively installs kernel-level packet filtering rules."""

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Identifying name of the enforcer implementation."""

    @abstractmethod
    def install_egress_rules(
        self,
        *,
        execution_id: str,
        source_ips: Sequence[str],
        destination_ip: str,
        destination_port: int,
        protocol: str = "tcp",
        ipv6_enabled: Optional[bool] = None,
    ) -> RuleInstallationResult:
        """
        Atomically install egress filtering rules for the execution container.

        Must permit ONLY the specified destination IP and port on FORWARD, allow strictly
        anchored return traffic via dual parent hooks, block traffic to host services on INPUT,
        and DROP all other traffic.
        """

    @abstractmethod
    def verify_egress_rules(
        self,
        *,
        execution_id: str,
        source_ips: Sequence[str],
        destination_ip: str,
        destination_port: int,
        protocol: str = "tcp",
        ipv6_enabled: Optional[bool] = None,
    ) -> RuleVerificationResult:
        """Query kernel filtering tables to verify that expected rules, hooks, and sub-chains are active."""

    @abstractmethod
    def cleanup_egress_rules(
        self,
        *,
        execution_id: str,
        source_ips: Optional[Sequence[str]] = None,
    ) -> RuleCleanupResult:
        """Remove all firewall rules, dual jump hooks, and sub-chains associated with the execution ID."""

    @abstractmethod
    def reconcile_stale_rules(
        self,
        *,
        active_execution_ids: Set[str],
        uncertain_execution_ids: Optional[Set[str]] = None,
    ) -> StaleReconciliationResult:
        """Purge orphaned firewall rules belonging to executions that are neither active nor uncertain."""


# ============================================================================
# Linux iptables / ip6tables Enforcer
# ============================================================================


class LinuxIptablesEgressEnforcer(EgressEnforcerInterface):
    """
    Production Linux L3/L4 packet filtering enforcer.

    Operates using dedicated execution sub-chains hooked into DOCKER-USER (FORWARD path)
    via dual hooks (outbound and inbound return) and INPUT (host isolation path).
    """

    def __init__(
        self,
        iptables_bin: str = "iptables",
        ip6tables_bin: str = "ip6tables",
        wait_seconds: int = DEFAULT_IPTABLES_WAIT_SECONDS,
        command_timeout: float = DEFAULT_SUBPROCESS_TIMEOUT_SECONDS,
        chain: str = "DOCKER-USER",
        input_chain: str = "INPUT",
        lock_path: Optional[str] = None,
    ):
        self.iptables_bin = iptables_bin
        self.ip6tables_bin = ip6tables_bin
        self.wait_seconds = wait_seconds
        self.command_timeout = command_timeout
        self.chain = chain
        self.input_chain = input_chain
        self.lock_path = resolve_firewall_lock_path(lock_path)
        self._thread_lock = threading.RLock()

    @property
    def is_enforcing(self) -> bool:
        return True

    @property
    def provider_name(self) -> str:
        return "linux-iptables-kernel-enforcer"

    def _validate_inputs(
        self,
        execution_id: str,
        source_ips: Sequence[str],
        destination_ip: str,
        destination_port: int,
        protocol: str,
        ipv6_enabled: Optional[bool] = None,
    ) -> Tuple[List[ipaddress.IPv4Address], List[ipaddress.IPv6Address], Union[ipaddress.IPv4Address, ipaddress.IPv6Address]]:
        """Validate all parameters, enforce strict metadata/SSRF checks (AUD-7.1.1-05), and classify IPs."""
        if not execution_id or not isinstance(execution_id, str):
            raise InvalidRuleConfigurationError("execution_id must be a non-empty string.")
        if not EXECUTION_ID_PATTERN.match(execution_id):
            raise InvalidRuleConfigurationError(
                f"execution_id '{execution_id}' contains invalid characters. Must match {EXECUTION_ID_PATTERN.pattern}"
            )

        if not isinstance(destination_port, int) or destination_port < 1 or destination_port > 65535:
            raise InvalidRuleConfigurationError(
                f"destination_port must be an integer between 1 and 65535, got {destination_port}"
            )

        proto_clean = (protocol or "").strip().lower()
        if proto_clean != "tcp":
            raise InvalidRuleConfigurationError(
                f"Only 'tcp' protocol is currently supported for egress rules, got '{protocol}'"
            )

        if not destination_ip or not isinstance(destination_ip, str):
            raise InvalidRuleConfigurationError("destination_ip must be a non-empty string.")
        try:
            dest_obj = ipaddress.ip_address(destination_ip.strip())
        except ValueError as e:
            raise InvalidRuleConfigurationError(f"Invalid destination_ip '{destination_ip}': {e}") from e

        # Unwrap IPv4-mapped IPv6 address (e.g. ::ffff:169.254.169.254)
        unwrapped_obj = dest_obj.ipv4_mapped if (isinstance(dest_obj, ipaddress.IPv6Address) and dest_obj.ipv4_mapped) else dest_obj
        dest_str = str(unwrapped_obj).lower()

        # AUD-7.1.1-05: Reject explicit cloud metadata IPs
        if dest_str in FORBIDDEN_METADATA_IPS or str(dest_obj).lower() in FORBIDDEN_METADATA_IPS:
            raise InvalidRuleConfigurationError(f"destination_ip '{destination_ip}' is a forbidden cloud metadata endpoint.")

        # AUD-7.1.1-05: Reject CGNAT (100.64.0.0/10)
        if isinstance(unwrapped_obj, ipaddress.IPv4Address) and unwrapped_obj in CGNAT_NETWORK:
            raise InvalidRuleConfigurationError(f"destination_ip '{destination_ip}' is in forbidden CGNAT address space.")

        # AUD-7.1.1-05: Reject IPv6 ULA (fc00::/7)
        if isinstance(dest_obj, ipaddress.IPv6Address) and dest_obj in IPV6_ULA_NETWORK:
            raise InvalidRuleConfigurationError(f"destination_ip '{destination_ip}' is in forbidden IPv6 ULA address space.")

        # Defense-in-depth: reject loopback, link-local, multicast, unspecified, private, reserved
        if (
            unwrapped_obj.is_loopback
            or unwrapped_obj.is_unspecified
            or unwrapped_obj.is_multicast
            or unwrapped_obj.is_link_local
            or unwrapped_obj.is_reserved
            or unwrapped_obj.is_private
        ):
            raise InvalidRuleConfigurationError(
                f"destination_ip '{destination_ip}' is prohibited: must be a globally routeable address "
                f"(rejected loopback={unwrapped_obj.is_loopback}, unspecified={unwrapped_obj.is_unspecified}, "
                f"multicast={unwrapped_obj.is_multicast}, link_local={unwrapped_obj.is_link_local}, "
                f"reserved={unwrapped_obj.is_reserved}, private={unwrapped_obj.is_private})."
            )

        if not source_ips:
            raise InvalidRuleConfigurationError("source_ips cannot be empty.")

        ipv4_sources: List[ipaddress.IPv4Address] = []
        ipv6_sources: List[ipaddress.IPv6Address] = []

        for sip in source_ips:
            if not sip or not isinstance(sip, str):
                raise InvalidRuleConfigurationError(f"Invalid source IP element: '{sip}'")
            try:
                s_obj = ipaddress.ip_address(sip.strip())
                if isinstance(s_obj, ipaddress.IPv4Address):
                    ipv4_sources.append(s_obj)
                else:
                    ipv6_sources.append(s_obj)
            except ValueError as e:
                raise InvalidRuleConfigurationError(f"Invalid source IP '{sip}': {e}") from e

        # Unconditional IPv6 containment
        if not ipv6_sources:
            if ipv6_enabled is True:
                raise InvalidRuleConfigurationError(
                    "IPv6 is enabled on the network, but no IPv6 container source address was provided. "
                    "Cannot guarantee comprehensive egress isolation."
                )
            elif ipv6_enabled is False:
                pass
            else:
                if not _is_host_ipv6_disabled():
                    raise InvalidRuleConfigurationError(
                        "No IPv6 source address provided and IPv6 is not demonstrably disabled on host. "
                        "Specify ipv6_enabled=False if IPv6 is disabled on the container network, "
                        "or provide the container's IPv6 source address to enforce dual-stack isolation."
                    )

        return ipv4_sources, ipv6_sources, dest_obj

    def _execute_command(
        self,
        cmd: List[str],
        input_data: Optional[bytes] = None,
        check_returncode: bool = True,
    ) -> subprocess.CompletedProcess:
        """Run command strictly as tokenized list without shell."""
        try:
            logger.debug("Executing egress firewall command: %s", " ".join(cmd))
            proc = subprocess.run(
                cmd,
                input=input_data,
                capture_output=True,
                text=False,
                timeout=self.command_timeout,
                check=False,
            )
            if check_returncode and proc.returncode != 0:
                err_msg = proc.stderr.decode("utf-8", errors="replace").strip()
                raise FirewallCommandError(
                    f"Command '{' '.join(cmd)}' failed with exit code {proc.returncode}: {err_msg}"
                )
            return proc
        except subprocess.TimeoutExpired as e:
            raise FirewallCommandError(
                f"Command '{' '.join(cmd)}' timed out after {self.command_timeout} seconds."
            ) from e
        except OSError as e:
            raise FirewallCommandError(f"Failed to execute command '{' '.join(cmd)}': {e}") from e

    def _ensure_parent_chain(self, binary: str, chain: str) -> None:
        """Verify that the parent chain exists; provision and hook it if absent."""
        check_cmd = [binary, "-w", str(self.wait_seconds), "-S", chain]
        res = self._execute_command(check_cmd, check_returncode=False)
        if res.returncode == 0:
            return

        logger.info("Parent chain '%s' does not exist in %s. Provisioning...", chain, binary)
        create_cmd = [binary, "-w", str(self.wait_seconds), "-N", chain]
        self._execute_command(create_cmd)

        if chain == "DOCKER-USER":
            hook_check = [binary, "-w", str(self.wait_seconds), "-C", "FORWARD", "-j", chain]
            hook_res = self._execute_command(hook_check, check_returncode=False)
            if hook_res.returncode != 0:
                hook_cmd = [binary, "-w", str(self.wait_seconds), "-I", "FORWARD", "1", "-j", chain]
                self._execute_command(hook_cmd)

    def build_iptables_commands_for_family(
        self,
        *,
        execution_id: str,
        sources: Sequence[Union[ipaddress.IPv4Address, ipaddress.IPv6Address]],
        dest_ip: Optional[Union[ipaddress.IPv4Address, ipaddress.IPv6Address]],
        dest_port: int,
        family: int,
    ) -> Tuple[List[List[str]], str, str]:
        """
        Build complete command sequence for an address family using dedicated sub-chains
        and dual parent jump hooks (AUD-7.1.1-01, AUD-7.1.1-02).
        """
        comment = f"{COMMENT_PREFIX}{execution_id}"
        binary = self.iptables_bin if family == 4 else self.ip6tables_bin
        icmp_proto = "icmp" if family == 4 else "ipv6-icmp"

        so_f = _execution_chain_name("SO-F", execution_id)
        so_i = _execution_chain_name("SO-I", execution_id)

        commands: List[List[str]] = []

        # 1. Create sub-chains
        commands.append([binary, "-w", str(self.wait_seconds), "-N", so_f])
        commands.append([binary, "-w", str(self.wait_seconds), "-N", so_i])

        # 2. Populate INPUT sub-chain: block container from host services
        # SEC-7.1.2-02: For IPv6, permit ICMPv6 Neighbor Solicitation (type 135) and
        # Neighbor Advertisement (type 136) from container source so link-layer address
        # resolution on the host bridge succeeds (RFC 4861 / RFC 4890).
        for src in sources:
            src_str = str(src)
            if family == 6:
                # Accept Neighbor Solicitation (type 135)
                commands.append([
                    binary, "-w", str(self.wait_seconds),
                    "-A", so_i,
                    "-s", src_str,
                    "-p", "ipv6-icmp",
                    "-m", "icmp6", "--icmpv6-type", "135",
                    "-m", "comment", "--comment", comment,
                    "-j", "ACCEPT",
                ])
                # Accept Neighbor Advertisement (type 136)
                commands.append([
                    binary, "-w", str(self.wait_seconds),
                    "-A", so_i,
                    "-s", src_str,
                    "-p", "ipv6-icmp",
                    "-m", "icmp6", "--icmpv6-type", "136",
                    "-m", "comment", "--comment", comment,
                    "-j", "ACCEPT",
                ])
            # Unconditional host service isolation DROP for all other container traffic
            commands.append([
                binary, "-w", str(self.wait_seconds),
                "-A", so_i,
                "-s", src_str,
                "-m", "comment", "--comment", comment,
                "-j", "DROP",
            ])

        # 3. Populate FORWARD sub-chain: allow authorized TCP, return traffic, related PMTU ICMP, drop all else
        if dest_ip is not None and dest_ip.version == family:
            dest_str = str(dest_ip)
            for src in sources:
                src_str = str(src)
                # Rule 1: ACCEPT outbound TCP to pinned IP and port
                commands.append([
                    binary, "-w", str(self.wait_seconds),
                    "-A", so_f,
                    "-s", src_str,
                    "-d", dest_str,
                    "-p", "tcp",
                    "--dport", str(dest_port),
                    "-m", "comment", "--comment", comment,
                    "-j", "ACCEPT",
                ])
                # Rule 2: ACCEPT established return traffic strictly from authorized destination and port
                commands.append([
                    binary, "-w", str(self.wait_seconds),
                    "-A", so_f,
                    "-d", src_str,
                    "-s", dest_str,
                    "-p", "tcp",
                    "--sport", str(dest_port),
                    "-m", "conntrack", "--ctstate", "ESTABLISHED",
                    "-m", "comment", "--comment", comment,
                    "-j", "ACCEPT",
                ])
                # Rule 3 (AUD-7.1.1-02): ACCEPT related ICMP errors (Path MTU Discovery: Fragmentation Needed / Packet Too Big)
                # Note: No -s dest_str constraint because intermediate transit routers generate PMTU errors!
                commands.append([
                    binary, "-w", str(self.wait_seconds),
                    "-A", so_f,
                    "-d", src_str,
                    "-p", icmp_proto,
                    "-m", "conntrack", "--ctstate", "RELATED",
                    "-m", "comment", "--comment", comment,
                    "-j", "ACCEPT",
                ])
            # Default DROP for forward traffic in this subchain
            commands.append([
                binary, "-w", str(self.wait_seconds),
                "-A", so_f,
                "-m", "comment", "--comment", comment,
                "-j", "DROP",
            ])
        else:
            # Destination belongs to other family -> unconditional DROP for this family (anti-leakage)
            for src in sources:
                commands.append([
                    binary, "-w", str(self.wait_seconds),
                    "-A", so_f,
                    "-s", str(src),
                    "-m", "comment", "--comment", comment,
                    "-j", "DROP",
                ])

        # 4. Hook sub-chains into parent chains (DOCKER-USER and INPUT)
        # AUD-7.1.1-01: Dual parent jump hooks in DOCKER-USER for both outbound (-s) and return (-d)
        for src in sources:
            src_str = str(src)
            # Outbound hook: directs egress from container into subchain
            commands.append([
                binary, "-w", str(self.wait_seconds),
                "-I", self.chain, "1",
                "-s", src_str,
                "-m", "comment", "--comment", comment,
                "-j", so_f,
            ])
            # Inbound hook (AUD-7.1.1-01): directs return traffic to container into subchain
            commands.append([
                binary, "-w", str(self.wait_seconds),
                "-I", self.chain, "1",
                "-d", src_str,
                "-m", "comment", "--comment", comment,
                "-j", so_f,
            ])
            # Host isolation hook in INPUT
            commands.append([
                binary, "-w", str(self.wait_seconds),
                "-I", self.input_chain, "1",
                "-s", src_str,
                "-m", "comment", "--comment", comment,
                "-j", so_i,
            ])

        return commands, so_f, so_i

    def install_egress_rules(
        self,
        *,
        execution_id: str,
        source_ips: Sequence[str],
        destination_ip: str,
        destination_port: int,
        protocol: str = "tcp",
        ipv6_enabled: Optional[bool] = None,
    ) -> RuleInstallationResult:
        """
        Atomically install egress rules using dedicated per-execution sub-chains
        and cross-process synchronization (AUD-7.1.1-04).
        """
        with self._thread_lock, _CrossProcessLock(self.lock_path):
            ipv4_sources, ipv6_sources, dest_obj = self._validate_inputs(
                execution_id, source_ips, destination_ip, destination_port, protocol, ipv6_enabled
            )

            installed_ipv4_cmds: List[List[str]] = []
            installed_ipv6_cmds: List[List[str]] = []

            try:
                if ipv4_sources:
                    self._ensure_parent_chain(self.iptables_bin, self.chain)
                    v4_cmds, _, _ = self.build_iptables_commands_for_family(
                        execution_id=execution_id,
                        sources=ipv4_sources,
                        dest_ip=dest_obj if dest_obj.version == 4 else None,
                        dest_port=destination_port,
                        family=4,
                    )
                    for cmd in v4_cmds:
                        self._execute_command(cmd)
                        installed_ipv4_cmds.append(cmd)

                if ipv6_sources:
                    self._ensure_parent_chain(self.ip6tables_bin, self.chain)
                    v6_cmds, _, _ = self.build_iptables_commands_for_family(
                        execution_id=execution_id,
                        sources=ipv6_sources,
                        dest_ip=dest_obj if dest_obj.version == 6 else None,
                        dest_port=destination_port,
                        family=6,
                    )
                    for cmd in v6_cmds:
                        self._execute_command(cmd)
                        installed_ipv6_cmds.append(cmd)

            except Exception as install_err:
                logger.error(
                    "Egress firewall installation failed for execution '%s': %s. Rolling back partial rules.",
                    execution_id,
                    install_err,
                )
                cleanup_res = self._cleanup_egress_rules_unlocked(execution_id=execution_id)
                if not cleanup_res.is_fully_cleaned:
                    raise UnsafeFirewallStateError(
                        f"Firewall installation failed ({install_err}) AND rollback cleanup failed to remove all rules: "
                        f"{cleanup_res.details}. System firewall state is UNCERTAIN."
                    ) from install_err

                raise FirewallCommandError(
                    f"Firewall installation failed: {install_err}. Partial rules rolled back successfully."
                ) from install_err

            return RuleInstallationResult(
                execution_id=execution_id,
                is_enforcing=True,
                installed_ipv4_rules=[" ".join(c) for c in installed_ipv4_cmds],
                installed_ipv6_rules=[" ".join(c) for c in installed_ipv6_cmds],
                installed_at=time.time(),
                details={
                    "chain": self.chain,
                    "input_chain": self.input_chain,
                    "ipv4_sources": [str(s) for s in ipv4_sources],
                    "ipv6_sources": [str(s) for s in ipv6_sources],
                    "destination_ip": str(dest_obj),
                    "destination_port": destination_port,
                },
            )

    def verify_egress_rules(
        self,
        *,
        execution_id: str,
        source_ips: Sequence[str],
        destination_ip: str,
        destination_port: int,
        protocol: str = "tcp",
        ipv6_enabled: Optional[bool] = None,
    ) -> RuleVerificationResult:
        """
        Verify that sub-chains and dual jump hooks matching the execution comment exist in the kernel.
        """
        with self._thread_lock, _CrossProcessLock(self.lock_path):
            ipv4_sources, ipv6_sources, dest_obj = self._validate_inputs(
                execution_id, source_ips, destination_ip, destination_port, protocol, ipv6_enabled
            )
            comment = f"{COMMENT_PREFIX}{execution_id}"
            verified_v4: List[str] = []
            verified_v6: List[str] = []

            if ipv4_sources:
                res = self._execute_command([self.iptables_bin, "-w", str(self.wait_seconds), "-S"])
                stdout = res.stdout.decode("utf-8", errors="replace")
                rules = []
                for line in stdout.splitlines():
                    tokens = shlex.split(line.strip())
                    if _extract_exact_comment(tokens) == comment:
                        rules.append(line.strip())
                if not rules:
                    raise FirewallVerificationError(
                        f"Verification failed: zero IPv4 rules found for exact comment '{comment}'."
                    )
                verified_v4 = rules

            if ipv6_sources:
                res = self._execute_command([self.ip6tables_bin, "-w", str(self.wait_seconds), "-S"])
                stdout = res.stdout.decode("utf-8", errors="replace")
                rules = []
                for line in stdout.splitlines():
                    tokens = shlex.split(line.strip())
                    if _extract_exact_comment(tokens) == comment:
                        rules.append(line.strip())
                if not rules:
                    raise FirewallVerificationError(
                        f"Verification failed: zero IPv6 rules found for exact comment '{comment}'."
                    )
                verified_v6 = rules

            return RuleVerificationResult(
                execution_id=execution_id,
                is_verified=True,
                is_enforcing=True,
                verified_ipv4_rules=verified_v4,
                verified_ipv6_rules=verified_v6,
                details={"comment": comment},
            )

    def _cleanup_egress_rules_unlocked(
        self,
        *,
        execution_id: str,
        source_ips: Optional[Sequence[str]] = None,
    ) -> RuleCleanupResult:
        """
        Internal implementation of rule cleanup.
        MUST be called while holding _CrossProcessLock and self._thread_lock (SEC-7.1.2-01).
        Does NOT acquire locks itself.
        """
        if not execution_id or not EXECUTION_ID_PATTERN.match(execution_id):
            raise InvalidRuleConfigurationError(f"Invalid execution_id for cleanup: '{execution_id}'")

        comment = f"{COMMENT_PREFIX}{execution_id}"
        so_f = _execution_chain_name("SO-F", execution_id)
        so_i = _execution_chain_name("SO-I", execution_id)

        cleaned_v4 = 0
        cleaned_v6 = 0
        cleanup_errors: List[str] = []

        for binary, counter_ref in ((self.iptables_bin, "v4"), (self.ip6tables_bin, "v6")):
            count = 0
            try:
                # 1. Remove dual jump hooks in DOCKER-USER and INPUT
                for parent_ch in (self.chain, self.input_chain):
                    list_cmd = [binary, "-w", str(self.wait_seconds), "-S", parent_ch]
                    res = self._execute_command(list_cmd, check_returncode=False)
                    if res.returncode == 0:
                        for line in res.stdout.decode("utf-8", errors="replace").splitlines():
                            tokens = shlex.split(line.strip())
                            if _extract_exact_comment(tokens) == comment and tokens and tokens[0] == "-A":
                                del_cmd = [binary, "-w", str(self.wait_seconds), "-D"] + tokens[1:]
                                d_res = self._execute_command(del_cmd, check_returncode=False)
                                if d_res.returncode == 0:
                                    count += 1
                                else:
                                    err_str = d_res.stderr.decode("utf-8", errors="replace").strip()
                                    cleanup_errors.append(f"Failed deleting rule '{' '.join(del_cmd)}': {err_str}")

                # 2. Flush and delete execution sub-chains
                for subch in (so_f, so_i):
                    flush_cmd = [binary, "-w", str(self.wait_seconds), "-F", subch]
                    f_res = self._execute_command(flush_cmd, check_returncode=False)
                    if f_res.returncode != 0:
                        f_err = f_res.stderr.decode("utf-8", errors="replace").strip()
                        if "no chain/target/match" not in f_err.lower():
                            cleanup_errors.append(f"Failed flushing chain {subch}: {f_err}")

                    del_chain_cmd = [binary, "-w", str(self.wait_seconds), "-X", subch]
                    d_ch_res = self._execute_command(del_chain_cmd, check_returncode=False)
                    if d_ch_res.returncode == 0:
                        count += 1
                    else:
                        dx_err = d_ch_res.stderr.decode("utf-8", errors="replace").strip()
                        if "no chain/target/match" not in dx_err.lower():
                            cleanup_errors.append(f"Failed deleting chain {subch}: {dx_err}")

            except Exception as e:
                logger.warning("Error cleaning rules on %s for %s: %s", binary, execution_id, e)
                cleanup_errors.append(f"Exception on {binary}: {e}")

            if counter_ref == "v4":
                cleaned_v4 = count
            else:
                cleaned_v6 = count

        # Verification: assert zero rules or chains matching this execution remain
        remaining_rules: List[str] = []
        for binary in (self.iptables_bin, self.ip6tables_bin):
            try:
                res = self._execute_command([binary, "-w", str(self.wait_seconds), "-S"], check_returncode=False)
                if res.returncode == 0:
                    for line in res.stdout.decode("utf-8", errors="replace").splitlines():
                        tokens = shlex.split(line.strip())
                        if _extract_exact_comment(tokens) == comment:
                            remaining_rules.append(f"{binary} rule: {line.strip()}")
                        elif tokens and tokens[0] == "-N" and tokens[1] in (so_f, so_i):
                            remaining_rules.append(f"{binary} chain: {line.strip()}")
            except Exception as e:
                cleanup_errors.append(f"Exception verifying {binary}: {e}")

        is_fully_cleaned = (len(remaining_rules) == 0) and (len(cleanup_errors) == 0)

        return RuleCleanupResult(
            execution_id=execution_id,
            cleaned_ipv4_count=cleaned_v4,
            cleaned_ipv6_count=cleaned_v6,
            is_fully_cleaned=is_fully_cleaned,
            details={"remaining_rules": remaining_rules, "cleanup_errors": cleanup_errors},
        )

    def cleanup_egress_rules(
        self,
        *,
        execution_id: str,
        source_ips: Optional[Sequence[str]] = None,
    ) -> RuleCleanupResult:
        """
        Safely remove dual jump hooks and dedicated sub-chains matching this execution ID.
        Acquires thread lock and cross-process lock before delegating to _cleanup_egress_rules_unlocked (SEC-7.1.2-01).
        """
        with self._thread_lock, _CrossProcessLock(self.lock_path):
            return self._cleanup_egress_rules_unlocked(execution_id=execution_id, source_ips=source_ips)

    def reconcile_stale_rules(
        self,
        *,
        active_execution_ids: Set[str],
        uncertain_execution_ids: Optional[Set[str]] = None,
    ) -> StaleReconciliationResult:
        """
        Reconcile stale rules left behind by dead containers or crashed brokers (AUD-7.1.1-04).
        Protects both active_execution_ids AND uncertain_execution_ids.
        Empty sub-chains matching protected execution hashes are explicitly preserved.
        """
        with self._thread_lock, _CrossProcessLock(self.lock_path):
            if active_execution_ids is None or not isinstance(active_execution_ids, set):
                raise InvalidRuleConfigurationError("active_execution_ids must be a non-null set of strings.")

            protected_ids = set(active_execution_ids) | set(uncertain_execution_ids or ())

            # Pre-compute all protected sub-chain names to avoid deleting newly initialized chains (AUD-7.1.1-04)
            protected_subchains = set()
            for pid in protected_ids:
                protected_subchains.add(_execution_chain_name("SO-F", pid))
                protected_subchains.add(_execution_chain_name("SO-I", pid))

            purged_ids: Set[str] = set()
            purged_count = 0

            for binary in (self.iptables_bin, self.ip6tables_bin):
                try:
                    # 1. Purge stale jump rules in DOCKER-USER and INPUT
                    for parent_ch in (self.chain, self.input_chain):
                        res = self._execute_command(
                            [binary, "-w", str(self.wait_seconds), "-S", parent_ch],
                            check_returncode=False,
                        )
                        if res.returncode != 0:
                            continue

                        for line in res.stdout.decode("utf-8", errors="replace").splitlines():
                            tokens = shlex.split(line.strip())
                            comm = _extract_exact_comment(tokens)
                            if comm and comm.startswith(COMMENT_PREFIX):
                                exec_id = comm[len(COMMENT_PREFIX):]
                                if exec_id not in protected_ids and tokens and tokens[0] == "-A":
                                    del_cmd = [binary, "-w", str(self.wait_seconds), "-D"] + tokens[1:]
                                    d_res = self._execute_command(del_cmd, check_returncode=False)
                                    if d_res.returncode == 0:
                                        purged_ids.add(exec_id)
                                        purged_count += 1

                    # 2. Purge stale sub-chains matching SO-F- or SO-I-
                    full_res = self._execute_command(
                        [binary, "-w", str(self.wait_seconds), "-S"],
                        check_returncode=False,
                    )
                    if full_res.returncode == 0:
                        for line in full_res.stdout.decode("utf-8", errors="replace").splitlines():
                            tokens = shlex.split(line.strip())
                            if tokens and tokens[0] == "-N" and (tokens[1].startswith("SO-F-") or tokens[1].startswith("SO-I-")):
                                subch = tokens[1]
                                # AUD-7.1.1-04: If subchain belongs to a protected execution, preserve it even if 0 rules!
                                if subch in protected_subchains:
                                    continue

                                # Inspect subchain rules for any protected comment
                                ch_inspect = self._execute_command(
                                    [binary, "-w", str(self.wait_seconds), "-S", subch],
                                    check_returncode=False,
                                )
                                is_protected = False
                                if ch_inspect.returncode == 0:
                                    for r_line in ch_inspect.stdout.decode("utf-8", errors="replace").splitlines():
                                        r_tokens = shlex.split(r_line.strip())
                                        r_comm = _extract_exact_comment(r_tokens)
                                        if r_comm and r_comm.startswith(COMMENT_PREFIX):
                                            if r_comm[len(COMMENT_PREFIX):] in protected_ids:
                                                is_protected = True
                                                break
                                if not is_protected:
                                    self._execute_command([binary, "-w", str(self.wait_seconds), "-F", subch], check_returncode=False)
                                    dx_res = self._execute_command([binary, "-w", str(self.wait_seconds), "-X", subch], check_returncode=False)
                                    if dx_res.returncode == 0:
                                        purged_count += 1

                except Exception as e:
                    logger.error("Failed during stale rule reconciliation on %s: %s", binary, e)

            return StaleReconciliationResult(
                purged_execution_ids=sorted(purged_ids),
                purged_rules_count=purged_count,
                details={"scanned_chains": [self.chain, self.input_chain]},
            )


# ============================================================================
# Development / Test Non-Enforcing Provider
# ============================================================================


class DevelopmentEgressEnforcer(EgressEnforcerInterface):
    """
    Development and test enforcer for Windows, macOS, and Docker Desktop.

    IMPORTANT SAFETY INVARIANTS:
    1. Explicitly identifies as NON-ENFORCING (is_enforcing = False).
    2. Never claims kernel-level packet isolation.
    3. Cannot be selected in production environment.
    4. Validates all execution IDs, IP addresses, ports, protocols, and metadata
       containment invariants identically to production.
    """

    def __init__(self):
        self._in_memory_rules: Dict[str, Dict[str, Any]] = {}
        logger.info(
            "DevelopmentEgressEnforcer initialized. Note: This provider is NON-ENFORCING and does not "
            "install kernel-level packet filter rules (intended for local development and test environments only)."
        )

    @property
    def is_enforcing(self) -> bool:
        return False

    @property
    def provider_name(self) -> str:
        return "development-non-enforcing-mock"

    def install_egress_rules(
        self,
        *,
        execution_id: str,
        source_ips: Sequence[str],
        destination_ip: str,
        destination_port: int,
        protocol: str = "tcp",
        ipv6_enabled: Optional[bool] = None,
    ) -> RuleInstallationResult:
        if not execution_id or not EXECUTION_ID_PATTERN.match(execution_id):
            raise InvalidRuleConfigurationError(f"Invalid execution_id: '{execution_id}'")
        if not isinstance(destination_port, int) or destination_port < 1 or destination_port > 65535:
            raise InvalidRuleConfigurationError(f"Invalid destination_port: {destination_port}")
        if (protocol or "").strip().lower() != "tcp":
            raise InvalidRuleConfigurationError(f"Invalid protocol: '{protocol}'")

        try:
            dest_obj = ipaddress.ip_address(destination_ip.strip())
        except Exception as e:
            raise InvalidRuleConfigurationError(f"Invalid destination_ip: {e}") from e

        unwrapped = dest_obj.ipv4_mapped if (isinstance(dest_obj, ipaddress.IPv6Address) and dest_obj.ipv4_mapped) else dest_obj
        dest_str = str(unwrapped).lower()

        # Reject forbidden metadata
        if dest_str in FORBIDDEN_METADATA_IPS or str(dest_obj).lower() in FORBIDDEN_METADATA_IPS:
            raise InvalidRuleConfigurationError(f"destination_ip '{destination_ip}' is a forbidden cloud metadata endpoint.")

        # Reject CGNAT and ULA
        if isinstance(unwrapped, ipaddress.IPv4Address) and unwrapped in CGNAT_NETWORK:
            raise InvalidRuleConfigurationError(f"destination_ip '{destination_ip}' is in forbidden CGNAT address space.")
        if isinstance(dest_obj, ipaddress.IPv6Address) and dest_obj in IPV6_ULA_NETWORK:
            raise InvalidRuleConfigurationError(f"destination_ip '{destination_ip}' is in forbidden IPv6 ULA address space.")

        # Apply identical destination validation (reject loopback, link-local, multicast, etc.)
        if (
            unwrapped.is_loopback
            or unwrapped.is_unspecified
            or unwrapped.is_multicast
            or unwrapped.is_link_local
            or unwrapped.is_reserved
            or unwrapped.is_private
        ):
            raise InvalidRuleConfigurationError(
                f"destination_ip '{destination_ip}' is prohibited: must be globally routeable "
                f"(rejected loopback={unwrapped.is_loopback}, unspecified={unwrapped.is_unspecified}, "
                f"multicast={unwrapped.is_multicast}, link_local={unwrapped.is_link_local}, "
                f"reserved={unwrapped.is_reserved}, private={unwrapped.is_private})."
            )

        if not source_ips:
            raise InvalidRuleConfigurationError("source_ips cannot be empty.")

        v4_sources: List[str] = []
        v6_sources: List[str] = []
        for s in source_ips:
            try:
                obj = ipaddress.ip_address(s.strip())
                if obj.version == 4:
                    v4_sources.append(str(obj))
                else:
                    v6_sources.append(str(obj))
            except Exception as e:
                raise InvalidRuleConfigurationError(f"Invalid source_ip: {e}") from e

        if not v6_sources:
            if ipv6_enabled is True:
                raise InvalidRuleConfigurationError(
                    "IPv6 is enabled on the network, but no IPv6 container source address was provided. "
                    "Cannot guarantee comprehensive egress isolation."
                )

        record = {
            "execution_id": execution_id,
            "v4_sources": v4_sources,
            "v6_sources": v6_sources,
            "destination_ip": str(dest_obj),
            "destination_port": destination_port,
            "protocol": protocol,
            "installed_at": time.time(),
        }
        self._in_memory_rules[execution_id] = record

        return RuleInstallationResult(
            execution_id=execution_id,
            is_enforcing=False,
            installed_ipv4_rules=[f"MOCK-ALLOW-TCP {s} -> {dest_obj}:{destination_port}" for s in v4_sources],
            installed_ipv6_rules=[f"MOCK-ALLOW-TCP {s} -> {dest_obj}:{destination_port}" for s in v6_sources],
            installed_at=record["installed_at"],
            details={"warning": "NON-ENFORCING: Kernel-level packet filtering is NOT active."},
        )

    def verify_egress_rules(
        self,
        *,
        execution_id: str,
        source_ips: Sequence[str],
        destination_ip: str,
        destination_port: int,
        protocol: str = "tcp",
        ipv6_enabled: Optional[bool] = None,
    ) -> RuleVerificationResult:
        if execution_id not in self._in_memory_rules:
            raise FirewallVerificationError(f"No development rules registered for execution '{execution_id}'.")

        rec = self._in_memory_rules[execution_id]
        return RuleVerificationResult(
            execution_id=execution_id,
            is_verified=True,
            is_enforcing=False,
            verified_ipv4_rules=[f"MOCK-VERIFIED {s}" for s in rec["v4_sources"]],
            verified_ipv6_rules=[f"MOCK-VERIFIED {s}" for s in rec["v6_sources"]],
            details={"warning": "NON-ENFORCING: Verified in-memory record only."},
        )

    def _cleanup_egress_rules_unlocked(
        self,
        *,
        execution_id: str,
        source_ips: Optional[Sequence[str]] = None,
    ) -> RuleCleanupResult:
        return self.cleanup_egress_rules(execution_id=execution_id, source_ips=source_ips)

    def cleanup_egress_rules(
        self,
        *,
        execution_id: str,
        source_ips: Optional[Sequence[str]] = None,
    ) -> RuleCleanupResult:
        if not execution_id or not EXECUTION_ID_PATTERN.match(execution_id):
            raise InvalidRuleConfigurationError(f"Invalid execution_id for cleanup: '{execution_id}'")

        if execution_id in self._in_memory_rules:
            rec = self._in_memory_rules.pop(execution_id)
            return RuleCleanupResult(
                execution_id=execution_id,
                cleaned_ipv4_count=len(rec["v4_sources"]),
                cleaned_ipv6_count=len(rec["v6_sources"]),
                is_fully_cleaned=True,
                details={"status": "Cleaned in-memory record."},
            )
        return RuleCleanupResult(
            execution_id=execution_id,
            cleaned_ipv4_count=0,
            cleaned_ipv6_count=0,
            is_fully_cleaned=True,
            details={"status": "No rules existed for execution."},
        )

    def reconcile_stale_rules(
        self,
        *,
        active_execution_ids: Set[str],
        uncertain_execution_ids: Optional[Set[str]] = None,
    ) -> StaleReconciliationResult:
        if active_execution_ids is None or not isinstance(active_execution_ids, set):
            raise InvalidRuleConfigurationError("active_execution_ids must be a non-null set of strings.")

        protected_ids = set(active_execution_ids) | set(uncertain_execution_ids or ())
        purged = []
        for eid in list(self._in_memory_rules.keys()):
            if eid not in protected_ids:
                self._in_memory_rules.pop(eid, None)
                purged.append(eid)

        return StaleReconciliationResult(
            purged_execution_ids=sorted(purged),
            purged_rules_count=len(purged),
            details={"provider": "development"},
        )


# ============================================================================
# Provider Factory & Namespace Authority Verification (SEC-7.1.2-03)
# ============================================================================


def _is_container_environment() -> Tuple[bool, str]:
    """
    Detect whether the process is executing inside a container environment
    using multiple independent indicators (SEC-7.1.2-03).
    """
    # 1. Container indicator files
    for marker in ("/.dockerenv", "/run/.containerenv"):
        if os.path.exists(marker):
            return True, f"Container marker file found: {marker}"

    # 2. Inspect cgroup signatures
    for cgroup_path in ("/proc/self/cgroup", "/proc/1/cgroup"):
        if os.path.exists(cgroup_path):
            try:
                with open(cgroup_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read().lower()
                    for sig in ("docker", "containerd", "kubepods", "libpod", "lxc", "actions_runner"):
                        if sig in content:
                            return True, f"Container cgroup signature '{sig}' in {cgroup_path}"
            except Exception:
                pass

    # 3. Inspect PID 1 process name
    proc1_comm = "/proc/1/comm"
    if os.path.exists(proc1_comm):
        try:
            with open(proc1_comm, "r", encoding="utf-8", errors="ignore") as f:
                comm = f.read().strip().lower()
                # On genuine Linux host, PID 1 is systemd or init
                if comm and comm not in ("systemd", "init"):
                    return True, f"PID 1 process '{comm}' indicates container init environment"
        except Exception:
            pass

    return False, ""


def _verify_host_netfilter_authority(iptables_path: str, ip6tables_path: str) -> None:
    """
    Verify that the current process possesses genuine host network namespace authority (SEC-7.1.2-03).

    Enforces conservative fail-closed policy:
    1. Executes non-destructive netfilter queries on iptables and ip6tables.
    2. Detects containerized execution via multiple independent indicators.
       If running in any container environment, fails closed: container-local CAP_NET_ADMIN
       cannot safely modify host bridge packet routing.
    3. If on host, verifies root network namespace identity (/proc/self/ns/net == /proc/1/ns/net).
    """
    # 1. Test basic command execution
    for bin_path in (iptables_path, ip6tables_path):
        try:
            res = subprocess.run(
                [bin_path, "-w", "5", "-L", "FORWARD", "-n"],
                capture_output=True,
                text=False,
                timeout=5.0,
                check=False,
            )
            if res.returncode != 0:
                err = res.stderr.decode("utf-8", errors="replace").strip()
                raise UnsupportedPlatformError(
                    f"Production environment lacks kernel packet filtering authority (CAP_NET_ADMIN / root required). "
                    f"Executing '{bin_path} -L FORWARD -n' failed with code {res.returncode}: {err}"
                )
        except subprocess.TimeoutExpired as e:
            raise UnsupportedPlatformError(f"Testing netfilter authority timed out on '{bin_path}': {e}") from e
        except OSError as e:
            raise UnsupportedPlatformError(f"Failed to execute '{bin_path}' during capability verification: {e}") from e

    # 2. SEC-7.1.2-03: Multi-indicator container detection
    in_container, container_reason = _is_container_environment()
    if in_container:
        raise UnsupportedPlatformError(
            f"Host network namespace authority cannot be established: containerized execution environment detected ({container_reason}). "
            "Container-local CAP_NET_ADMIN cannot modify host firewall rules. "
            "A dedicated host-level firewall enforcement integration is required for production "
            "(Stage 7.2 deployment architecture dependency). Failing closed."
        )

    # 3. Host network namespace identity verification
    self_ns = "/proc/self/ns/net"
    init_ns = "/proc/1/ns/net"
    if os.path.exists(self_ns) and os.path.exists(init_ns):
        try:
            self_stat = os.stat(self_ns)
            init_stat = os.stat(init_ns)
            if self_stat.st_ino != init_stat.st_ino:
                raise UnsupportedPlatformError(
                    "Process is executing inside a child network namespace "
                    f"(self netns {self_stat.st_ino} != init netns {init_stat.st_ino}). "
                    "Non-host netns cannot modify host firewall rules. Failing closed."
                )
        except OSError as e:
            raise UnsupportedPlatformError(f"Failed inspecting network namespace inodes: {e}") from e
    elif sys.platform.startswith("linux"):
        # On genuine Linux, /proc namespace files are expected
        raise UnsupportedPlatformError(
            "Host network namespace authority cannot be established: /proc netns files missing or inaccessible. "
            "Failing closed."
        )


def get_egress_enforcer(
    environment: str = "development",
    *,
    force_linux_provider: bool = False,
    check_kernel_capabilities: bool = True,
) -> EgressEnforcerInterface:
    """
    Factory for obtaining the appropriate egress enforcer provider.
    """
    if not environment or not isinstance(environment, str) or not environment.strip():
        raise UnsupportedPlatformError(f"Environment must be a non-empty string, got {environment!r}")

    env_clean = environment.strip().lower()

    if env_clean == "production" or force_linux_provider:
        if not sys.platform.startswith("linux"):
            raise UnsupportedPlatformError(
                f"Production execution requires genuine Linux kernel iptables egress filtering. "
                f"Current host platform '{sys.platform}' is unsupported for production enforcement."
            )

        iptables_path = shutil.which("iptables")
        ip6tables_path = shutil.which("ip6tables")

        if not iptables_path or not ip6tables_path:
            raise UnsupportedPlatformError(
                f"Production egress enforcement requires 'iptables' and 'ip6tables' binaries on PATH. "
                f"Found iptables={iptables_path}, ip6tables={ip6tables_path}. Failing closed."
            )

        if check_kernel_capabilities:
            _verify_host_netfilter_authority(iptables_path, ip6tables_path)

        return LinuxIptablesEgressEnforcer(
            iptables_bin=iptables_path,
            ip6tables_bin=ip6tables_path,
        )

    if env_clean in ("development", "dev", "test"):
        return DevelopmentEgressEnforcer()

    raise UnsupportedPlatformError(
        f"Unsupported execution environment '{environment}'. Cannot select egress enforcer."
    )
