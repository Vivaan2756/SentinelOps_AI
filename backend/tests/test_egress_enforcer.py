"""Unit and Adversarial Test Suite for Egress Enforcer Core (Phase 2A.1 Stage 7.1.3).

Comprehensive adversarial coverage for Stage 7.1.3 corrections:
Group 1: Packet Routing & Dual Hooks (AUD-7.1.1-01, SEC-7.1.2-01)
  1. Outbound packet enters the execution chain (-s).
  2. Return packet enters the execution chain (-d).
  3. Return packet from authorized IP and port accepted.
  4. Return packet from unauthorized IP dropped.
  5. Return packet from unauthorized source port dropped.
  6. Unsolicited inbound packet dropped.
  7. Both parent hooks installed and removed correctly.
  8. Partial installation rolls back safely without re-entrancy deadlock.
  9. Rollback under simulated Linux flock semantics executes without deadlock (SEC-7.1.2-01).
  10. Rollback failure is surfaced as UnsafeFirewallStateError.

Group 2: ICMP & Path MTU Discovery (AUD-7.1.1-02)
  11. IPv4 RELATED Fragmentation Needed from intermediate router permitted.
  12. Unrelated IPv4 ICMP denied.
  13. IPv6 RELATED Packet Too Big handled correctly.
  14. Unrelated IPv6 ICMPv6 denied.

Group 3: Essential IPv6 Neighbor Discovery in INPUT (SEC-7.1.2-02)
  15. IPv6 Neighbor Solicitation (type 135) accepted before host isolation DROP.
  16. IPv6 Neighbor Advertisement (type 136) accepted before host isolation DROP.
  17. Unrelated ICMPv6 types denied in host isolation sub-chain.
  18. IPv4 host isolation chain remains DROP-only without ICMP rules.

Group 4: Hardened Host Namespace Authority (AUD-7.1.1-03, SEC-7.1.2-03)
  19. Container marker file /.dockerenv fails closed.
  20. Container marker file /run/.containerenv fails closed.
  21. Container cgroup signature in /proc/self/cgroup fails closed.
  22. Non-host PID 1 process name in /proc/1/comm fails closed.
  23. Bridge interface presence inside container does NOT bypass container detection.
  24. Inode mismatch between /proc/self/ns/net and /proc/1/ns/net fails closed.
  25. Factory never reports enforcing status from isolated namespace.
  26. Development mode remains explicitly non-enforcing.

Group 5: Deterministic Lock Path & Cross-Process Concurrency (AUD-7.1.1-04, SEC-7.1.2-04)
  27. Default lock path resolves to /var/run/sentinelops/firewall.lock.
  28. SENTINELOPS_FIREWALL_LOCK_PATH environment variable overrides lock path.
  29. Relative lock path is rejected.
  30. Empty or whitespace lock path is rejected.
  31. Missing parent directory fails closed.
  32. Parent directory symlink fails closed.
  33. Lock file symlink fails closed.
  34. Non-regular file descriptor fails closed.
  35. Cross-process lock serializes multi-command transactions.
  36. Reconciliation cannot delete empty chain during active installation.
  37. Process termination during installation leaves recoverable state.
  38. Reconciliation preserves uncertain executions.
  39. Lock acquisition failure fails closed.

Group 6: Destination Validation & Cloud Metadata Rejection (AUD-7.1.1-05)
  40. Alibaba metadata IPv4 rejected.
  41. AWS IPv6 metadata rejected.
  42. CGNAT and IPv6 ULA destinations rejected.
  43. IPv4-mapped IPv6 prohibited destinations rejected.
"""

import ipaddress
import os
import shlex
import stat
import subprocess
import tempfile
import threading
from unittest.mock import MagicMock, call, mock_open, patch

import pytest

from app.execution.egress_enforcer import (
    COMMENT_PREFIX,
    DEFAULT_FIREWALL_LOCK_PATH,
    DevelopmentEgressEnforcer,
    EgressEnforcerInterface,
    FirewallCommandError,
    FirewallVerificationError,
    InvalidRuleConfigurationError,
    LinuxIptablesEgressEnforcer,
    RuleCleanupResult,
    RuleInstallationResult,
    RuleVerificationResult,
    StaleReconciliationResult,
    UnsafeFirewallStateError,
    UnsupportedPlatformError,
    _CrossProcessLock,
    _execution_chain_name,
    _extract_exact_comment,
    _is_container_environment,
    _verify_host_netfilter_authority,
    get_egress_enforcer,
    resolve_firewall_lock_path,
)


class SimulatedLinuxFlock:
    """
    Simulate Linux kernel flock semantics:
    flock locks are tied to the open file description (struct file).
    A second open fd attempting LOCK_EX raises BlockingIOError.
    """

    def __init__(self):
        self.active_locks = set()
        self.LOCK_EX = 2
        self.LOCK_NB = 4
        self.LOCK_UN = 8

    def flock(self, fd, op):
        if op & self.LOCK_UN:
            self.active_locks.discard(fd)
            return
        if op & self.LOCK_EX:
            other_locks = [f for f in self.active_locks if f != fd]
            if other_locks:
                raise BlockingIOError("Resource temporarily unavailable (simulated Linux flock)")
            self.active_locks.add(fd)


# ============================================================================
# Group 1: Packet Routing & Dual Hooks (Tests 1-10: AUD-7.1.1-01, SEC-7.1.2-01)
# ============================================================================


class TestPacketRoutingAndDualHooks:
    """Tests 1 through 10: Packet routing, dual parent jump hooks, and safe rollback."""

    def test_outbound_packet_enters_execution_chain(self, tmp_path):
        """Scenario 1: Outbound packet with SRC = container_ip matches parent hook and enters subchain."""
        enforcer = LinuxIptablesEgressEnforcer(lock_path=str(tmp_path / "test.lock"))
        cmds, so_f, _ = enforcer.build_iptables_commands_for_family(
            execution_id="exec-route-1",
            sources=[ipaddress.IPv4Address("172.17.0.2")],
            dest_ip=ipaddress.IPv4Address("93.184.216.34"),
            dest_port=443,
            family=4,
        )

        outbound_hook = [
            "iptables", "-w", "5",
            "-I", "DOCKER-USER", "1",
            "-s", "172.17.0.2",
            "-m", "comment", "--comment", "sentinelops-exec-exec-route-1",
            "-j", so_f,
        ]
        assert outbound_hook in cmds

    def test_return_packet_enters_execution_chain(self, tmp_path):
        """Scenario 2: Inbound return packet with DST = container_ip matches parent hook and enters subchain (AUD-7.1.1-01)."""
        enforcer = LinuxIptablesEgressEnforcer(lock_path=str(tmp_path / "test.lock"))
        cmds, so_f, _ = enforcer.build_iptables_commands_for_family(
            execution_id="exec-route-2",
            sources=[ipaddress.IPv4Address("172.17.0.2")],
            dest_ip=ipaddress.IPv4Address("93.184.216.34"),
            dest_port=443,
            family=4,
        )

        inbound_hook = [
            "iptables", "-w", "5",
            "-I", "DOCKER-USER", "1",
            "-d", "172.17.0.2",
            "-m", "comment", "--comment", "sentinelops-exec-exec-route-2",
            "-j", so_f,
        ]
        assert inbound_hook in cmds

    def test_return_packet_from_authorized_ip_and_port_accepted(self, tmp_path):
        """Scenario 3: Return packet matching exact server IP, server port, and ESTABLISHED is accepted."""
        enforcer = LinuxIptablesEgressEnforcer(lock_path=str(tmp_path / "test.lock"))
        cmds, so_f, _ = enforcer.build_iptables_commands_for_family(
            execution_id="exec-route-3",
            sources=[ipaddress.IPv4Address("172.17.0.2")],
            dest_ip=ipaddress.IPv4Address("93.184.216.34"),
            dest_port=443,
            family=4,
        )

        expected_return_rule = [
            "iptables", "-w", "5",
            "-A", so_f,
            "-d", "172.17.0.2",
            "-s", "93.184.216.34",
            "-p", "tcp",
            "--sport", "443",
            "-m", "conntrack", "--ctstate", "ESTABLISHED",
            "-m", "comment", "--comment", "sentinelops-exec-exec-route-3",
            "-j", "ACCEPT",
        ]
        assert expected_return_rule in cmds

    def test_return_packet_from_unauthorized_ip_dropped(self, tmp_path):
        """Scenario 4: Return packet with DST = container_ip but wrong SRC fails Rule 2 and hits final DROP."""
        enforcer = LinuxIptablesEgressEnforcer(lock_path=str(tmp_path / "test.lock"))
        cmds, so_f, _ = enforcer.build_iptables_commands_for_family(
            execution_id="exec-route-4",
            sources=[ipaddress.IPv4Address("172.17.0.2")],
            dest_ip=ipaddress.IPv4Address("93.184.216.34"),
            dest_port=443,
            family=4,
        )

        final_drop = [
            "iptables", "-w", "5",
            "-A", so_f,
            "-m", "comment", "--comment", "sentinelops-exec-exec-route-4",
            "-j", "DROP",
        ]
        so_f_rules = [c for c in cmds if "-A" in c and so_f in c]
        assert so_f_rules[-1] == final_drop

    def test_return_packet_from_unauthorized_source_port_dropped(self, tmp_path):
        """Scenario 5: Return packet with DST = container_ip and correct SRC but wrong port fails Rule 2."""
        enforcer = LinuxIptablesEgressEnforcer(lock_path=str(tmp_path / "test.lock"))
        cmds, so_f, _ = enforcer.build_iptables_commands_for_family(
            execution_id="exec-route-5",
            sources=[ipaddress.IPv4Address("172.17.0.2")],
            dest_ip=ipaddress.IPv4Address("93.184.216.34"),
            dest_port=443,
            family=4,
        )

        return_rules = [c for c in cmds if "-A" in c and so_f in c and "--sport" in c]
        assert len(return_rules) == 1
        assert "--sport" in return_rules[0]
        assert return_rules[0][return_rules[0].index("--sport") + 1] == "443"

    def test_unsolicited_inbound_packet_dropped(self, tmp_path):
        """Scenario 6: Inbound unsolicited packet (ctstate NEW) enters subchain via hook 2 and is dropped."""
        enforcer = LinuxIptablesEgressEnforcer(lock_path=str(tmp_path / "test.lock"))
        cmds, so_f, _ = enforcer.build_iptables_commands_for_family(
            execution_id="exec-route-6",
            sources=[ipaddress.IPv4Address("172.17.0.2")],
            dest_ip=ipaddress.IPv4Address("93.184.216.34"),
            dest_port=443,
            family=4,
        )

        accept_rules = [c for c in cmds if "-A" in c and so_f in c and "-j" in c and c[c.index("-j") + 1] == "ACCEPT"]
        for r in accept_rules:
            if "-d" in r and r[r.index("-d") + 1] == "172.17.0.2":
                assert "ESTABLISHED" in r or "RELATED" in r
                assert "NEW" not in r

    @patch("subprocess.run")
    def test_both_parent_hooks_installed_and_removed_correctly(self, mock_run, tmp_path):
        """Scenario 7: Both outbound (-s) and inbound (-d) hooks are installed and removed."""
        exec_id = "exec-dual-hooks"
        comment = f"{COMMENT_PREFIX}{exec_id}"
        so_f = _execution_chain_name("SO-F", exec_id)
        so_i = _execution_chain_name("SO-I", exec_id)

        sample_table = (
            f"-A DOCKER-USER -s 172.17.0.2/32 -m comment --comment {comment} -j {so_f}\n"
            f"-A DOCKER-USER -d 172.17.0.2/32 -m comment --comment {comment} -j {so_f}\n"
            f"-A INPUT -s 172.17.0.2/32 -m comment --comment {comment} -j {so_i}\n"
        ).encode("utf-8")

        executed_cmds = []
        rules_deleted = False

        def side_effect(cmd, **kwargs):
            nonlocal rules_deleted
            executed_cmds.append(cmd)
            if "-S" in cmd:
                if not rules_deleted:
                    return subprocess.CompletedProcess(args=cmd, returncode=0, stdout=sample_table, stderr=b"")
                return subprocess.CompletedProcess(args=cmd, returncode=0, stdout=b"", stderr=b"")
            if "-D" in cmd:
                rules_deleted = True
                return subprocess.CompletedProcess(args=cmd, returncode=0, stdout=b"", stderr=b"")
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout=b"", stderr=b"")

        mock_run.side_effect = side_effect

        enforcer = LinuxIptablesEgressEnforcer(lock_path=str(tmp_path / "test_so_lock.lock"))
        res = enforcer.cleanup_egress_rules(execution_id=exec_id)

        assert res.is_fully_cleaned is True
        delete_cmds = [cmd for cmd in executed_cmds if "-D" in cmd]
        assert len(delete_cmds) == 3
        assert any("-s" in c and "DOCKER-USER" in c for c in delete_cmds)
        assert any("-d" in c and "DOCKER-USER" in c for c in delete_cmds)
        assert any("INPUT" in c for c in delete_cmds)

    @patch("subprocess.run")
    def test_partial_installation_of_two_hooks_rolls_back_safely(self, mock_run, tmp_path):
        """Scenario 8: If failure occurs after first hook, both hooks and subchains are rolled back."""
        call_count = 0

        def side_effect(cmd, **kwargs):
            nonlocal call_count
            call_count += 1
            if "-I" in cmd and call_count > 6:
                return subprocess.CompletedProcess(args=cmd, returncode=1, stdout=b"", stderr=b"Hook failure")
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout=b"", stderr=b"")

        mock_run.side_effect = side_effect

        enforcer = LinuxIptablesEgressEnforcer(lock_path=str(tmp_path / "test_so_lock.lock"))
        with pytest.raises(FirewallCommandError) as exc_info:
            enforcer.install_egress_rules(
                execution_id="exec-partial-hooks",
                source_ips=["172.17.0.2"],
                destination_ip="93.184.216.34",
                destination_port=443,
                ipv6_enabled=False,
            )
        assert "rolled back successfully" in str(exc_info.value).lower()

    @patch("subprocess.run")
    def test_rollback_under_real_flock_semantics_does_not_deadlock(self, mock_run, tmp_path):
        """Scenario 9 (SEC-7.1.2-01): Rollback under strict flock mutual exclusion completes without deadlock."""
        sim_flock = SimulatedLinuxFlock()
        call_count = 0

        def side_effect(cmd, **kwargs):
            nonlocal call_count
            call_count += 1
            if "-I" in cmd and call_count > 5:
                return subprocess.CompletedProcess(args=cmd, returncode=1, stdout=b"", stderr=b"IPTables error")
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout=b"", stderr=b"")

        mock_run.side_effect = side_effect

        with patch.dict("sys.modules", {"fcntl": sim_flock}):
            enforcer = LinuxIptablesEgressEnforcer(lock_path=str(tmp_path / "flock_deadlock_test.lock"))
            with pytest.raises(FirewallCommandError) as exc_info:
                enforcer.install_egress_rules(
                    execution_id="exec-flock-safe",
                    source_ips=["172.17.0.2"],
                    destination_ip="93.184.216.34",
                    destination_port=443,
                    ipv6_enabled=False,
                )
            assert "rolled back successfully" in str(exc_info.value).lower()

    @patch("subprocess.run")
    def test_rollback_failure_surfaced_as_unsafe_firewall_state(self, mock_run, tmp_path):
        """Scenario 10 (SEC-7.1.2-01): If rollback cleanup fails to remove all rules, UnsafeFirewallStateError is raised."""
        call_count = 0

        def side_effect(cmd, **kwargs):
            nonlocal call_count
            call_count += 1
            if "-I" in cmd and call_count > 5:
                return subprocess.CompletedProcess(args=cmd, returncode=1, stdout=b"", stderr=b"Install error")
            if "-F" in cmd or "-X" in cmd:
                return subprocess.CompletedProcess(args=cmd, returncode=1, stdout=b"", stderr=b"Flush error")
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout=b"", stderr=b"")

        mock_run.side_effect = side_effect

        enforcer = LinuxIptablesEgressEnforcer(lock_path=str(tmp_path / "rollback_fail.lock"))
        with pytest.raises(UnsafeFirewallStateError) as exc_info:
            enforcer.install_egress_rules(
                execution_id="exec-rollback-fail",
                source_ips=["172.17.0.2"],
                destination_ip="93.184.216.34",
                destination_port=443,
                ipv6_enabled=False,
            )
        assert "uncertain" in str(exc_info.value).lower()


# ============================================================================
# Group 2: ICMP & Path MTU Discovery (Tests 11-14: AUD-7.1.1-02)
# ============================================================================


class TestIcmpAndPathMtuDiscovery:
    """Tests 11 through 14: ICMP error handling and Path MTU Discovery."""

    def test_ipv4_related_fragmentation_needed_from_intermediate_router_permitted(self, tmp_path):
        """Scenario 11: IPv4 RELATED ICMP does NOT constrain source IP to destination server (AUD-7.1.1-02)."""
        enforcer = LinuxIptablesEgressEnforcer(lock_path=str(tmp_path / "test.lock"))
        cmds, so_f, _ = enforcer.build_iptables_commands_for_family(
            execution_id="exec-icmp-pmtu",
            sources=[ipaddress.IPv4Address("172.17.0.2")],
            dest_ip=ipaddress.IPv4Address("93.184.216.34"),
            dest_port=443,
            family=4,
        )

        icmp_rules = [c for c in cmds if "-p" in c and "icmp" in c]
        assert len(icmp_rules) == 1
        rule = icmp_rules[0]

        assert "-s" not in rule
        assert "-d" in rule and rule[rule.index("-d") + 1] == "172.17.0.2"
        assert "--ctstate" in rule and rule[rule.index("--ctstate") + 1] == "RELATED"
        assert "-j" in rule and rule[rule.index("-j") + 1] == "ACCEPT"

    def test_unrelated_ipv4_icmp_denied(self, tmp_path):
        """Scenario 12: Unrelated IPv4 ICMP (ping / scan) lacks RELATED state and hits default DROP."""
        enforcer = LinuxIptablesEgressEnforcer(lock_path=str(tmp_path / "test.lock"))
        cmds, so_f, _ = enforcer.build_iptables_commands_for_family(
            execution_id="exec-icmp-unrelated",
            sources=[ipaddress.IPv4Address("172.17.0.2")],
            dest_ip=ipaddress.IPv4Address("93.184.216.34"),
            dest_port=443,
            family=4,
        )

        so_f_rules = [c for c in cmds if "-A" in c and so_f in c]
        assert so_f_rules[-1][-1] == "DROP"

    def test_ipv6_related_packet_too_big_handled_correctly(self, tmp_path):
        """Scenario 13: IPv6 RELATED Packet Too Big uses ipv6-icmp without source IP restriction."""
        enforcer = LinuxIptablesEgressEnforcer(lock_path=str(tmp_path / "test.lock"))
        cmds, so_f, _ = enforcer.build_iptables_commands_for_family(
            execution_id="exec-icmpv6-pmtu",
            sources=[ipaddress.IPv6Address("2001:db8::2")],
            dest_ip=ipaddress.IPv6Address("2606:2800:220:1:248:1893:25c8:1946"),
            dest_port=443,
            family=6,
        )

        icmpv6_rules = [c for c in cmds if "-p" in c and "ipv6-icmp" in c and so_f in c]
        assert len(icmpv6_rules) == 1
        rule = icmpv6_rules[0]

        assert "-s" not in rule
        assert "-d" in rule and rule[rule.index("-d") + 1] == "2001:db8::2"
        assert "--ctstate" in rule and rule[rule.index("--ctstate") + 1] == "RELATED"

    def test_unrelated_ipv6_icmpv6_denied(self, tmp_path):
        """Scenario 14: Unrelated IPv6 ICMPv6 is denied by default DROP."""
        enforcer = LinuxIptablesEgressEnforcer(lock_path=str(tmp_path / "test.lock"))
        cmds, so_f, _ = enforcer.build_iptables_commands_for_family(
            execution_id="exec-icmpv6-unrel",
            sources=[ipaddress.IPv6Address("2001:db8::2")],
            dest_ip=ipaddress.IPv6Address("2606:2800:220:1:248:1893:25c8:1946"),
            dest_port=443,
            family=6,
        )

        so_f_rules = [c for c in cmds if "-A" in c and so_f in c]
        assert so_f_rules[-1][-1] == "DROP"


# ============================================================================
# Group 3: Essential IPv6 Neighbor Discovery (Tests 15-18: SEC-7.1.2-02)
# ============================================================================


class TestIPv6NeighborDiscoveryInHostIsolation:
    """Tests 15 through 18: ICMPv6 Neighbor Discovery preservation in INPUT subchain (SEC-7.1.2-02)."""

    def test_ipv6_neighbor_solicitation_accepted_before_drop(self, tmp_path):
        """Scenario 15: ICMPv6 Neighbor Solicitation (type 135) is accepted before host-isolation DROP."""
        enforcer = LinuxIptablesEgressEnforcer(lock_path=str(tmp_path / "test.lock"))
        cmds, _, so_i = enforcer.build_iptables_commands_for_family(
            execution_id="exec-ipv6-nd-ns",
            sources=[ipaddress.IPv6Address("2001:db8::2")],
            dest_ip=ipaddress.IPv6Address("2606:2800:220:1:248:1893:25c8:1946"),
            dest_port=443,
            family=6,
        )

        so_i_rules = [c for c in cmds if "-A" in c and so_i in c]
        ns_rules = [c for c in so_i_rules if "--icmpv6-type" in c and "135" in c]
        assert len(ns_rules) == 1
        rule = ns_rules[0]
        assert "-s" in rule and rule[rule.index("-s") + 1] == "2001:db8::2"
        assert "-p" in rule and rule[rule.index("-p") + 1] == "ipv6-icmp"
        assert "-j" in rule and rule[rule.index("-j") + 1] == "ACCEPT"

        # Ensure NS rule precedes the final DROP rule
        assert so_i_rules.index(rule) < len(so_i_rules) - 1

    def test_ipv6_neighbor_advertisement_accepted_before_drop(self, tmp_path):
        """Scenario 16: ICMPv6 Neighbor Advertisement (type 136) is accepted before host-isolation DROP."""
        enforcer = LinuxIptablesEgressEnforcer(lock_path=str(tmp_path / "test.lock"))
        cmds, _, so_i = enforcer.build_iptables_commands_for_family(
            execution_id="exec-ipv6-nd-na",
            sources=[ipaddress.IPv6Address("2001:db8::2")],
            dest_ip=ipaddress.IPv6Address("2606:2800:220:1:248:1893:25c8:1946"),
            dest_port=443,
            family=6,
        )

        so_i_rules = [c for c in cmds if "-A" in c and so_i in c]
        na_rules = [c for c in so_i_rules if "--icmpv6-type" in c and "136" in c]
        assert len(na_rules) == 1
        rule = na_rules[0]
        assert "-s" in rule and rule[rule.index("-s") + 1] == "2001:db8::2"
        assert "-j" in rule and rule[rule.index("-j") + 1] == "ACCEPT"
        assert so_i_rules.index(rule) < len(so_i_rules) - 1

    def test_unrelated_icmpv6_denied_in_input_chain(self, tmp_path):
        """Scenario 17: Other ICMPv6 types (echo 128, RS 133, redirect 137) are NOT accepted in SO-I."""
        enforcer = LinuxIptablesEgressEnforcer(lock_path=str(tmp_path / "test.lock"))
        cmds, _, so_i = enforcer.build_iptables_commands_for_family(
            execution_id="exec-ipv6-nd-other",
            sources=[ipaddress.IPv6Address("2001:db8::2")],
            dest_ip=ipaddress.IPv6Address("2606:2800:220:1:248:1893:25c8:1946"),
            dest_port=443,
            family=6,
        )

        so_i_rules = [c for c in cmds if "-A" in c and so_i in c]
        # Only type 135 and 136 are accepted; final rule is DROP
        accepted_types = [c[c.index("--icmpv6-type") + 1] for c in so_i_rules if "--icmpv6-type" in c]
        assert set(accepted_types) == {"135", "136"}
        assert so_i_rules[-1][-1] == "DROP"

    def test_ipv4_host_isolation_chain_remains_drop_only(self, tmp_path):
        """Scenario 18: IPv4 host isolation in SO-I has NO ICMP rules, only unconditional DROP (ARP is L2)."""
        enforcer = LinuxIptablesEgressEnforcer(lock_path=str(tmp_path / "test.lock"))
        cmds, _, so_i = enforcer.build_iptables_commands_for_family(
            execution_id="exec-ipv4-input-drop",
            sources=[ipaddress.IPv4Address("172.17.0.2")],
            dest_ip=ipaddress.IPv4Address("93.184.216.34"),
            dest_port=443,
            family=4,
        )

        so_i_rules = [c for c in cmds if "-A" in c and so_i in c]
        assert len(so_i_rules) == 1
        assert so_i_rules[0][-1] == "DROP"
        assert "-p" not in so_i_rules[0]


# ============================================================================
# Group 4: Hardened Host Namespace Authority (Tests 19-26: AUD-7.1.1-03, SEC-7.1.2-03)
# ============================================================================


class TestNamespaceAuthority:
    """Tests 19 through 26: Hardened host network namespace authority validation (SEC-7.1.2-03)."""

    @patch("os.path.exists")
    @patch("subprocess.run")
    def test_container_marker_dockerenv_fails_closed(self, mock_run, mock_exists):
        """Scenario 19: Presence of /.dockerenv causes authority verification to fail closed."""
        mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0, stdout=b"", stderr=b"")
        mock_exists.side_effect = lambda path: path == "/.dockerenv"

        with pytest.raises(UnsupportedPlatformError) as exc_info:
            _verify_host_netfilter_authority("/sbin/iptables", "/sbin/ip6tables")

        assert "containerized execution environment detected" in str(exc_info.value).lower()

    @patch("os.path.exists")
    @patch("subprocess.run")
    def test_container_marker_containerenv_fails_closed(self, mock_run, mock_exists):
        """Scenario 20: Presence of /run/.containerenv causes authority verification to fail closed."""
        mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0, stdout=b"", stderr=b"")
        mock_exists.side_effect = lambda path: path == "/run/.containerenv"

        with pytest.raises(UnsupportedPlatformError) as exc_info:
            _verify_host_netfilter_authority("/sbin/iptables", "/sbin/ip6tables")

        assert "containerized execution environment detected" in str(exc_info.value).lower()

    @patch("os.path.exists")
    @patch("builtins.open", new_callable=mock_open, read_data="1:name=systemd:/docker/c5a1d0f8...")
    @patch("subprocess.run")
    def test_container_cgroup_signature_fails_closed(self, mock_run, mock_file, mock_exists):
        """Scenario 21: Container cgroup signature in /proc/self/cgroup fails closed."""
        mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0, stdout=b"", stderr=b"")
        mock_exists.side_effect = lambda path: path in ("/proc/self/cgroup", "/proc/1/cgroup")

        with pytest.raises(UnsupportedPlatformError) as exc_info:
            _verify_host_netfilter_authority("/sbin/iptables", "/sbin/ip6tables")

        assert "container cgroup signature" in str(exc_info.value).lower()

    @patch("os.path.exists")
    @patch("builtins.open", new_callable=mock_open, read_data="python\n")
    @patch("subprocess.run")
    def test_container_pid1_process_name_fails_closed(self, mock_run, mock_file, mock_exists):
        """Scenario 22: Non-host PID 1 comm ('python') indicates container init environment and fails closed."""
        mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0, stdout=b"", stderr=b"")
        mock_exists.side_effect = lambda path: path == "/proc/1/comm"

        with pytest.raises(UnsupportedPlatformError) as exc_info:
            _verify_host_netfilter_authority("/sbin/iptables", "/sbin/ip6tables")

        assert "container init environment" in str(exc_info.value).lower()

    @patch("os.path.exists")
    @patch("subprocess.run")
    def test_bridge_presence_inside_container_does_not_bypass_authority_check(self, mock_run, mock_exists):
        """Scenario 23: Even if docker0 or br-0 exists, containerized execution still fails closed."""
        mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0, stdout=b"", stderr=b"")
        # Both /.dockerenv AND bridge interface exist
        mock_exists.side_effect = lambda path: path in ("/.dockerenv", "/sys/class/net/docker0")

        with pytest.raises(UnsupportedPlatformError) as exc_info:
            _verify_host_netfilter_authority("/sbin/iptables", "/sbin/ip6tables")

        assert "containerized execution environment detected" in str(exc_info.value).lower()

    @patch("os.path.exists")
    @patch("os.stat")
    @patch("subprocess.run")
    def test_container_local_cap_net_admin_does_not_qualify_as_host_authority(self, mock_run, mock_stat, mock_exists):
        """Scenario 24: Inode mismatch between /proc/self/ns/net and /proc/1/ns/net fails closed."""
        mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0, stdout=b"", stderr=b"")

        # No container markers, but netns files exist and mismatch
        def exists_side_effect(path):
            if path in ("/proc/self/ns/net", "/proc/1/ns/net"):
                return True
            return False

        mock_exists.side_effect = exists_side_effect

        self_stat = MagicMock(st_ino=100)
        init_stat = MagicMock(st_ino=200)

        def stat_side_effect(path):
            if path == "/proc/self/ns/net":
                return self_stat
            return init_stat

        mock_stat.side_effect = stat_side_effect

        with pytest.raises(UnsupportedPlatformError) as exc_info:
            _verify_host_netfilter_authority("/sbin/iptables", "/sbin/ip6tables")

        assert "child network namespace" in str(exc_info.value).lower()

    @patch("sys.platform", "linux")
    @patch("shutil.which")
    @patch("app.execution.egress_enforcer._verify_host_netfilter_authority")
    def test_factory_never_reports_enforcing_status_from_isolated_namespace(self, mock_verify, mock_which):
        """Scenario 25: Factory raises UnsupportedPlatformError when host authority check fails."""
        mock_which.side_effect = lambda b: f"/sbin/{b}"
        mock_verify.side_effect = UnsupportedPlatformError("Isolated container namespace detected.")

        with pytest.raises(UnsupportedPlatformError) as exc_info:
            get_egress_enforcer("production")

        assert "isolated container namespace" in str(exc_info.value).lower()

    def test_development_mode_remains_explicitly_non_enforcing(self):
        """Scenario 26: Development provider is non-enforcing and does not require Linux authority."""
        dev = get_egress_enforcer("development")
        assert dev.is_enforcing is False
        assert dev.provider_name == "development-non-enforcing-mock"


# ============================================================================
# Group 5: Deterministic Lock Path & Cross-Process Concurrency (Tests 27-39: SEC-7.1.2-04)
# ============================================================================


class TestDeterministicLockPathAndConcurrency:
    """Tests 27 through 39: Deterministic lock path and cross-process serialization (SEC-7.1.2-04)."""

    def test_default_lock_path_resolves_to_var_run_sentinelops(self):
        """Scenario 27: Without override, lock path resolves deterministically to DEFAULT_FIREWALL_LOCK_PATH."""
        with patch.dict("os.environ", {}, clear=True):
            resolved = resolve_firewall_lock_path(None)
            assert resolved.endswith(os.path.normpath(DEFAULT_FIREWALL_LOCK_PATH)) or resolved == os.path.abspath(DEFAULT_FIREWALL_LOCK_PATH)

    def test_env_var_overrides_lock_path(self, tmp_path):
        """Scenario 28: SENTINELOPS_FIREWALL_LOCK_PATH env var overrides default lock path."""
        custom_lock = str(tmp_path / "custom.lock")
        with patch.dict("os.environ", {"SENTINELOPS_FIREWALL_LOCK_PATH": custom_lock}):
            resolved = resolve_firewall_lock_path(None)
            assert resolved == os.path.abspath(custom_lock)

    def test_relative_lock_path_rejected(self):
        """Scenario 29: Relative lock path is rejected with InvalidRuleConfigurationError."""
        with pytest.raises(InvalidRuleConfigurationError) as exc_info:
            resolve_firewall_lock_path("relative/path/firewall.lock")
        assert "absolute path" in str(exc_info.value).lower()

    def test_empty_or_whitespace_lock_path_rejected(self):
        """Scenario 30: Empty or whitespace lock path is rejected."""
        with pytest.raises(InvalidRuleConfigurationError):
            resolve_firewall_lock_path("")
        with pytest.raises(InvalidRuleConfigurationError):
            resolve_firewall_lock_path("   ")

    def test_missing_parent_directory_fails_closed(self, tmp_path):
        """Scenario 31: Missing parent directory for lock file fails closed with UnsafeFirewallStateError."""
        non_existent = str(tmp_path / "non_existent_dir" / "firewall.lock")
        with pytest.raises(UnsafeFirewallStateError) as exc_info:
            with _CrossProcessLock(non_existent):
                pass
        assert "parent directory" in str(exc_info.value).lower()
        assert "does not exist" in str(exc_info.value).lower()

    def test_parent_directory_symlink_fails_closed(self, tmp_path):
        """Scenario 32: Parent directory as symbolic link fails closed."""
        fake_parent = tmp_path / "sym_dir"
        fake_parent.mkdir()
        with patch("os.path.islink", side_effect=lambda p: str(fake_parent) in p):
            with pytest.raises(UnsafeFirewallStateError) as exc_info:
                with _CrossProcessLock(str(fake_parent / "firewall.lock")):
                    pass
        assert "symbolic link" in str(exc_info.value).lower()

    def test_lock_file_symlink_fails_closed(self, tmp_path):
        """Scenario 33: Lock file as symbolic link fails closed."""
        lock_file = str(tmp_path / "symlink.lock")
        with patch("os.path.islink", side_effect=lambda p: p == lock_file):
            with pytest.raises(UnsafeFirewallStateError) as exc_info:
                with _CrossProcessLock(lock_file):
                    pass
        assert "symbolic link" in str(exc_info.value).lower()

    def test_lock_file_not_regular_file_fails_closed(self, tmp_path):
        """Scenario 34: Opened lock file that is not a regular file (e.g. dir) fails closed."""
        lock_dir = tmp_path / "dir_as_file.lock"
        lock_dir.mkdir()
        with patch("stat.S_ISREG", return_value=False):
            with pytest.raises(UnsafeFirewallStateError) as exc_info:
                with _CrossProcessLock(str(lock_dir / "actual.lock")):
                    pass
        assert "not a regular file" in str(exc_info.value).lower()

    def test_cross_process_lock_serializes_transactions(self, tmp_path):
        """Scenario 35: _CrossProcessLock acquires and releases file lock safely."""
        lock_file = str(tmp_path / "test.lock")
        mock_fcntl = MagicMock()
        mock_fcntl.LOCK_EX = 2
        mock_fcntl.LOCK_NB = 4
        mock_fcntl.LOCK_UN = 8
        with patch.dict("sys.modules", {"fcntl": mock_fcntl}):
            with _CrossProcessLock(lock_file):
                assert os.path.exists(lock_file)
            assert mock_fcntl.flock.called

    @patch("subprocess.run")
    def test_reconciliation_cannot_delete_chain_during_installation(self, mock_run, tmp_path):
        """Scenario 36: Empty subchain matching active execution hash is NEVER deleted by reconciliation."""
        active_id = "exec-active-new"
        active_f_chain = _execution_chain_name("SO-F", active_id)

        sample_table = f"-N {active_f_chain}\n".encode("utf-8")
        deleted_chains = []

        def side_effect(cmd, **kwargs):
            if "-S" in cmd:
                return subprocess.CompletedProcess(args=cmd, returncode=0, stdout=sample_table, stderr=b"")
            if "-X" in cmd:
                deleted_chains.append(cmd)
                return subprocess.CompletedProcess(args=cmd, returncode=0, stdout=b"", stderr=b"")
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout=b"", stderr=b"")

        mock_run.side_effect = side_effect

        enforcer = LinuxIptablesEgressEnforcer(lock_path=str(tmp_path / "reconcile.lock"))
        res = enforcer.reconcile_stale_rules(active_execution_ids={active_id})

        assert len(deleted_chains) == 0
        assert active_id not in res.purged_execution_ids

    @patch("subprocess.run")
    def test_process_termination_during_installation_leaves_recoverable_state(self, mock_run, tmp_path):
        """Scenario 37: Orphaned subchain from terminated process is purged on reconciliation."""
        dead_id = "exec-crashed"
        dead_f_chain = _execution_chain_name("SO-F", dead_id)

        sample_table = f"-N {dead_f_chain}\n".encode("utf-8")
        deleted_chains = []

        def side_effect(cmd, **kwargs):
            if "-S" in cmd:
                return subprocess.CompletedProcess(args=cmd, returncode=0, stdout=sample_table, stderr=b"")
            if "-X" in cmd:
                deleted_chains.append(cmd)
                return subprocess.CompletedProcess(args=cmd, returncode=0, stdout=b"", stderr=b"")
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout=b"", stderr=b"")

        mock_run.side_effect = side_effect

        enforcer = LinuxIptablesEgressEnforcer(lock_path=str(tmp_path / "reconcile_dead.lock"))
        res = enforcer.reconcile_stale_rules(active_execution_ids=set())

        assert any(dead_f_chain in c for c in deleted_chains)

    @patch("subprocess.run")
    def test_reconciliation_preserves_uncertain_executions(self, mock_run, tmp_path):
        """Scenario 38: Chains and rules for uncertain executions are explicitly preserved."""
        unc_id = "exec-uncertain"
        unc_f_chain = _execution_chain_name("SO-F", unc_id)

        sample_table = f"-N {unc_f_chain}\n".encode("utf-8")
        deleted_chains = []

        def side_effect(cmd, **kwargs):
            if "-S" in cmd:
                return subprocess.CompletedProcess(args=cmd, returncode=0, stdout=sample_table, stderr=b"")
            if "-X" in cmd:
                deleted_chains.append(cmd)
                return subprocess.CompletedProcess(args=cmd, returncode=0, stdout=b"", stderr=b"")
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout=b"", stderr=b"")

        mock_run.side_effect = side_effect

        enforcer = LinuxIptablesEgressEnforcer(lock_path=str(tmp_path / "reconcile_unc.lock"))
        res = enforcer.reconcile_stale_rules(
            active_execution_ids=set(),
            uncertain_execution_ids={unc_id},
        )

        assert len(deleted_chains) == 0
        assert unc_id not in res.purged_execution_ids

    def test_lock_acquisition_failure_fails_closed(self, tmp_path):
        """Scenario 39: Timeout acquiring lock raises UnsafeFirewallStateError."""
        lock_file = str(tmp_path / "timeout.lock")
        mock_fcntl = MagicMock()
        mock_fcntl.LOCK_EX = 2
        mock_fcntl.LOCK_NB = 4
        mock_fcntl.flock.side_effect = BlockingIOError("Locked")

        with patch.dict("sys.modules", {"fcntl": mock_fcntl}):
            with pytest.raises(UnsafeFirewallStateError) as exc_info:
                with _CrossProcessLock(lock_file, timeout=0.05):
                    pass
            assert "failed to acquire cross-process firewall lock" in str(exc_info.value).lower()


# ============================================================================
# Group 6: Destination Validation & Cloud Metadata Rejection (Tests 40-43: AUD-7.1.1-05)
# ============================================================================


class TestDestinationValidationAndMetadataRejection:
    """Tests 40 through 43: Strict metadata, CGNAT, ULA, and mapped IP rejection."""

    def test_alibaba_metadata_ipv4_rejected(self, tmp_path):
        """Scenario 40: Alibaba Cloud metadata IP 100.100.100.200 is rejected (AUD-7.1.1-05)."""
        enforcer = LinuxIptablesEgressEnforcer(lock_path=str(tmp_path / "test.lock"))
        with pytest.raises(InvalidRuleConfigurationError) as exc_info:
            enforcer.install_egress_rules(
                execution_id="exec-meta-alibaba",
                source_ips=["172.17.0.2"],
                destination_ip="100.100.100.200",
                destination_port=80,
                ipv6_enabled=False,
            )
        assert "metadata" in str(exc_info.value).lower()

    def test_aws_ipv6_metadata_rejected(self, tmp_path):
        """Scenario 41: AWS EC2 IPv6 metadata endpoint fd00:ec2::254 is rejected."""
        enforcer = LinuxIptablesEgressEnforcer(lock_path=str(tmp_path / "test.lock"))
        with pytest.raises(InvalidRuleConfigurationError) as exc_info:
            enforcer.install_egress_rules(
                execution_id="exec-meta-aws-v6",
                source_ips=["172.17.0.2"],
                destination_ip="fd00:ec2::254",
                destination_port=80,
                ipv6_enabled=False,
            )
        assert "metadata" in str(exc_info.value).lower()

    def test_cgnat_and_ipv6_ula_destinations_rejected(self, tmp_path):
        """Scenario 42: Carrier-Grade NAT (100.64.0.0/10) and IPv6 ULA (fc00::/7) are rejected."""
        enforcer = LinuxIptablesEgressEnforcer(lock_path=str(tmp_path / "test.lock"))

        with pytest.raises(InvalidRuleConfigurationError) as exc_v4:
            enforcer.install_egress_rules(
                execution_id="exec-cgnat",
                source_ips=["172.17.0.2"],
                destination_ip="100.64.0.1",
                destination_port=443,
                ipv6_enabled=False,
            )
        assert "cgnat" in str(exc_v4.value).lower()

        with pytest.raises(InvalidRuleConfigurationError) as exc_v6:
            enforcer.install_egress_rules(
                execution_id="exec-ula",
                source_ips=["172.17.0.2"],
                destination_ip="fd12:3456:789a:1::1",
                destination_port=443,
                ipv6_enabled=False,
            )
        assert "ula" in str(exc_v6.value).lower() or "private" in str(exc_v6.value).lower()

    def test_ipv4_mapped_ipv6_prohibited_destinations_rejected(self, tmp_path):
        """Scenario 43: IPv4-mapped IPv6 prohibited addresses (e.g. ::ffff:169.254.169.254) are rejected."""
        enforcer = LinuxIptablesEgressEnforcer(lock_path=str(tmp_path / "test.lock"))

        with pytest.raises(InvalidRuleConfigurationError) as exc_meta:
            enforcer.install_egress_rules(
                execution_id="exec-mapped-meta",
                source_ips=["172.17.0.2"],
                destination_ip="::ffff:169.254.169.254",
                destination_port=80,
                ipv6_enabled=False,
            )
        assert "metadata" in str(exc_meta.value).lower()

        with pytest.raises(InvalidRuleConfigurationError) as exc_priv:
            enforcer.install_egress_rules(
                execution_id="exec-mapped-priv",
                source_ips=["172.17.0.2"],
                destination_ip="::ffff:10.0.0.1",
                destination_port=80,
                ipv6_enabled=False,
            )
        assert "private" in str(exc_priv.value).lower() or "prohibited" in str(exc_priv.value).lower()
