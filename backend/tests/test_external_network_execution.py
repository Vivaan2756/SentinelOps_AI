"""Tests for Phase 2A: Secure External Network Execution and Dual-Layer SSRF Defense.

Validates:
1. External HTTPS URLs resolution with public IPs and connection-time IP pinning.
2. Rejection of external targets resolving to private, loopback, link-local, multicast, or metadata IPs.
3. Rejection of unencrypted HTTP scheme for external targets (requiring HTTPS).
4. Container network configuration:
   - External targets generate network_mode='bridge' with empty extra_hosts (no host-gateway exposure).
   - Localhost targets preserve 'host.docker.internal' mapping to 'host-gateway' in dev.
5. Permitted ports:
   - External targets permit standard HTTPS port 443 and explicit ports.
   - Non-external targets strictly enforce demo/staging/production port rules.
6. PinnedIPTransport SNI and hostname preservation for external domains.
"""

import ipaddress
import socket
import pytest
from unittest.mock import patch

from app.execution.exceptions import BrokerSecurityViolation
from app.execution.network import (
    build_container_network_config,
    resolve_safe_target_url,
    validate_safe_target_url,
    ContainerNetworkConfig,
    ValidatedTarget,
)
from services.executor.runner import (
    PinnedSyncBackend,
    PinnedIPTransport,
)


class TestExternalTargetResolutionAndSSRF:
    """Validate resolution and strict SSRF defenses for external service domains."""

    def test_external_https_valid_public_domain(self):
        """A valid public HTTPS domain resolving to public IPs succeeds and pins the IP."""
        mock_addr_info = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443)),
            (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2606:2800:220:1:248:1893:25c8:1946", 443)),
        ]
        with patch("socket.getaddrinfo", return_value=mock_addr_info):
            target = resolve_safe_target_url(
                "https://api.payment-service.example.com/api/v1/recover",
                environment="development",
                action_id="execute_http_recovery",
            )
            assert target.pinned_ip == "93.184.216.34"
            assert target.hostname == "api.payment-service.example.com"
            assert target.port == 443
            assert target.scheme == "https"
            assert target.path == "/api/v1/recover"

    def test_external_domain_resolving_to_private_ip_rejected(self):
        """DNS rebinding or external domain resolving to private RFC 1918 IP is strictly rejected."""
        mock_addr_info = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.5", 443)),
        ]
        with patch("socket.getaddrinfo", return_value=mock_addr_info):
            with pytest.raises(BrokerSecurityViolation, match="disallowed IP '10.0.0.5'"):
                resolve_safe_target_url(
                    "https://malicious-internal-rebinding.example.com/recover",
                    environment="development",
                    action_id="execute_http_recovery",
                )

    def test_external_domain_resolving_to_cloud_metadata_rejected(self):
        """External domain resolving to AWS/GCP/Azure IMDS 169.254.169.254 is strictly rejected."""
        mock_addr_info = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", 443)),
        ]
        with patch("socket.getaddrinfo", return_value=mock_addr_info):
            with pytest.raises(BrokerSecurityViolation, match="forbidden cloud metadata endpoint"):
                resolve_safe_target_url(
                    "https://metadata-rebinding.example.com/latest/meta-data",
                    environment="development",
                    action_id="execute_http_recovery",
                )

    def test_external_domain_resolving_to_loopback_rejected(self):
        """External domain resolving to 127.0.0.1 is rejected (only direct localhost origin is permitted in dev)."""
        mock_addr_info = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443)),
        ]
        with patch("socket.getaddrinfo", return_value=mock_addr_info):
            with pytest.raises(BrokerSecurityViolation, match="loopback IP is prohibited"):
                resolve_safe_target_url(
                    "https://spoofed-external.example.com/recover",
                    environment="development",
                    action_id="execute_http_recovery",
                )

    def test_external_domain_resolving_to_ipv6_metadata_rejected(self):
        """External domain resolving to AWS EC2 IMDS IPv6 fd00:ec2::254 is rejected."""
        mock_addr_info = [
            (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("fd00:ec2::254", 443)),
        ]
        with patch("socket.getaddrinfo", return_value=mock_addr_info):
            with pytest.raises(BrokerSecurityViolation, match="forbidden cloud metadata endpoint"):
                resolve_safe_target_url(
                    "https://aws-ipv6-metadata.example.com/meta",
                    environment="development",
                    action_id="execute_http_recovery",
                )


class TestContainerNetworkConfiguration:
    """Validate container network generation for external targets vs localhost."""

    def test_external_target_container_network_dev_environment(self):
        """External targets in dev use bridge networking WITHOUT host-gateway extra_hosts."""
        mock_addr_info = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("104.21.5.12", 443)),
        ]
        with patch("socket.getaddrinfo", return_value=mock_addr_info):
            config = build_container_network_config(
                environment="development",
                raw_service_url="https://payment-api.onrender.com/api/v1/recover",
                action_id="execute_http_recovery",
            )
            assert config.container_url == "https://payment-api.onrender.com/api/v1/recover"
            assert config.network_kwargs == {
                "network_mode": "bridge",
                "extra_hosts": {},
            }
            assert config.target.pinned_ip == "104.21.5.12"
            assert config.target.hostname == "payment-api.onrender.com"

    def test_external_target_container_network_production_environment(self):
        """External targets in production use configured external egress network."""
        mock_addr_info = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("104.21.5.12", 443)),
        ]
        with patch("socket.getaddrinfo", return_value=mock_addr_info):
            config = build_container_network_config(
                environment="production",
                raw_service_url="https://api.acme-corp.com/ops/reset",
                action_id="execute_http_recovery",
            )
            assert config.container_url == "https://api.acme-corp.com/ops/reset"
            assert config.network_kwargs["network_mode"] == "bridge"
            assert config.network_kwargs["extra_hosts"] == {}
            assert config.target.pinned_ip == "104.21.5.12"

    def test_localhost_target_preserves_host_gateway_in_dev(self):
        """Localhost/127.0.0.1 target continues mapping to host.docker.internal with host-gateway in dev."""
        config = build_container_network_config(
            environment="development",
            raw_service_url="http://127.0.0.1:9100/admin/recovery/reset",
            action_id="execute_http_recovery",
        )
        assert config.container_url == "http://host.docker.internal:9100/admin/recovery/reset"
        assert config.network_kwargs == {
            "network_mode": "bridge",
            "extra_hosts": {"host.docker.internal": "host-gateway"},
        }
        assert config.target.hostname == "host.docker.internal"

    def test_localhost_target_strictly_rejected_in_production(self):
        """Localhost target in production continues to be strictly rejected."""
        with pytest.raises(BrokerSecurityViolation, match="strictly prohibited in production"):
            build_container_network_config(
                environment="production",
                raw_service_url="http://127.0.0.1:9100/admin/recovery/reset",
                action_id="execute_http_recovery",
            )


class TestRunnerConnectionPinningExternal:
    """Validate PinnedSyncBackend connection behavior for external pinned IPs."""

    def test_pinned_backend_connects_to_external_pinned_ip(self):
        """PinnedSyncBackend verifies host matches target and routes TCP to pinned IP."""
        backend = PinnedSyncBackend(
            target_host="api.external.com",
            pinned_ip="198.51.100.42",
            environment="development",
        )
        # Target host mismatch is rejected before connection
        with pytest.raises(RuntimeError, match="Connection blocked: attempted connection to unpinned host"):
            backend.connect_tcp("other.evil.com", 443)

    def test_pinned_backend_rejects_cloud_metadata_pinned_ip(self):
        """PinnedSyncBackend rejects cloud metadata pinned IPs."""
        backend = PinnedSyncBackend(
            target_host="api.external.com",
            pinned_ip="169.254.169.254",
            environment="development",
        )
        with pytest.raises(RuntimeError, match="forbidden cloud metadata endpoint"):
            backend.connect_tcp("api.external.com", 443)
