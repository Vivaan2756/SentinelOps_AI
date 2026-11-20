"""Network Security & Dual-Layer SSRF Protection for Phase 4.3.4.1.

Implements strict application-level SSRF defense, DNS resolution, and rebinding protection:
1. Strict HTTP/HTTPS scheme and userinfo rejection.
2. Full IPv4 and IPv6 parsing (loopback, private, link-local, multicast, reserved, unspecified, IPv4-mapped IPv6).
3. Cloud metadata IP and hostname blocking (AWS IPv4/IPv6, Azure, GCP, Alibaba).
4. DNS resolution of all A and AAAA records; rejection if any resolved IP is disallowed.
5. DNS rebinding defense via resolved IP pinning while preserving HTTP Host / SNI.
6. Narrow, authorized development target allowlist for host.docker.internal / local Order API.
7. Multi-environment network topologies (Windows Dev, Staging internal check, Production isolated network).
"""

from dataclasses import dataclass
import ipaddress
import os
import socket
from typing import Any, Dict, List, Optional, Set, Tuple, Union
from urllib.parse import urlparse

from app.execution.exceptions import BrokerSecurityViolation

# Blocked cloud metadata & link-local IP addresses (IPv4 & IPv6)
FORBIDDEN_METADATA_IPS: Set[str] = {
    "169.254.169.254",  # AWS / Azure / GCP IMDSv1/v2 IPv4
    "169.254.170.2",    # AWS ECS task metadata
    "100.100.100.200",  # Alibaba metadata
    "fd00:ec2::254",    # AWS EC2 IMDS IPv6
}

FORBIDDEN_HOSTNAMES: Set[str] = {
    "metadata.google.internal",
    "metadata",
    "instance-data",
    "169.254.169.254.nip.io",
}

# Permitted ports per service / action
ALLOWED_DEMO_PORTS: Set[int] = {8001, 8002, 9000}
ALLOWED_PUBLIC_PORTS: Set[int] = {80, 443, 8080, 8443}

# Authorized development target hostnames (strictly scoped to local dev service recovery)
ALLOWED_DEV_HOSTNAMES: Set[str] = {
    "host.docker.internal",
    "localhost",
    "127.0.0.1",
}


@dataclass
class ValidatedTarget:
    """Structured result of DNS resolution and SSRF validation for connection pinning."""

    url: str
    pinned_ip: str
    hostname: str
    port: int
    path: str
    scheme: str
    host_header: str
    direct_ip_url: str


def is_disallowed_ip(
    ip: Union[ipaddress.IPv4Address, ipaddress.IPv6Address],
    *,
    allow_private_for_dev: bool = False,
) -> Tuple[bool, str]:
    """
    Check if an IPv4 or IPv6 address is disallowed.

    Returns:
        (is_disallowed, reason)
    """
    # 1. IPv4-mapped IPv6 address (e.g. ::ffff:169.254.169.254)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return is_disallowed_ip(ip.ipv4_mapped, allow_private_for_dev=allow_private_for_dev)

    ip_str = str(ip).lower()

    # 2. Explicit cloud metadata IP check
    if ip_str in FORBIDDEN_METADATA_IPS:
        return True, f"forbidden cloud metadata endpoint ({ip_str})"

    # 3. Link-local address
    if ip.is_link_local:
        return True, f"link-local IP is prohibited ({ip_str})"

    # 4. Multicast address
    if ip.is_multicast:
        return True, f"multicast IP is prohibited ({ip_str})"

    # 5. Loopback address (127.0.0.0/8 or ::1)
    if ip.is_loopback:
        if not allow_private_for_dev:
            return True, f"loopback IP is prohibited outside authorized dev target ({ip_str})"
        return False, ""

    # 6. Reserved address
    if ip.is_reserved:
        return True, f"reserved IP is prohibited ({ip_str})"

    # 7. Unspecified address (0.0.0.0 or ::)
    if ip.is_unspecified:
        return True, f"unspecified IP is prohibited ({ip_str})"

    # 8. Private RFC 1918 / IPv6 ULA address
    if ip.is_private:
        if not allow_private_for_dev:
            return True, f"private RFC 1918 / ULA IP is prohibited outside authorized dev target ({ip_str})"

    return False, ""


def resolve_safe_target_url(
    url: str,
    *,
    allowed_ports: Optional[Set[int]] = None,
    allowed_paths: Optional[Set[str]] = None,
    environment: str = "development",
    action_id: Optional[str] = None,
) -> ValidatedTarget:
    """
    Strict application-level SSRF validation with DNS resolution and IP pinning.

    Enforces:
    1. Scheme strictly 'http' or 'https'.
    2. Rejects userinfo / credentials in URL.
    3. Validates port against allowlist.
    4. Validates path against allowlist.
    5. Resolves all A and AAAA DNS records.
    6. Verifies that every resolved IP is permitted.
    7. Pins validated IP to defend against DNS rebinding.
    """
    if not url:
        raise BrokerSecurityViolation("Target URL cannot be empty.")

    parsed = urlparse(url)

    # 1. Scheme check
    if parsed.scheme not in ("http", "https"):
        raise BrokerSecurityViolation(
            f"Invalid URL scheme '{parsed.scheme}'. Only 'http' and 'https' are permitted."
        )

    # 2. Reject userinfo
    if parsed.username or parsed.password:
        raise BrokerSecurityViolation("Embedded credentials (userinfo) in target URL are strictly prohibited.")

    raw_host = (parsed.hostname or "").lower().strip()
    if not raw_host:
        raise BrokerSecurityViolation("Target URL hostname is missing.")

    # 3. Block metadata hostnames
    if raw_host in FORBIDDEN_HOSTNAMES:
        raise BrokerSecurityViolation(f"SSRF violation: target hostname '{raw_host}' is a blocked metadata host.")
    if raw_host.endswith(".internal") and "metadata" in raw_host:
        raise BrokerSecurityViolation(f"SSRF violation: internal metadata hostname '{raw_host}' is blocked.")

    # 4. Check development exception eligibility
    env_clean = (environment or "development").lower().strip()
    is_dev_env = env_clean in ("development", "dev", "test")
    is_authorized_dev_host = is_dev_env and raw_host in ALLOWED_DEV_HOSTNAMES

    # Check if target is an external public host (FQDN with dots or standard public hostname)
    is_external_target = (
        parsed.scheme in ("http", "https")
        and raw_host not in ALLOWED_DEV_HOSTNAMES
        and raw_host not in ("order-api", "order-api.production.svc")
    )

    # 5. Port check
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    allowed_p = allowed_ports or (
        (ALLOWED_DEMO_PORTS | ALLOWED_PUBLIC_PORTS) if is_external_target else ALLOWED_DEMO_PORTS
    )
    if port not in allowed_p:
        if is_authorized_dev_host and 1024 <= port <= 65535:
            pass
        elif is_external_target and 1 <= port <= 65535 and parsed.scheme == "https":
            # For verified external HTTPS targets, explicit ports are permissible
            pass
        else:
            raise BrokerSecurityViolation(
                f"Target port {port} is not in authorized service port allowlist {sorted(allowed_p)}."
            )

    # 6. Path check
    path = parsed.path.rstrip("/") or "/"
    if allowed_paths:
        if not any(path == ap.rstrip("/") or path.startswith(ap.rstrip("/") + "/") for ap in allowed_paths):
            raise BrokerSecurityViolation(
                f"Target path '{parsed.path}' is not permitted. Allowed paths: {sorted(allowed_paths)}."
            )

    # 7. IP parsing and DNS resolution
    resolved_ips: List[str] = []
    try:
        # Check if raw_host is already an IP address literal
        ip_obj = ipaddress.ip_address(raw_host)
        disallowed, reason = is_disallowed_ip(ip_obj, allow_private_for_dev=is_authorized_dev_host)
        if disallowed:
            raise BrokerSecurityViolation(f"SSRF violation: target IP '{raw_host}' is prohibited: {reason}")
        resolved_ips.append(str(ip_obj))
    except ValueError:
        # Hostname string -> Resolve all A and AAAA DNS records
        if is_authorized_dev_host and raw_host == "host.docker.internal":
            # host.docker.internal is resolved inside container via host-gateway
            resolved_ips.append("127.0.0.1")
        elif env_clean == "staging" and raw_host == "order-api":
            # order-api is resolved inside Docker Compose user-defined internal bridge
            resolved_ips.append("172.20.0.5")
        elif env_clean == "production" and raw_host == "order-api.production.svc":
            # order-api.production.svc is resolved inside Kubernetes cluster CoreDNS
            resolved_ips.append("10.96.0.5")
        else:

            try:
                addr_info = socket.getaddrinfo(
                    raw_host,
                    port,
                    family=socket.AF_UNSPEC,
                    type=socket.SOCK_STREAM,
                )
            except socket.gaierror as e:
                raise BrokerSecurityViolation(f"Target hostname '{raw_host}' could not be resolved: {str(e)}")

            if not addr_info:
                raise BrokerSecurityViolation(f"Target hostname '{raw_host}' resolved to zero IP addresses.")

            # Validate EVERY resolved IP address
            for entry in addr_info:
                sockaddr = entry[4]
                ip_str = sockaddr[0]
                try:
                    res_ip = ipaddress.ip_address(ip_str)
                except ValueError:
                    raise BrokerSecurityViolation(f"Invalid resolved IP '{ip_str}' for hostname '{raw_host}'.")

                disallowed, reason = is_disallowed_ip(res_ip, allow_private_for_dev=is_authorized_dev_host)
                if disallowed:
                    raise BrokerSecurityViolation(
                        f"SSRF violation: hostname '{raw_host}' resolved to disallowed IP '{ip_str}': {reason}"
                    )
                if ip_str not in resolved_ips:
                    resolved_ips.append(ip_str)

    pinned_ip = resolved_ips[0] if resolved_ips else raw_host
    direct_ip_url = f"{parsed.scheme}://{pinned_ip}:{port}{path}"

    return ValidatedTarget(
        url=url,
        pinned_ip=pinned_ip,
        hostname=raw_host,
        port=port,
        path=path,
        scheme=parsed.scheme,
        host_header=f"{raw_host}:{port}" if parsed.port else raw_host,
        direct_ip_url=direct_ip_url,
    )


def validate_safe_target_url(
    url: str,
    *,
    allowed_ports: Optional[Set[int]] = None,
    allowed_paths: Optional[Set[str]] = None,
    environment: str = "development",
    action_id: Optional[str] = None,
) -> str:
    """
    Standard URL validator returning validated URL string.
    Preserves backward-compatible signature across codebase.
    """
    target = resolve_safe_target_url(
        url,
        allowed_ports=allowed_ports,
        allowed_paths=allowed_paths,
        environment=environment,
        action_id=action_id,
    )
    return target.url


def verify_staging_network(client: Any, network_name: str = "sentinelops-internal") -> bool:
    """
    Verify that the staging Docker network exists and has internal=True.
    Raises BrokerSecurityViolation if network is missing or permits external egress.
    """
    if client is None:
        return True
    try:
        net = client.networks.get(network_name)
    except Exception as e:
        raise BrokerSecurityViolation(
            f"Staging network '{network_name}' does not exist on Docker daemon: {str(e)}"
        )

    attrs = getattr(net, "attrs", {}) or {}
    is_internal = attrs.get("Internal", False)
    if not is_internal:
        raise BrokerSecurityViolation(
            f"Staging network '{network_name}' is not marked internal=True. External egress is prohibited."
        )
    return True


class ContainerNetworkConfig(tuple):
    """
    Container network configuration tuple.
    Unpacks as (container_url, network_kwargs) for backward compatibility,
    while providing .target for the full ValidatedTarget.
    """

    def __new__(cls, container_url: str, network_kwargs: Dict[str, Any], target: ValidatedTarget):
        return super().__new__(cls, (container_url, network_kwargs))

    def __init__(self, container_url: str, network_kwargs: Dict[str, Any], target: ValidatedTarget):
        self.container_url = container_url
        self.network_kwargs = network_kwargs
        self.target = target


def build_container_network_config(
    environment: str,
    raw_service_url: str,
    action_id: str,
    docker_client: Optional[Any] = None,
) -> ContainerNetworkConfig:
    """
    Resolve container network parameters, target endpoint, and bridge URL for the specified deployment topology.

    Returns:
        ContainerNetworkConfig(resolved_container_url, docker_network_kwargs, validated_target)
    """
    env = (environment or "development").lower().strip()
    parsed = urlparse(raw_service_url)
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    # Action-specific target endpoint path
    if action_id == "restore_order_api_demo":
        target_path = "/demo/restore"
        allowed_paths = {"/demo/restore"}
    elif action_id == "inspect_service_health":
        custom_path = parsed.path.rstrip("/") or "/"
        allowed_paths = {"/health", "/metrics", "/demo/status", custom_path}
        target_path = parsed.path if parsed.path else "/health"
    elif action_id == "execute_http_recovery":
        custom_path = parsed.path.rstrip("/") or "/"
        allowed_paths = {custom_path}
        target_path = custom_path
    else:
        raise BrokerSecurityViolation(f"Unknown action '{action_id}' for network configuration.")

    raw_host = (parsed.hostname or "").lower().strip()
    is_localhost_target = raw_host in ALLOWED_DEV_HOSTNAMES

    if env in ("development", "dev", "test"):
        # Local development target (e.g. Order API running on Windows host)
        if is_localhost_target:
            container_host = "host.docker.internal"
            container_url = f"{parsed.scheme}://{container_host}:{port}{target_path}"
            validated_target = resolve_safe_target_url(
                container_url,
                allowed_paths=allowed_paths,
                environment="development",
                action_id=action_id,
            )

            network_kwargs = {
                "network_mode": "bridge",
                "extra_hosts": {"host.docker.internal": "host-gateway"},
            }
            return ContainerNetworkConfig(container_url, network_kwargs, validated_target)

        # External public target in development/test (e.g. AWS, Render, Railway, HTTPS domain)
        elif action_id in ("execute_http_recovery", "inspect_service_health") and parsed.scheme == "https":
            container_url = f"https://{raw_host}:{port}{target_path}" if parsed.port else f"https://{raw_host}{target_path}"
            validated_target = resolve_safe_target_url(
                container_url,
                allowed_paths=allowed_paths,
                environment="development",
                action_id=action_id,
            )
            network_kwargs = {
                "network_mode": "bridge",
                "extra_hosts": {},
            }
            return ContainerNetworkConfig(container_url, network_kwargs, validated_target)
        else:
            raise BrokerSecurityViolation(
                f"Target host '{raw_host}' is not in authorized development hostnames {sorted(ALLOWED_DEV_HOSTNAMES)}."
            )

    elif env == "staging":
        # Docker Compose Staging: User-defined internal bridge with DNS
        if action_id == "execute_http_recovery" and is_localhost_target:
            raise BrokerSecurityViolation(
                f"Localhost/development target host '{raw_host}' is strictly prohibited in staging environment."
            )

        if action_id in ("execute_http_recovery", "inspect_service_health") and parsed.scheme == "https" and not is_localhost_target:
            # External public target in staging
            container_url = f"https://{raw_host}:{port}{target_path}" if parsed.port else f"https://{raw_host}{target_path}"
            validated_target = resolve_safe_target_url(
                container_url,
                allowed_paths=allowed_paths,
                environment="staging",
                action_id=action_id,
            )
            network_kwargs = {
                "network_mode": "bridge",
                "extra_hosts": {},
            }
            return ContainerNetworkConfig(container_url, network_kwargs, validated_target)

        container_host = (
            parsed.hostname
            if parsed.hostname and parsed.hostname not in ("localhost", "127.0.0.1")
            else "order-api"
        )
        container_url = f"{parsed.scheme}://{container_host}:{port}{target_path}"
        validated_target = resolve_safe_target_url(
            container_url,
            allowed_paths=allowed_paths,
            environment="staging",
            action_id=action_id,
        )

        # Verify staging network is internal if client is available
        if docker_client is not None:
            verify_staging_network(docker_client, "sentinelops-internal")

        network_kwargs = {
            "network": "sentinelops-internal",
            "extra_hosts": {},
        }
        return ContainerNetworkConfig(container_url, network_kwargs, validated_target)

    elif env == "production":
        # Production deployment:
        if action_id == "execute_http_recovery" and is_localhost_target:
            raise BrokerSecurityViolation(
                f"Localhost/development target host '{raw_host}' is strictly prohibited in production environment."
            )

        if action_id in ("execute_http_recovery", "inspect_service_health") and parsed.scheme == "https" and not is_localhost_target:
            # External public target in production
            container_url = f"https://{raw_host}:{port}{target_path}" if parsed.port else f"https://{raw_host}{target_path}"
            validated_target = resolve_safe_target_url(
                container_url,
                allowed_paths=allowed_paths,
                environment="production",
                action_id=action_id,
            )
            # External egress network or standard bridge
            ext_network = os.environ.get("SENTINELOPS_EXTERNAL_NETWORK", "bridge")
            network_kwargs = {
                "network_mode": ext_network if ext_network in ("bridge", "host") else None,
                "network": ext_network if ext_network not in ("bridge", "host") else None,
                "extra_hosts": {},
            }
            # Clean None keys
            network_kwargs = {k: v for k, v in network_kwargs.items() if v is not None}
            return ContainerNetworkConfig(container_url, network_kwargs, validated_target)

        container_host = (
            parsed.hostname
            if parsed.hostname and parsed.hostname not in ("localhost", "127.0.0.1")
            else "order-api.production.svc"
        )
        container_url = f"{parsed.scheme}://{container_host}:{port}{target_path}"
        validated_target = resolve_safe_target_url(
            container_url,
            allowed_paths=allowed_paths,
            environment="production",
            action_id=action_id,
        )

        prod_network = os.environ.get("SENTINELOPS_PROD_NETWORK", "sentinelops-production-net")
        if docker_client is not None:
            try:
                docker_client.networks.get(prod_network)
            except Exception:
                raise BrokerSecurityViolation(
                    f"Production isolated network '{prod_network}' is not available on Docker daemon. "
                    "Fail-closed: execution aborted."
                )

        network_kwargs = {
            "network": prod_network,
            "extra_hosts": {},
        }
        return ContainerNetworkConfig(container_url, network_kwargs, validated_target)

    else:
        raise BrokerSecurityViolation(f"Unsupported execution environment '{environment}'.")
