"""URL and Target Validator with SSRF Safeguards.

Blueprint Section 10:
"Prevent server-side request forgery (SSRF): arbitrary endpoint registration must not trigger a request.
Block loopback/private/link-local/metadata destinations by default, validate DNS and redirects, and use egress controls."
"""

import ipaddress
from urllib.parse import urlparse
from typing import Tuple


class SSRFValidationError(Exception):
    """Raised when target URL violates SSRF safety constraints."""
    pass


# Forbidden Cloud Metadata Hosts and IP Networks
BLOCKED_METADATA_HOSTS = {
    "169.254.169.254",
    "169.254.170.2",
    "metadata.google.internal",
    "metadata.internal",
    "100.100.100.200",
}

LINK_LOCAL_NETWORKS = [
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("fe80::/10"),
]


def validate_target_url(url: str, allow_local: bool = True) -> Tuple[bool, str]:
    """
    Validate target URL against SSRF attack vectors.

    Parameters:
    - url: The target URL to probe.
    - allow_local: Whether loopback (localhost/127.0.0.1) is permitted for local development/demo.

    Returns:
    - (is_valid, sanitized_url)

    Raises:
    - SSRFValidationError if constraints are violated.
    """
    if not url or not isinstance(url, str):
        raise SSRFValidationError("URL cannot be empty")

    parsed = urlparse(url.strip())

    # 1. Enforce HTTP/HTTPS scheme only
    if parsed.scheme.lower() not in ("http", "https"):
        raise SSRFValidationError(f"Invalid URL scheme '{parsed.scheme}'. Only http and https are permitted.")

    # 2. Reject embedded user credentials (http://user:pass@host)
    if parsed.username or parsed.password:
        raise SSRFValidationError("Embedded user credentials in target URL are prohibited.")

    hostname = parsed.hostname
    if not hostname:
        raise SSRFValidationError("Target URL must include a valid hostname.")

    hostname_lower = hostname.lower()

    # 3. Block known cloud metadata endpoints immediately
    if hostname_lower in BLOCKED_METADATA_HOSTS:
        raise SSRFValidationError(f"Access to cloud metadata destination '{hostname}' is blocked.")

    # 4. Check if hostname is an IP address
    parsed_ip = None
    try:
        parsed_ip = ipaddress.ip_address(hostname_lower)
    except ValueError:
        # Not a raw IP; hostname is a domain name
        parsed_ip = None

    if parsed_ip is not None:
        # Check link-local metadata addresses
        for net in LINK_LOCAL_NETWORKS:
            if parsed_ip in net:
                raise SSRFValidationError(f"Access to link-local address '{parsed_ip}' is blocked.")

        # Check loopback
        if parsed_ip.is_loopback:
            if not allow_local:
                raise SSRFValidationError(f"Access to loopback address '{parsed_ip}' is blocked in this environment.")
            return True, url

        # Check private networks
        if parsed_ip.is_private:
            if not allow_local:
                raise SSRFValidationError(f"Access to private IP address '{parsed_ip}' is blocked.")
            return True, url
    else:
        # Hostname is a domain name
        if hostname_lower in ("localhost", "localhost.localdomain"):
            if not allow_local:
                raise SSRFValidationError(f"Access to localhost is blocked in this environment.")
            return True, url

    return True, url
