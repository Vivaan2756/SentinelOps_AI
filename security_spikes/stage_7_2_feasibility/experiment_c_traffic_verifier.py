#!/usr/bin/env python3
"""
SentinelOps Phase B — Experiment C: Packet-Level Traffic Verifier.

Tests:
1. Authorized TCP destination and port.
2. Unauthorized IPv4 destination (must be dropped or rejected).
3. Unauthorized IPv6 destination (must be dropped or rejected).
4. DNS exfiltration attempt over UDP port 53 (must fail).
5. Output structured JSON test results.
"""

import json
import socket
import sys
import time
from urllib.request import urlopen, Request
from urllib.error import URLError


def test_authorized_http(target_url: str, timeout: float = 3.0) -> dict:
    start = time.time()
    try:
        req = Request(target_url, headers={"User-Agent": "SentinelOps-Traffic-Verifier"})
        with urlopen(req, timeout=timeout) as resp:
            data = resp.read().decode()
            return {
                "test": "authorized_http",
                "target": target_url,
                "status_code": resp.status,
                "duration_ms": round((time.time() - start) * 1000, 2),
                "success": (resp.status == 200),
                "error": None,
            }
    except Exception as e:
        return {
            "test": "authorized_http",
            "target": target_url,
            "status_code": None,
            "duration_ms": round((time.time() - start) * 1000, 2),
            "success": False,
            "error": str(e),
        }


def test_unauthorized_ipv4_tcp(host: str, port: int, timeout: float = 2.0) -> dict:
    start = time.time()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        s.close()
        # Connection succeeded -> firewall LEAK!
        return {
            "test": "unauthorized_ipv4_tcp",
            "target": f"{host}:{port}",
            "blocked": False,
            "duration_ms": round((time.time() - start) * 1000, 2),
            "error": "SECURITY LEAK: Connection succeeded to unauthorized host!",
        }
    except socket.timeout:
        return {
            "test": "unauthorized_ipv4_tcp",
            "target": f"{host}:{port}",
            "blocked": True,
            "duration_ms": round((time.time() - start) * 1000, 2),
            "error": "Connection timed out (packet dropped by firewall)",
        }
    except OSError as e:
        # Connection refused or host unreachable (ICMP reject)
        return {
            "test": "unauthorized_ipv4_tcp",
            "target": f"{host}:{port}",
            "blocked": True,
            "duration_ms": round((time.time() - start) * 1000, 2),
            "error": f"Rejected by firewall: {e}",
        }


def test_unauthorized_ipv6(host: str, port: int, timeout: float = 2.0) -> dict:
    start = time.time()
    try:
        s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        s.close()
        return {
            "test": "unauthorized_ipv6_tcp",
            "target": f"[{host}]:{port}",
            "blocked": False,
            "error": "SECURITY LEAK: IPv6 connection succeeded!",
        }
    except Exception as e:
        return {
            "test": "unauthorized_ipv6_tcp",
            "target": f"[{host}]:{port}",
            "blocked": True,
            "error": f"Blocked: {e}",
        }


def test_dns_udp(dns_server: str = "8.8.8.8", port: int = 53, timeout: float = 2.0) -> dict:
    start = time.time()
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    # Minimal raw DNS query for example.com
    dns_query = b"\xaa\xaa\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01"
    try:
        s.sendto(dns_query, (dns_server, port))
        data, _ = s.recvfrom(512)
        s.close()
        return {
            "test": "dns_udp_exfiltration",
            "target": f"{dns_server}:{port}",
            "blocked": False,
            "error": "SECURITY LEAK: DNS query answered via public resolver!",
        }
    except Exception as e:
        return {
            "test": "dns_udp_exfiltration",
            "target": f"{dns_server}:{port}",
            "blocked": True,
            "error": f"DNS blocked: {e}",
        }


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 experiment_c_traffic_verifier.py <authorized_http_url> [unauthorized_ip]")
        sys.exit(1)

    auth_url = sys.argv[1]
    unauth_ip = sys.argv[2] if len(sys.argv) > 2 else "1.1.1.1"

    results = {
        "timestamp": time.time(),
        "authorized_traffic": test_authorized_http(auth_url),
        "unauthorized_ipv4_traffic": test_unauthorized_ipv4_tcp(unauth_ip, 80),
        "unauthorized_ipv6_traffic": test_unauthorized_ipv6("2606:4700:4700::1111", 80),
        "dns_exfiltration": test_dns_udp("8.8.8.8", 53),
    }

    print(json.dumps(results, indent=2))
    all_passed = (
        results["authorized_traffic"]["success"]
        and results["unauthorized_ipv4_traffic"]["blocked"]
        and results["unauthorized_ipv6_traffic"]["blocked"]
        and results["dns_exfiltration"]["blocked"]
    )
    sys.exit(0 if all_passed else 1)


if __name__ == "__main__":
    main()
