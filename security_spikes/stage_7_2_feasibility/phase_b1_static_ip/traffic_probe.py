#!/usr/bin/env python3
"""
SentinelOps Phase B1.6 — Comprehensive Traffic Probe & Bypass Verification Suite.

Probes network egress behavior from within the executor container sandbox:
1. Authorized Target HTTP/TCP endpoint (must be ALLOWED).
2. Unauthorized Target IP on authorized port (must be BLOCKED).
3. Authorized Target IP on unauthorized port (must be BLOCKED).
4. Direct external DNS over UDP (8.8.8.8:53) (must be BLOCKED).
5. Direct external DNS over TCP (8.8.8.8:53) (must be BLOCKED).
6. Docker embedded DNS (127.0.0.11:53) UDP query (must not resolve external domains).
7. Docker embedded DNS (127.0.0.11:53) TCP connect (monitored).
8. DNS tunneling exfiltration attempt via 127.0.0.11 (must not reach resolver or be inconclusive).
9. IPv6 egress attempt (must be BLOCKED or NOT_APPLICABLE).
10. Raw socket / source IP spoofing (must be BLOCKED).
11. Multi-homed interface source-IP binding egress (if tested, must be BLOCKED).

Enforces strict statuses: ALLOWED, BLOCKED, RESOLVER_REJECTED, SOCKET_BIND_FAILED, INCONCLUSIVE, NOT_APPLICABLE, NOT_TESTED.
"""

import json
import socket
import struct
import sys
import time
from urllib.request import urlopen, Request


def probe_http(url: str, timeout: float = 3.0) -> dict:
    start = time.time()
    try:
        req = Request(url, headers={"User-Agent": "SentinelOps-B1-Probe"})
        with urlopen(req, timeout=timeout) as resp:
            data = resp.read().decode(errors="ignore")
            return {
                "status": "ALLOWED" if resp.status == 200 else "INCONCLUSIVE",
                "success": (resp.status == 200),
                "status_code": resp.status,
                "duration_ms": round((time.time() - start) * 1000, 2),
                "body_preview": data[:100],
                "error": None,
            }
    except Exception as e:
        return {
            "status": "BLOCKED",
            "success": False,
            "status_code": None,
            "duration_ms": round((time.time() - start) * 1000, 2),
            "body_preview": None,
            "error": str(e),
        }


def probe_tcp_connect(host: str, port: int, timeout: float = 2.0, bind_ip: str = None) -> dict:
    start = time.time()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    if bind_ip:
        try:
            s.bind((bind_ip, 0))
        except Exception as be:
            s.close()
            return {
                "status": "SOCKET_BIND_FAILED",
                "connected": False,
                "duration_ms": round((time.time() - start) * 1000, 2),
                "error": f"Socket bind failed on IP {bind_ip}: {be}",
            }
    try:
        s.connect((host, port))
        s.close()
        return {
            "status": "ALLOWED",
            "connected": True,
            "duration_ms": round((time.time() - start) * 1000, 2),
            "error": "SECURITY WARNING: TCP connection succeeded!",
        }
    except socket.timeout:
        s.close()
        return {
            "status": "BLOCKED",
            "connected": False,
            "duration_ms": round((time.time() - start) * 1000, 2),
            "error": "Connection timed out (packet dropped by firewall)",
        }
    except ConnectionRefusedError as cre:
        s.close()
        return {
            "status": "BLOCKED",
            "connected": False,
            "duration_ms": round((time.time() - start) * 1000, 2),
            "error": f"Connection refused by target / firewall: {cre}",
        }
    except OSError as e:
        s.close()
        return {
            "status": "BLOCKED",
            "connected": False,
            "duration_ms": round((time.time() - start) * 1000, 2),
            "error": f"Connection rejected: {e}",
        }
    except Exception as e:
        s.close()
        return {
            "status": "INCONCLUSIVE",
            "connected": False,
            "duration_ms": round((time.time() - start) * 1000, 2),
            "error": f"Unexpected connect error: {e}",
        }


def build_dns_query_bytes(query_domain: str = "example.com", tx_id: int = 0xAAAA) -> bytes:
    labels = query_domain.split(".")
    qname_bytes = b"".join(bytes([len(l)]) + l.encode("ascii") for l in labels) + b"\x00"
    header = struct.pack("!HHHHHH", tx_id, 0x0100, 1, 0, 0, 0)
    question = qname_bytes + struct.pack("!HH", 1, 1)  # QTYPE=A (1), QCLASS=IN (1)
    return header + question


def probe_dns_udp(server: str = "8.8.8.8", port: int = 53, query_domain: str = "example.com", timeout: float = 2.0) -> dict:
    start = time.time()
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    dns_query = build_dns_query_bytes(query_domain)
    try:
        s.sendto(dns_query, (server, port))
        data, _ = s.recvfrom(512)
        s.close()
        rcode = data[3] & 0x0F if len(data) > 3 else 99
        if rcode == 0:
            return {
                "status": "ALLOWED",
                "disposition": "DNS_DELIVERED_AND_ANSWERED",
                "resolved": True,
                "rcode": rcode,
                "duration_ms": round((time.time() - start) * 1000, 2),
                "response_bytes_len": len(data),
                "error": "SECURITY LEAK: DNS query answered successfully (NOERROR)!",
            }
        else:
            return {
                "status": "RESOLVER_REJECTED",
                "disposition": "DNS_DELIVERED_BUT_RESOLVER_REJECTED",
                "resolved": False,
                "rcode": rcode,
                "duration_ms": round((time.time() - start) * 1000, 2),
                "response_bytes_len": len(data),
                "error": f"DNS query reached resolver and was rejected with RCODE={rcode} (EGRESS REACHED RESOLVER)",
            }
    except socket.timeout:
        s.close()
        if server == "127.0.0.11":
            return {
                "status": "BLOCKED",
                "disposition": "DNS_UDP_UPSTREAM_BLACKHOLED_OR_DROPPED",
                "resolved": False,
                "rcode": None,
                "duration_ms": round((time.time() - start) * 1000, 2),
                "error": "Query to 127.0.0.11 timed out (upstream blackholed via RFC 5737)",
            }
        else:
            return {
                "status": "BLOCKED",
                "disposition": "DNS_BLOCKED_BEFORE_RESOLVER",
                "resolved": False,
                "rcode": None,
                "duration_ms": round((time.time() - start) * 1000, 2),
                "error": "DNS query timed out (packet dropped by host Netfilter gate)",
            }
    except OSError as e:
        s.close()
        return {
            "status": "BLOCKED",
            "disposition": "DNS_BLOCKED_BEFORE_RESOLVER",
            "resolved": False,
            "rcode": None,
            "duration_ms": round((time.time() - start) * 1000, 2),
            "error": f"DNS query rejected by network layer: {e}",
        }
    except Exception as e:
        s.close()
        return {
            "status": "INCONCLUSIVE",
            "disposition": "DNS_OUTCOME_UNKNOWN",
            "resolved": False,
            "rcode": None,
            "duration_ms": round((time.time() - start) * 1000, 2),
            "error": f"Unexpected DNS error: {e}",
        }


def probe_dns_tcp(server: str = "8.8.8.8", port: int = 53, query_domain: str = "example.com", timeout: float = 2.0) -> dict:
    """
    Performs RFC 1035 framed DNS-over-TCP query to test whether TCP DNS queries can reach
    an external resolver or escape via local/embedded resolvers (Requirement B1.7-07).
    """
    start = time.time()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    dns_payload = build_dns_query_bytes(query_domain)
    framed_query = struct.pack("!H", len(dns_payload)) + dns_payload

    try:
        # Step 1: TCP Handshake
        s.connect((server, port))
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        s.close()
        disposition = "DNS_TCP_DROPPED_BY_FIREWALL" if isinstance(e, socket.timeout) else "DNS_TCP_REJECTED_BY_FIREWALL"
        return {
            "status": "BLOCKED",
            "disposition": disposition,
            "connected": False,
            "resolved": False,
            "rcode": None,
            "duration_ms": round((time.time() - start) * 1000, 2),
            "error": f"TCP connection to {server}:{port} blocked by firewall: {e}",
        }
    except Exception as e:
        s.close()
        return {
            "status": "INCONCLUSIVE",
            "disposition": "DNS_TCP_CONNECT_ERROR",
            "connected": False,
            "resolved": False,
            "rcode": None,
            "duration_ms": round((time.time() - start) * 1000, 2),
            "error": f"Unexpected error connecting to {server}:{port}: {e}",
        }

    # Step 2: Connection succeeded.
    try:
        s.sendall(framed_query)

        # Read 2-byte response length
        len_bytes = b""
        while len(len_bytes) < 2:
            chunk = s.recv(2 - len(len_bytes))
            if not chunk:
                break
            len_bytes += chunk

        if len(len_bytes) < 2:
            s.close()
            if server == "127.0.0.11":
                return {
                    "status": "BLOCKED",
                    "disposition": "DNS_TCP_RESOLVER_CLOSED_WITHOUT_RESPONSE",
                    "connected": True,
                    "resolved": False,
                    "rcode": None,
                    "duration_ms": round((time.time() - start) * 1000, 2),
                    "error": "Local resolver closed TCP connection without data (upstream blocked)",
                }
            else:
                return {
                    "status": "ALLOWED",
                    "disposition": "DNS_TCP_EXTERNAL_CONNECTED_BUT_RESET",
                    "connected": True,
                    "resolved": False,
                    "rcode": None,
                    "duration_ms": round((time.time() - start) * 1000, 2),
                    "error": f"SECURITY LEAK: External TCP connection to {server}:{port} succeeded (closed before response)",
                }

        resp_len = struct.unpack("!H", len_bytes)[0]
        resp_data = b""
        while len(resp_data) < resp_len:
            chunk = s.recv(resp_len - len(resp_data))
            if not chunk:
                break
            resp_data += chunk
        s.close()

        if len(resp_data) < 4:
            return {
                "status": "INCONCLUSIVE",
                "disposition": "DNS_TCP_MALFORMED_RESPONSE",
                "connected": True,
                "resolved": False,
                "rcode": None,
                "duration_ms": round((time.time() - start) * 1000, 2),
                "error": "Received malformed/truncated DNS response header over TCP",
            }

        rcode = resp_data[3] & 0x0F
        if rcode == 0:
            return {
                "status": "ALLOWED",
                "disposition": "DNS_TCP_DELIVERED_AND_ANSWERED",
                "connected": True,
                "resolved": True,
                "rcode": rcode,
                "duration_ms": round((time.time() - start) * 1000, 2),
                "response_bytes_len": len(resp_data),
                "error": f"SECURITY LEAK: DNS query over TCP to {server} answered successfully (NOERROR)!",
            }
        else:
            return {
                "status": "RESOLVER_REJECTED",
                "disposition": "DNS_TCP_DELIVERED_BUT_RESOLVER_REJECTED",
                "connected": True,
                "resolved": False,
                "rcode": rcode,
                "duration_ms": round((time.time() - start) * 1000, 2),
                "response_bytes_len": len(resp_data),
                "error": f"SECURITY LEAK: DNS query over TCP reached resolver and returned RCODE={rcode} (EGRESS REACHED RESOLVER)",
            }
    except socket.timeout:
        s.close()
        if server == "127.0.0.11":
            return {
                "status": "BLOCKED",
                "disposition": "DNS_TCP_UPSTREAM_BLACKHOLED_OR_DROPPED",
                "connected": True,
                "resolved": False,
                "rcode": None,
                "duration_ms": round((time.time() - start) * 1000, 2),
                "error": "Query to 127.0.0.11 over TCP timed out (upstream blackholed via RFC 5737)",
            }
        else:
            return {
                "status": "ALLOWED",
                "disposition": "DNS_TCP_EXTERNAL_CONNECTED_NO_REPLY",
                "connected": True,
                "resolved": False,
                "rcode": None,
                "duration_ms": round((time.time() - start) * 1000, 2),
                "error": f"SECURITY LEAK: External TCP connection to {server}:{port} succeeded (query timed out on reply)",
            }
    except Exception as e:
        s.close()
        return {
            "status": "INCONCLUSIVE",
            "disposition": "DNS_TCP_OUTCOME_UNKNOWN",
            "connected": True,
            "resolved": False,
            "rcode": None,
            "duration_ms": round((time.time() - start) * 1000, 2),
            "error": f"Unexpected TCP DNS communication error: {e}",
        }


def probe_ipv6_connect(host: str = "2606:4700:4700::1111", port: int = 80, timeout: float = 2.0) -> dict:
    start = time.time()
    try:
        s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        s.close()
        return {
            "status": "ALLOWED",
            "connected": True,
            "duration_ms": round((time.time() - start) * 1000, 2),
            "error": "SECURITY LEAK: IPv6 connection succeeded!",
        }
    except OSError as e:
        if e.errno in (97, 101):  # EAFNOSUPPORT / ENETUNREACH
            return {
                "status": "NOT_APPLICABLE",
                "connected": False,
                "duration_ms": round((time.time() - start) * 1000, 2),
                "error": f"IPv6 disabled in kernel stack: {e}",
            }
        return {
            "status": "BLOCKED",
            "connected": False,
            "duration_ms": round((time.time() - start) * 1000, 2),
            "error": f"IPv6 rejected: {e}",
        }
    except Exception as e:
        return {
            "status": "INCONCLUSIVE",
            "connected": False,
            "duration_ms": round((time.time() - start) * 1000, 2),
            "error": f"Unexpected IPv6 error: {e}",
        }


def probe_raw_socket_spoofing() -> dict:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        s.close()
        return {
            "status": "ALLOWED",
            "raw_socket_permitted": True,
            "error": "SECURITY WARNING: CAP_NET_RAW active, raw socket opened!",
        }
    except PermissionError as pe:
        return {
            "status": "BLOCKED",
            "raw_socket_permitted": False,
            "error": f"Blocked by kernel capability checks: {pe}",
        }
    except Exception as e:
        return {
            "status": "INCONCLUSIVE",
            "raw_socket_permitted": False,
            "error": f"Raw socket creation error: {e}",
        }


def probe_multi_homing_leak(secondary_ip: str, target_host: str = "1.1.1.1", target_port: int = 80) -> dict:
    if not secondary_ip:
        return {"status": "NOT_APPLICABLE", "leaked": False, "detail": "Precondition: No secondary network attached"}
    res = probe_tcp_connect(target_host, target_port, timeout=2.0, bind_ip=secondary_ip)
    if res["status"] == "SOCKET_BIND_FAILED":
        return {
            "status": "SOCKET_BIND_FAILED",
            "leaked": False,
            "error": f"Precondition failed: Unable to bind to secondary IP {secondary_ip} ({res['error']})",
        }
    if res["connected"]:
        return {
            "status": "ALLOWED",
            "leaked": True,
            "error": f"CRITICAL LEAK: Traffic escaped via secondary interface bound to {secondary_ip}!",
        }
    if res["status"] == "BLOCKED":
        return {
            "status": "BLOCKED",
            "leaked": False,
            "detail": res["error"],
        }
    return {
        "status": "INCONCLUSIVE",
        "leaked": False,
        "detail": res.get("error", "Unknown connect status"),
    }


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 traffic_probe.py <auth_url> [auth_host] [auth_port] [unauth_host] [unauth_port] [sec_ip]")
        sys.exit(1)

    auth_url = sys.argv[1]
    auth_host = sys.argv[2] if len(sys.argv) > 2 else "172.29.0.10"
    auth_port = int(sys.argv[3]) if len(sys.argv) > 3 else 8001
    unauth_host = sys.argv[4] if len(sys.argv) > 4 else "172.29.0.20"
    unauth_port = int(sys.argv[5]) if len(sys.argv) > 5 else 8002
    sec_ip = sys.argv[6] if len(sys.argv) > 6 else None

    # Tunneling domain simulation
    ts = int(time.time())
    tunnel_domain = f"exfil-test-{ts}.sentinelops-audit.internal"

    results = {
        "timestamp": ts,
        "1_authorized_http": probe_http(auth_url),
        "2_unauthorized_host_same_port": probe_tcp_connect(unauth_host, auth_port),
        "3_authorized_host_unauthorized_port": probe_tcp_connect(auth_host, unauth_port),
        "4_dns_direct_external_udp_53": probe_dns_udp("8.8.8.8", 53),
        "5_dns_direct_external_tcp_53": probe_dns_tcp("8.8.8.8", 53),
        "6_docker_embedded_dns_127_0_0_11_udp": probe_dns_udp("127.0.0.11", 53, "example.com"),
        "7_docker_embedded_dns_127_0_0_11_tcp": probe_dns_tcp("127.0.0.11", 53),
        "8_dns_tunneling_probe": probe_dns_udp("127.0.0.11", 53, tunnel_domain),
        "9_ipv6_egress": probe_ipv6_connect(),
        "10_raw_socket_spoofing": probe_raw_socket_spoofing(),
        "11_multi_homing_leak": probe_multi_homing_leak(sec_ip),
    }

    print(json.dumps(results, indent=2))

    failures = []

    # Invariant 1: Authorized target MUST succeed
    if results["1_authorized_http"]["status"] != "ALLOWED":
        failures.append(f"1_authorized_http failed (status: {results['1_authorized_http']['status']}, error: {results['1_authorized_http']['error']})")

    # Invariant 2: Unauthorized host on same port MUST be strictly blocked
    if results["2_unauthorized_host_same_port"]["status"] != "BLOCKED":
        failures.append(f"2_unauthorized_host_same_port was NOT blocked (status: {results['2_unauthorized_host_same_port']['status']})")

    # Invariant 3: Authorized host on unauthorized port MUST be strictly blocked
    if results["3_authorized_host_unauthorized_port"]["status"] != "BLOCKED":
        failures.append(f"3_authorized_host_unauthorized_port was NOT blocked (status: {results['3_authorized_host_unauthorized_port']['status']})")

    # Invariant 4: Direct external UDP DNS MUST be strictly blocked
    if results["4_dns_direct_external_udp_53"]["status"] != "BLOCKED":
        failures.append(f"4_dns_direct_external_udp_53 was NOT blocked (status: {results['4_dns_direct_external_udp_53']['status']})")

    # Invariant 5: Direct external TCP DNS MUST be strictly blocked
    if results["5_dns_direct_external_tcp_53"]["status"] != "BLOCKED":
        failures.append(f"5_dns_direct_external_tcp_53 was NOT blocked (status: {results['5_dns_direct_external_tcp_53']['status']})")

    # Invariant 6: Docker embedded DNS UDP must NOT resolve external domains or leak
    if results["6_docker_embedded_dns_127_0_0_11_udp"]["status"] in ("ALLOWED", "RESOLVER_REJECTED"):
        failures.append(f"6_docker_embedded_dns_127_0_0_11_udp reached external resolver (status: {results['6_docker_embedded_dns_127_0_0_11_udp']['status']})")
    elif results["6_docker_embedded_dns_127_0_0_11_udp"]["status"] == "INCONCLUSIVE":
        failures.append("6_docker_embedded_dns_127_0_0_11_udp status is INCONCLUSIVE (cannot prove UDP DNS containment)")

    # Invariant 7: Docker embedded DNS TCP must NOT connect externally or leak (Requirement B1.7-07)
    if results["7_docker_embedded_dns_127_0_0_11_tcp"]["status"] in ("ALLOWED", "RESOLVER_REJECTED"):
        failures.append(f"7_docker_embedded_dns_127_0_0_11_tcp reached external resolver (status: {results['7_docker_embedded_dns_127_0_0_11_tcp']['status']})")
    elif results["7_docker_embedded_dns_127_0_0_11_tcp"]["status"] == "INCONCLUSIVE":
        failures.append("7_docker_embedded_dns_127_0_0_11_tcp status is INCONCLUSIVE (cannot prove TCP DNS containment)")

    # Invariant 8: DNS Tunneling exfiltration MUST NOT succeed or deliver to resolver
    # If ALLOWED or RESOLVER_REJECTED, packets reached an external resolver!
    # INCONCLUSIVE also fails overall security enforcement per Requirement E
    if results["8_dns_tunneling_probe"]["status"] in ("ALLOWED", "RESOLVER_REJECTED"):
        failures.append(f"8_dns_tunneling_probe reached upstream resolver (status: {results['8_dns_tunneling_probe']['status']})")
    elif results["8_dns_tunneling_probe"]["status"] == "INCONCLUSIVE":
        failures.append("8_dns_tunneling_probe status is INCONCLUSIVE (cannot prove DNS exfiltration is blocked)")

    # Invariant 9: IPv6 MUST be blocked or disabled
    if results["9_ipv6_egress"]["status"] not in ("BLOCKED", "NOT_APPLICABLE"):
        failures.append(f"9_ipv6_egress was NOT blocked or disabled (status: {results['9_ipv6_egress']['status']})")

    # Invariant 10: Raw socket capabilities MUST be denied
    if results["10_raw_socket_spoofing"]["status"] != "BLOCKED":
        failures.append(f"10_raw_socket_spoofing permitted raw sockets (status: {results['10_raw_socket_spoofing']['status']})")

    # Invariant 11: Multi-homing leak: if secondary IP was provided, MUST be strictly BLOCKED
    if results["11_multi_homing_leak"]["status"] == "ALLOWED":
        failures.append("11_multi_homing_leak: traffic escaped via secondary interface (leak)")
    elif results["11_multi_homing_leak"]["status"] in ("INCONCLUSIVE", "SOCKET_BIND_FAILED"):
        failures.append(f"11_multi_homing_leak failed to execute reliably (status: {results['11_multi_homing_leak']['status']})")

    if failures:
        print(f"\n[SECURITY VERIFICATION FAILED] {len(failures)} invariant(s) violated:", file=sys.stderr)
        for f in failures:
            print(f"  - {f}", file=sys.stderr)
        sys.exit(1)

    print("\n[SECURITY VERIFICATION PASSED] All required security invariants satisfied.")
    sys.exit(0)


if __name__ == "__main__":
    main()
