#!/usr/bin/env python3
"""
SentinelOps Phase B — Experiment A: Kernel Capability & setns() Authority Probe.

Empirically tests Linux kernel namespace entry constraints:
1. setns(fd, CLONE_NEWNET) requirements:
   - Does CAP_NET_ADMIN alone authorize setns into another network namespace?
   - Or does the Linux kernel strictly require CAP_SYS_ADMIN in the owning user namespace?
2. Kernel reference:
   - Linux kernel `kernel/nsproxy.c` and `net/core/net_namespace.c`:
     `if (!ns_capable(net_ns->user_ns, CAP_SYS_ADMIN) || !ns_capable(current_user_ns(), CAP_SYS_ADMIN))`
"""

import ctypes
import os
import sys

CLONE_NEWNET = 0x40000000

libc = ctypes.CDLL(None, use_errno=True)


def get_capabilities() -> str:
    """Reads effective and bounding capabilities from /proc/self/status."""
    caps = {}
    try:
        with open("/proc/self/status", "r") as f:
            for line in f:
                if line.startswith("Cap"):
                    parts = line.strip().split(":")
                    caps[parts[0]] = parts[1].strip()
    except Exception as e:
        return f"Error reading /proc/self/status: {e}"
    return ", ".join(f"{k}={v}" for k, v in caps.items())


def test_setns(target_netns_path: str) -> None:
    print(f"=== TESTING setns(2) AUTHORITY ===")
    print(f"Current PID: {os.getpid()}")
    print(f"Current UID: {os.getuid()}, EUID: {os.geteuid()}")
    print(f"Capabilities: {get_capabilities()}")
    print(f"Target netns path: {target_netns_path}")

    if not os.path.exists(target_netns_path):
        print(f"ERROR: Target netns path '{target_netns_path}' does not exist.")
        sys.exit(1)

    try:
        fd = os.open(target_netns_path, os.O_RDONLY)
        print(f"Successfully opened fd {fd} to {target_netns_path}")
    except PermissionError as pe:
        print(f"FAILED to open netns path: {pe} (Permission Denied - DAC / MAC constraint)")
        sys.exit(1)
    except Exception as e:
        print(f"FAILED to open netns path: {e}")
        sys.exit(1)

    ret = libc.setns(fd, CLONE_NEWNET)
    errno = ctypes.get_errno()

    if ret == 0:
        print("SUCCESS: setns(fd, CLONE_NEWNET) succeeded. Entered target network namespace.")
    else:
        print(f"FAILED: setns(fd, CLONE_NEWNET) returned {ret}, errno={errno} ({os.strerror(errno)})")
        if errno == 1:  # EPERM
            print(
                "EXPLANATION (EPERM): The calling thread does not have CAP_SYS_ADMIN in both "
                "the owning user namespace of the target network namespace and its current user namespace."
            )
            print("CRITICAL ARCHITECTURAL FINDING: CAP_NET_ADMIN alone is INSUFFICIENT for setns().")
            print("The helper MUST possess CAP_SYS_ADMIN in host user namespace to enter container netns.")

    os.close(fd)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <path_to_netns_e.g._/proc/PID/ns/net_or_/var/run/docker/netns/ID>")
        sys.exit(1)
    test_setns(sys.argv[1])
