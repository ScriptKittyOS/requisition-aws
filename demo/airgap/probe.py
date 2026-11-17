# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sudo Apt Holdings LLC (Script Kitty OS & Labs)
"""Run INSIDE the airgap container (python3 -I): show that it has no network before anything is
verified. Prints its findings and one summary line, AIRGAP-PROBE no-network or NETWORK-PRESENT."""

import os
import socket

try:
    interfaces = sorted(os.listdir("/sys/class/net"))
except OSError:
    interfaces = ["?"]
print("network probe: interfaces %s" % interfaces)
reached = []
for host, port in (("1.1.1.1", 443), ("8.8.8.8", 53)):
    try:
        socket.create_connection((host, port), timeout=3).close()
        reached.append(host)
        print("network probe: connect %s:%d -> CONNECTED" % (host, port))
    except OSError as error:
        print("network probe: connect %s:%d -> %s" % (host, port, type(error).__name__))
try:
    socket.getaddrinfo("bedrock-runtime.us-east-1.amazonaws.com", 443)
    reached.append("dns")
    print("network probe: DNS -> RESOLVED")
except OSError as error:
    print("network probe: DNS bedrock-runtime.us-east-1.amazonaws.com -> %s" % type(error).__name__)
print("AIRGAP-PROBE " + ("no-network" if not reached and interfaces == ["lo"] else "NETWORK-PRESENT"))
