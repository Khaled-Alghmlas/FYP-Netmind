#!/bin/sh
set -e

# Reset to a clean, known state
iptables -F
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT

# Always allow loopback traffic
iptables -A INPUT -i lo -j ACCEPT

# Allow ICMP (ping) so reachability checks keep working
iptables -A INPUT -p icmp -j ACCEPT

# --- Baseline demo rule set ---
# Intentionally includes one common real-world misconfiguration (SSH open
# to any source) for the firewall-audit tool to detect and flag.
iptables -A INPUT -p tcp --dport 22 -j ACCEPT
# Telnet is correctly blocked (insecure protocol, should never be open).
iptables -A INPUT -p tcp --dport 23 -j DROP

# Keep the container alive in the foreground
exec tail -f /dev/null
