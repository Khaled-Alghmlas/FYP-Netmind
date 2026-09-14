#!/bin/sh
set -e

STATE_FILE="/etc/netmind-fw-rules"

if [ -f "$STATE_FILE" ]; then
    iptables-restore < "$STATE_FILE"
else
    iptables -F
    iptables -P INPUT ACCEPT
    iptables -P FORWARD ACCEPT
    iptables -P OUTPUT ACCEPT
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A INPUT -p icmp -j ACCEPT
    iptables -A INPUT -p tcp --dport 22 -j ACCEPT
    iptables -A INPUT -p tcp --dport 23 -j DROP
    iptables-save > "$STATE_FILE"
fi

exec tail -f /dev/null
