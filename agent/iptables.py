"""Pure iptables helpers: parsing `iptables -L` output and working out which rule is in effect."""
import re

from models import FirewallRule

# Ports commonly worth flagging when left open to any source.
SENSITIVE_PORTS = {22: "SSH", 23: "Telnet", 21: "FTP", 3389: "RDP"}

# INPUT filters traffic addressed to the firewall container itself; FORWARD filters traffic
# *passing through* it to hosts in other branches. Blocking only INPUT therefore does not
# stop e.g. SSH to a host behind the firewall.
FIREWALL_CHAINS = ("INPUT", "FORWARD")


def parse_rules(raw_output, chain="INPUT"):
    """Parse `iptables -L <chain> -n --line-numbers` output into FirewallRule models."""
    lines = raw_output.strip().split("\n")
    rules = []
    for line in lines[2:]:  # skip "Chain X (policy ...)" and the header row
        parts = line.split(None, 5)
        if len(parts) < 5:
            continue
        num, target, prot, _opt, source = parts[:5]
        rest = parts[5] if len(parts) > 5 else ""
        m = re.search(r"dpt:(\d+)", rest)
        rules.append(FirewallRule(chain=chain, rule_num=int(num), action=target, protocol=prot,
                                  source=source, port=int(m.group(1)) if m else None))
    return rules


def effective_port_rules(rules):
    """iptables is first-match-wins: for each (chain, port, protocol), only the topmost
    (lowest rule_num) rule is actually in effect."""
    effective = {}
    for r in sorted(rules, key=lambda r: (r.chain, r.rule_num)):
        if r.port is None:
            continue
        key = (r.chain, r.port, r.protocol)
        if key not in effective:
            effective[key] = r
    return effective
