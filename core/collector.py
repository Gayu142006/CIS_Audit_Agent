import json
from typing import Dict, Any

from core.connector import BaseConnector

ALLOWLIST = {
    "CIS-5.2.10": {
        "title": "SSH root login disabled",
        "command": "sshd -T 2>/dev/null | grep -i permitrootlogin || cat /etc/ssh/sshd_config 2>/dev/null | grep -i permitrootlogin"
    },
    "CIS-5.2.11": {
        "title": "SSH password auth disabled",
        "command": "sshd -T 2>/dev/null | grep -i passwordauthentication || cat /etc/ssh/sshd_config 2>/dev/null | grep -i passwordauthentication"
    },
    "CIS-5.3.1": {
        "title": "Password length policy set",
        "command": "grep '^minlen' /etc/security/pwquality.conf 2>/dev/null || echo ''"
    },
    "CIS-1.1.2": {
        "title": "No world-writable sensitive files",
        "command": "find /etc /var -perm -0002 -type f 2>/dev/null | head -n 5"
    },
    "CIS-6.1.2": {
        "title": "Correct /etc/passwd permissions",
        "command": "stat -c '%a' /etc/passwd 2>/dev/null || echo ''"
    },
    "CIS-6.1.3": {
        "title": "Correct /etc/shadow permissions",
        "command": "stat -c '%a' /etc/shadow 2>/dev/null || echo ''"
    },
    "CIS-3.5.1": {
        "title": "Firewall active",
        "command": "ufw status 2>/dev/null || iptables -L 2>/dev/null | grep -i 'Chain' | head -n 1"
    },
    "CIS-1.9": {
        "title": "Automatic updates enabled",
        "command": "systemctl is-enabled unattended-upgrades 2>/dev/null || echo 'not-found'"
    },
    "CIS-6.2.1": {
        "title": "No empty passwords",
        "command": "awk -F: '($2 == \"\")' /etc/shadow 2>/dev/null || echo 'permission-denied'"
    },
    "CIS-5.3.4": {
        "title": "No sudo NOPASSWD wildcards",
        "command": "cat /etc/sudoers 2>/dev/null | grep -v '^#' | grep NOPASSWD || echo ''"
    }
}

class Collector:
    def __init__(self, connector: BaseConnector):
        self.connector = connector

    def run_all(self) -> Dict[str, Any]:
        results = {}
        for rule_id, rule_data in ALLOWLIST.items():
            cmd = rule_data["command"]
            out, err, exit_code = self.connector.execute(cmd)
            
            # Record findings securely
            results[rule_id] = {
                "rule_id": rule_id,
                "title": rule_data["title"],
                "command": cmd,
                "raw_stdout": out,
                "raw_stderr": err,
                "exit_code": exit_code
            }
        return results
