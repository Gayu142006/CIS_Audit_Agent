from typing import Dict, Any, List

# Static mapping for remediation rules (Deterministic - no LLM drift)
REMEDIATION_MAP = {
    "CIS-5.2.10": {
        "severity": "Critical",
        "priority_score": 1,
        "category": "SSH Hardening",
        "why_it_matters": "A leaked or brute-forced root credential grants full remote access with no separate privilege step.",
        "fix_command": "sudo sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config && sudo systemctl reload sshd"
    },
    "CIS-5.2.11": {
        "severity": "High",
        "priority_score": 2,
        "category": "SSH Hardening",
        "why_it_matters": "Password authentication is susceptible to brute-force attacks. Key-based authentication is much stronger.",
        "fix_command": "sudo sed -i 's/^PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config && sudo systemctl reload sshd"
    },
    "CIS-5.3.1": {
        "severity": "Medium",
        "priority_score": 3,
        "category": "Password Policy",
        "why_it_matters": "Short passwords are easy to crack. Enforcing a minimum length mitigates brute-force attacks.",
        "fix_command": "sudo sed -i 's/^minlen.*/minlen = 14/' /etc/security/pwquality.conf"
    },
    "CIS-1.1.2": {
        "severity": "High",
        "priority_score": 2,
        "category": "File Permissions",
        "why_it_matters": "World-writable sensitive files can be modified by any user, leading to privilege escalation.",
        "fix_command": "sudo chmod -R o-w /etc /var"
    },
    "CIS-6.1.2": {
        "severity": "Medium",
        "priority_score": 3,
        "category": "File Permissions",
        "why_it_matters": "Incorrect permissions on /etc/passwd can allow unauthorized users to modify account configurations.",
        "fix_command": "sudo chmod 644 /etc/passwd"
    },
    "CIS-6.1.3": {
        "severity": "Critical",
        "priority_score": 1,
        "category": "File Permissions",
        "why_it_matters": "The /etc/shadow file contains password hashes. If readable by others, attackers can crack the hashes.",
        "fix_command": "sudo chmod 640 /etc/shadow && sudo chown root:shadow /etc/shadow"
    },
    "CIS-3.5.1": {
        "severity": "High",
        "priority_score": 2,
        "category": "Network Security",
        "why_it_matters": "An inactive firewall exposes all running services to the network unnecessarily.",
        "fix_command": "sudo ufw enable || sudo systemctl enable --now iptables"
    },
    "CIS-1.9": {
        "severity": "Low",
        "priority_score": 4,
        "category": "System Maintenance",
        "why_it_matters": "Without automatic updates, security patches might be missed, leaving the system vulnerable to known exploits.",
        "fix_command": "sudo apt-get install unattended-upgrades -y && sudo dpkg-reconfigure -plow unattended-upgrades"
    },
    "CIS-6.2.1": {
        "severity": "Critical",
        "priority_score": 1,
        "category": "Account Security",
        "why_it_matters": "Empty passwords allow anyone to log in as the user without authentication.",
        "fix_command": "sudo awk -F: '($2 == \"\") {print $1}' /etc/shadow | xargs -I {} sudo passwd -l {}"
    },
    "CIS-5.3.4": {
        "severity": "High",
        "priority_score": 2,
        "category": "Privilege Escalation",
        "why_it_matters": "Sudo NOPASSWD allows users to run privileged commands without verifying their identity again.",
        "fix_command": "sudo sed -i '/NOPASSWD/d' /etc/sudoers"
    }
}

class Prioritizer:
    def __init__(self):
        pass

    def prioritize(self, evaluated_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        fix_list = []
        
        for rule_id, result in evaluated_results.items():
            if result["status"] == "FAIL":
                mapping = REMEDIATION_MAP.get(rule_id, {})
                fix_list.append({
                    "priority_score": mapping.get("priority_score", 99),
                    "severity": mapping.get("severity", "Unknown"),
                    "rule_id": rule_id,
                    "category": mapping.get("category", "General"),
                    "finding": result["title"],
                    "why_it_matters": mapping.get("why_it_matters", "Security risk."),
                    "fix_command": mapping.get("fix_command", "Manual remediation required."),
                    "evidence_ref": result["evidence"]
                })
        
        # Sort by priority score (1 = highest priority)
        fix_list.sort(key=lambda x: x["priority_score"])
        
        # Remove the internal priority score before returning to user
        for item in fix_list:
            del item["priority_score"]
            
        return fix_list
