# CIS Audit Agent Report
**Generated:** 2026-08-14T11:53:14.266643
**Target:** localhost

## Summary

🔴 High: 2
🟠 Medium: 1

✅ Passed: 3
❓ Unknown: 4

## Prioritized Remediation Plan


### [High] CIS-5.2.11: SSH password auth disabled
- **Category:** SSH Hardening
- **Why it matters:** Password authentication is susceptible to brute-force attacks. Key-based authentication is much stronger.
- **Evidence:**
```
#passwordauthentication yes
# passwordauthentication.  depending on your pam configuration,
# pam authentication, then enable this but set passwordauthentication
```
- **Remediation Command:**
```bash
sudo sed -i 's/^PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config && sudo systemctl reload sshd
```

### [High] CIS-3.5.1: Firewall active
- **Category:** Network Security
- **Why it matters:** An inactive firewall exposes all running services to the network unnecessarily.
- **Evidence:**
```

```
- **Remediation Command:**
```bash
sudo ufw enable || sudo systemctl enable --now iptables
```

### [Medium] CIS-5.3.1: Password length policy set
- **Category:** Password Policy
- **Why it matters:** Short passwords are easy to crack. Enforcing a minimum length mitigates brute-force attacks.
- **Evidence:**
```

```
- **Remediation Command:**
```bash
sudo sed -i 's/^minlen.*/minlen = 14/' /etc/security/pwquality.conf
```


## Raw Evaluation Results
| Rule ID | Title | Status |
|---|---|---|
| CIS-5.2.10 | SSH root login disabled | PASS |
| CIS-5.2.11 | SSH password auth disabled | FAIL |
| CIS-5.3.1 | Password length policy set | FAIL |
| CIS-1.1.2 | No world-writable sensitive files | PASS |
| CIS-6.1.2 | Correct /etc/passwd permissions | UNKNOWN |
| CIS-6.1.3 | Correct /etc/shadow permissions | UNKNOWN |
| CIS-3.5.1 | Firewall active | FAIL |
| CIS-1.9 | Automatic updates enabled | UNKNOWN |
| CIS-6.2.1 | No empty passwords | UNKNOWN |
| CIS-5.3.4 | No sudo NOPASSWD wildcards | PASS |
