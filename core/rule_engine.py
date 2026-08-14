import re
from typing import Dict, Any

class RuleEngine:
    def __init__(self):
        pass

    def evaluate(self, raw_results: Dict[str, Any]) -> Dict[str, Any]:
        evaluated = {}
        for rule_id, data in raw_results.items():
            stdout = data.get("raw_stdout", "").lower().strip()
            stderr = data.get("raw_stderr", "").lower().strip()
            exit_code = data.get("exit_code", -1)
            
            status = "UNKNOWN"
            
            if "command not found" in stderr or "no such file" in stderr:
                status = "UNKNOWN"
            else:
                if rule_id == "CIS-5.2.10":
                    if "permitrootlogin yes" in stdout:
                        status = "FAIL"
                    elif "permitrootlogin" in stdout:
                        status = "PASS"
                    else:
                        status = "UNKNOWN"
                
                elif rule_id == "CIS-5.2.11":
                    if "passwordauthentication yes" in stdout:
                        status = "FAIL"
                    elif "passwordauthentication" in stdout:
                        status = "PASS"
                    else:
                        status = "UNKNOWN"
                        
                elif rule_id == "CIS-5.3.1":
                    if stdout.startswith("minlen"):
                        try:
                            # e.g., minlen = 14
                            val = int(re.search(r'\d+', stdout).group())
                            if val < 12:
                                status = "FAIL"
                            else:
                                status = "PASS"
                        except:
                            status = "FAIL"
                    else:
                        status = "FAIL"

                elif rule_id == "CIS-1.1.2":
                    if stdout == "":
                        status = "PASS"
                    else:
                        status = "FAIL"

                elif rule_id == "CIS-6.1.2":
                    if stdout == "644":
                        status = "PASS"
                    elif stdout == "":
                        status = "UNKNOWN"
                    else:
                        status = "FAIL"

                elif rule_id == "CIS-6.1.3":
                    if stdout in ["640", "600"]:
                        status = "PASS"
                    elif stdout == "":
                        status = "UNKNOWN"
                    else:
                        status = "FAIL"

                elif rule_id == "CIS-3.5.1":
                    if "inactive" in stdout or stdout == "":
                        status = "FAIL"
                    elif "status: active" in stdout or "chain" in stdout:
                        status = "PASS"
                    else:
                        status = "UNKNOWN"

                elif rule_id == "CIS-1.9":
                    if "enabled" in stdout:
                        status = "PASS"
                    elif "disabled" in stdout:
                        status = "FAIL"
                    else:
                        status = "UNKNOWN"

                elif rule_id == "CIS-6.2.1":
                    if "permission-denied" in stdout or exit_code != 0:
                        status = "UNKNOWN"
                    elif stdout == "":
                        status = "PASS"
                    else:
                        status = "FAIL"

                elif rule_id == "CIS-5.3.4":
                    if stdout == "":
                        status = "PASS"
                    else:
                        status = "FAIL"

            evaluated[rule_id] = {
                "rule_id": rule_id,
                "title": data["title"],
                "command": data["command"],
                "status": status,
                "evidence": stdout if stdout else stderr
            }
            
        return evaluated
