import json
import os
from datetime import datetime
from jinja2 import Environment, BaseLoader

MD_TEMPLATE = """# CIS Audit Agent Report
**Generated:** {{ timestamp }}
**Target:** {{ target_host }}

## Summary
{% if summary.critical > 0 %}🚨 Critical: {{ summary.critical }}{% endif %}
{% if summary.high > 0 %}🔴 High: {{ summary.high }}{% endif %}
{% if summary.medium > 0 %}🟠 Medium: {{ summary.medium }}{% endif %}
{% if summary.low > 0 %}🟡 Low: {{ summary.low }}{% endif %}
✅ Passed: {{ summary.passed }}
❓ Unknown: {{ summary.unknown }}

## Prioritized Remediation Plan
{% if not fix_list %}
No issues found! Your system is perfectly hardened against this ruleset.
{% endif %}
{% for fix in fix_list %}
### [{{ fix.severity }}] {{ fix.rule_id }}: {{ fix.finding }}
- **Category:** {{ fix.category }}
- **Why it matters:** {{ fix.why_it_matters }}
- **Evidence:**
```
{{ fix.evidence_ref }}
```
- **Remediation Command:**
```bash
{{ fix.fix_command }}
```
{% endfor %}

## Raw Evaluation Results
| Rule ID | Title | Status |
|---|---|---|
{% for rule_id, res in evaluated_results.items() -%}
| {{ rule_id }} | {{ res.title }} | {{ res.status }} |
{% endfor %}
"""

class Reporter:
    def __init__(self):
        pass
        
    def generate(self, evaluated_results: dict, fix_list: list, target_host: str, output_dir: str = "reports"):
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

        summary = {
            "critical": len([f for f in fix_list if f["severity"] == "Critical"]),
            "high": len([f for f in fix_list if f["severity"] == "High"]),
            "medium": len([f for f in fix_list if f["severity"] == "Medium"]),
            "low": len([f for f in fix_list if f["severity"] == "Low"]),
            "passed": len([r for r in evaluated_results.values() if r["status"] == "PASS"]),
            "unknown": len([r for r in evaluated_results.values() if r["status"] == "UNKNOWN"]),
        }

        report_data = {
            "timestamp": datetime.now().isoformat(),
            "target_host": target_host,
            "summary": summary,
            "fix_list": fix_list,
            "evaluated_results": evaluated_results
        }
        
        # 1. Write report.json
        json_path = os.path.join(output_dir, "report.json")
        with open(json_path, "w") as f:
            json.dump(report_data, f, indent=4)
            
        # 2. Write report.md
        env = Environment(loader=BaseLoader())
        template = env.from_string(MD_TEMPLATE)
        md_content = template.render(
            timestamp=report_data["timestamp"],
            target_host=target_host,
            summary=summary,
            fix_list=fix_list,
            evaluated_results=evaluated_results
        )
        
        md_path = os.path.join(output_dir, "report.md")
        with open(md_path, "w") as f:
            f.write(md_content)

        return json_path, md_path, report_data
