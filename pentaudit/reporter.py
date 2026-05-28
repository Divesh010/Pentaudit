"""
reporter.py — Report Generation Module
========================================

WHAT THIS MODULE DOES:
Takes all findings from the auditor and generates a beautiful HTML report
that looks professional enough for a real security engagement.

THE REPORT INCLUDES:
- Executive summary with overall risk score
- Each finding with risk level, evidence, MITRE mapping, and remediation
- Findings summary table
- MITRE ATT&CK coverage visualization
- Scan metadata (target, date, platforms found)

HOW IT WORKS:
Uses Jinja2 templating to fill in an HTML template with our findings data.
Think of it like a mail merge — the template has placeholders like
{{ finding.title }} that get replaced with actual data.
"""

import os
import json
from datetime import datetime

from pentaudit.config import RISK_LEVELS, MITRE_TECHNIQUES
from pentaudit.utils import print_phase, print_success, print_info, print_error

try:
    from jinja2 import Template
    JINJA_AVAILABLE = True
except ImportError:
    JINJA_AVAILABLE = False


class ReportGenerator:
    """
    Generates a professional HTML security audit report.
    
    USAGE:
        reporter = ReportGenerator(findings, platforms, scan_metadata)
        reporter.generate("report.html")
    """

    def __init__(self, findings, platforms, scan_metadata=None):
        """
        Args:
            findings:      List of finding dicts from SecurityAuditor
            platforms:     List of platform dicts from DiscoveryScanner
            scan_metadata: Optional dict with scan info (target, date, etc.)
        """
        self.findings = findings
        self.platforms = platforms
        self.scan_metadata = scan_metadata or {}

    def generate(self, output_path):
        """Generate the HTML report and save to output_path."""
        print_phase("PHASE 3: REPORT GENERATION")

        # Calculate summary statistics
        stats = self._calculate_stats()
        
        # Build the report data
        report_data = {
            "title": "PentAudit Security Assessment Report",
            "subtitle": "Autonomous Pentest Platform & AI Security Tool Audit",
            "author": "Divesh Gupta",
            "date": datetime.now().strftime("%B %d, %Y"),
            "timestamp": datetime.now().isoformat(),
            "target": self.scan_metadata.get("target", "N/A"),
            "scan_mode": self.scan_metadata.get("mode", "standard"),
            "platforms": self.platforms,
            "findings": self.findings,
            "stats": stats,
            "risk_levels": RISK_LEVELS,
            "mitre_techniques": MITRE_TECHNIQUES,
        }

        # Generate HTML
        print_info("Building HTML report...")
        html_content = self._render_html(report_data)

        # Save to file
        try:
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(html_content)
            print_success(f"Report saved to: {output_path}")
        except Exception as e:
            print_error(f"Failed to save report: {e}")

        # Also save findings as JSON (machine-readable)
        json_path = output_path.replace(".html", ".json")
        try:
            with open(json_path, "w", encoding="utf-8") as f:
                json.dump(report_data, f, indent=2, default=str)
            print_success(f"JSON data saved to: {json_path}")
        except Exception as e:
            print_error(f"Failed to save JSON: {e}")

        return output_path

    def _calculate_stats(self):
        """Calculate summary statistics from findings."""
        stats = {
            "total_findings": len(self.findings),
            "total_platforms": len(self.platforms),
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
            "overall_risk": "LOW",
            "mitre_techniques_covered": set(),
        }

        for f in self.findings:
            level = f["risk_level"].lower()
            if level in stats:
                stats[level] += 1
            if f.get("mitre_technique"):
                stats["mitre_techniques_covered"].add(f["mitre_technique"])

        # Calculate overall risk
        if stats["critical"] > 0:
            stats["overall_risk"] = "CRITICAL"
        elif stats["high"] > 0:
            stats["overall_risk"] = "HIGH"
        elif stats["medium"] > 0:
            stats["overall_risk"] = "MEDIUM"
        else:
            stats["overall_risk"] = "LOW"

        stats["mitre_techniques_covered"] = list(stats["mitre_techniques_covered"])
        return stats

    def _render_html(self, data):
        """Render the HTML report using the template."""
        template_str = self._get_template()
        
        if JINJA_AVAILABLE:
            template = Template(template_str)
            return template.render(**data)
        else:
            # Fallback: basic string replacement
            return self._render_fallback(template_str, data)

    def _render_fallback(self, template_str, data):
        """Simple fallback renderer if Jinja2 is not installed."""
        # Build findings HTML manually
        findings_html = ""
        for f in data["findings"]:
            color = RISK_LEVELS.get(f["risk_level"], {}).get("color", "#666")
            findings_html += f"""
            <div class="finding-card" style="border-left: 4px solid {color};">
                <div class="finding-header">
                    <span class="check-id">{f['check_id']}</span>
                    <span class="risk-badge" style="background: {color};">{f['risk_level']}</span>
                </div>
                <h3>{f['title']}</h3>
                <p><strong>Platform:</strong> {f['platform_name']} ({f['platform_host']})</p>
                <p><strong>Description:</strong> {f['description']}</p>
                <div class="evidence"><strong>Evidence:</strong><pre>{f['evidence']}</pre></div>
                <p><strong>MITRE ATT&CK:</strong> {f['mitre_technique']} — {f.get('mitre_details', {}).get('name', 'N/A')}</p>
                <p><strong>Remediation:</strong> {f['remediation']}</p>
                <p><strong>NIST Control:</strong> {f['nist_control']}</p>
            </div>
            """

        # Build platforms HTML
        platforms_html = ""
        for p in data["platforms"]:
            platforms_html += f"<tr><td>{p['host']}</td><td>{p['port']}</td><td>{p['platform']}</td><td>{p['confidence']}</td></tr>"

        return template_str.replace("{{FINDINGS_HTML}}", findings_html).replace(
            "{{PLATFORMS_HTML}}", platforms_html
        ).replace("{{DATE}}", data["date"]).replace(
            "{{TARGET}}", data["target"]
        ).replace("{{TOTAL}}", str(data["stats"]["total_findings"])).replace(
            "{{CRITICAL}}", str(data["stats"]["critical"])
        ).replace("{{HIGH}}", str(data["stats"]["high"])).replace(
            "{{MEDIUM}}", str(data["stats"]["medium"])
        ).replace("{{LOW}}", str(data["stats"]["low"])).replace(
            "{{INFO}}", str(data["stats"]["info"])
        ).replace("{{OVERALL_RISK}}", data["stats"]["overall_risk"]).replace(
            "{{PLATFORMS_COUNT}}", str(data["stats"]["total_platforms"])
        )

    def _get_template(self):
        """Return the HTML report template string."""
        # Check for external template file first
        template_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "templates")
        template_path = os.path.join(template_dir, "report_template.html")
        
        if os.path.exists(template_path):
            with open(template_path, "r", encoding="utf-8") as f:
                return f.read()
        
        # Fallback: use the inline template (non-Jinja2 version)
        return self._get_fallback_template()

    def _get_fallback_template(self):
        """Inline HTML template for when Jinja2 is not available."""
        return """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>PentAudit Security Assessment Report</title>
<style>
body { font-family: 'Segoe UI', Arial, sans-serif; margin: 0; padding: 0; background: #0f0f1a; color: #e0e0e0; }
.container { max-width: 1100px; margin: 0 auto; padding: 20px; }
.header { text-align: center; padding: 40px 20px; background: linear-gradient(135deg, #1a1a2e, #16213e); border-bottom: 3px solid #e94560; }
.header h1 { font-size: 2.2em; color: #fff; margin: 0; }
.header p { color: #aaa; font-size: 1.1em; }
.meta { display: flex; justify-content: space-around; padding: 20px; background: #16213e; margin: 20px 0; border-radius: 8px; }
.meta-item { text-align: center; }
.meta-item .label { font-size: 0.85em; color: #888; }
.meta-item .value { font-size: 1.3em; font-weight: bold; color: #fff; }
.stats { display: flex; gap: 15px; margin: 20px 0; flex-wrap: wrap; }
.stat-card { flex: 1; min-width: 100px; padding: 20px; border-radius: 8px; text-align: center; }
.stat-card .number { font-size: 2em; font-weight: bold; }
.stat-card .label { font-size: 0.85em; opacity: 0.9; }
.stat-critical { background: linear-gradient(135deg, #DC3545, #a71d2a); color: #fff; }
.stat-high { background: linear-gradient(135deg, #FD7E14, #c95a00); color: #fff; }
.stat-medium { background: linear-gradient(135deg, #FFC107, #d4a200); color: #000; }
.stat-low { background: linear-gradient(135deg, #28A745, #1e7b34); color: #fff; }
.stat-info { background: linear-gradient(135deg, #17A2B8, #0e7c8c); color: #fff; }
h2 { color: #e94560; border-bottom: 2px solid #e94560; padding-bottom: 8px; margin-top: 40px; }
table { width: 100%; border-collapse: collapse; margin: 15px 0; }
th { background: #16213e; color: #e94560; padding: 12px; text-align: left; border: 1px solid #2a2a4a; }
td { padding: 10px 12px; border: 1px solid #2a2a4a; background: #1a1a2e; }
tr:hover td { background: #1e2a3e; }
.finding-card { background: #1a1a2e; border-radius: 8px; padding: 20px; margin: 15px 0; border: 1px solid #2a2a4a; }
.finding-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; }
.check-id { font-family: monospace; font-size: 0.95em; color: #888; }
.risk-badge { color: #fff; padding: 4px 12px; border-radius: 4px; font-weight: bold; font-size: 0.85em; }
.finding-card h3 { margin: 8px 0; color: #fff; }
.finding-card p { margin: 6px 0; color: #ccc; line-height: 1.5; }
.evidence { background: #0d1117; padding: 12px; border-radius: 6px; margin: 10px 0; }
.evidence pre { margin: 0; white-space: pre-wrap; font-size: 0.9em; color: #79c0ff; }
.footer { text-align: center; padding: 30px; color: #555; font-size: 0.9em; border-top: 1px solid #2a2a4a; margin-top: 40px; }
</style>
</head>
<body>
<div class="header">
<h1>PentAudit Security Assessment Report</h1>
<p>Autonomous Pentest Platform & AI Security Tool Audit</p>
</div>
<div class="container">
<div class="meta">
<div class="meta-item"><div class="label">Date</div><div class="value">{{DATE}}</div></div>
<div class="meta-item"><div class="label">Target</div><div class="value">{{TARGET}}</div></div>
<div class="meta-item"><div class="label">Platforms Found</div><div class="value">{{PLATFORMS_COUNT}}</div></div>
<div class="meta-item"><div class="label">Overall Risk</div><div class="value">{{OVERALL_RISK}}</div></div>
</div>
<h2>Risk Summary</h2>
<div class="stats">
<div class="stat-card stat-critical"><div class="number">{{CRITICAL}}</div><div class="label">Critical</div></div>
<div class="stat-card stat-high"><div class="number">{{HIGH}}</div><div class="label">High</div></div>
<div class="stat-card stat-medium"><div class="number">{{MEDIUM}}</div><div class="label">Medium</div></div>
<div class="stat-card stat-low"><div class="number">{{LOW}}</div><div class="label">Low</div></div>
<div class="stat-card stat-info"><div class="number">{{INFO}}</div><div class="label">Info</div></div>
</div>
<h2>Discovered Platforms</h2>
<table><tr><th>Host</th><th>Port</th><th>Platform</th><th>Confidence</th></tr>{{PLATFORMS_HTML}}</table>
<h2>Detailed Findings</h2>
{{FINDINGS_HTML}}
<div class="footer">
<p>Generated by PentAudit v1.0.0 | Author: Divesh Gupta</p>
<p>This report is confidential. Unauthorized distribution is prohibited.</p>
</div>
</div>
</body>
</html>"""
