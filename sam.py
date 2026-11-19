import argparse
import html
import json
import re
from pathlib import Path
from urllib.parse import unquote

SEVERITY_ORDER = {"Critical": 1, "High": 2, "Medium": 3, "Low": 4, "Info": 5}
ZAP_RISK_MAP = {"3": "High", "2": "Medium", "1": "Low", "0": "Info"}

LOG_REGEX = re.compile(r'(?P<ip>\S+) .*?"(?P<method>\S+) (?P<path>\S+) .*?" (?P<status>\d{3})')
ATTACK_RULES = [
    ("SQL Injection", "Critical", re.compile(r"(union\s+select|'|\bor\b\s+1=1|--)", re.I)),
    ("XSS Attempt", "High", re.compile(r"(<script|javascript:|onerror=|onload=)", re.I)),
    ("Path Traversal", "Critical", re.compile(r"(\.\./|/etc/passwd|\.env)", re.I)),
]


def parse_zap_json(path):
    """Tool 1: Extracts web vulnerabilities from an OWASP ZAP JSON export."""
    findings = []
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    sites = data.get("site", [])
    if isinstance(sites, dict):
        sites = [sites]

    for site in sites:
        target = site.get("@name", "Web App")
        for alert in site.get("alerts", []):
            severity = ZAP_RISK_MAP.get(str(alert.get("riskcode", "0")), "Info")
            findings.append({
                "source": "OWASP ZAP",
                "severity": severity,
                "title": alert.get("name", "Web Vulnerability"),
                "target": target,
                "detail": f"{len(alert.get('instances', []))} endpoint(s) flagged by scanner",
            })
    return findings


def parse_access_log(path):
    """Tool 2: Detects live web attacks from Nginx/Apache access logs."""
    findings = []
    for line in Path(path).read_text(encoding="utf-8", errors="ignore").splitlines():
        match = LOG_REGEX.search(line)
        if not match:
            continue
        decoded_path = unquote(match.group("path"))
        for attack_name, severity, pattern in ATTACK_RULES:
            if pattern.search(decoded_path):
                findings.append({
                    "source": "Access Log",
                    "severity": severity,
                    "title": f"Live {attack_name}",
                    "target": match.group("ip"),
                    "detail": f"{match.group('method')} {decoded_path[:75]} (HTTP {match.group('status')})",
                })
    return findings


def generate_html_report(findings, out_file):
    """Deduplicates findings, ranks by severity, and exports an XSS-safe HTML dashboard."""
    seen, unique = set(), []
    for f in findings:
        key = (f["source"], f["title"], f["target"])
        if key not in seen:
            seen.add(key)
            unique.append(f)

    unique.sort(key=lambda x: SEVERITY_ORDER.get(x["severity"], 99))

    rows = "".join(
        f"<tr>"
        f"<td class='sev-{html.escape(f['severity']).lower()}'><strong>{html.escape(f['severity'])}</strong></td>"
        f"<td>{html.escape(f['source'])}</td>"
        f"<td>{html.escape(f['title'])}</td>"
        f"<td><code>{html.escape(f['target'])}</code></td>"
        f"<td><code>{html.escape(f['detail'])}</code></td>"
        f"</tr>"
        for f in unique
    )

    page = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><title>Unified Web Security Triage Report</title>
<style>
  body {{ font-family: Arial, sans-serif; margin: 32px; color: #1f2937; }}
  .summary {{ background: #f3f4f6; padding: 14px; border-radius: 6px; margin-bottom: 20px; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 14px; }}
  th, td {{ border: 1px solid #d1d5db; padding: 10px; text-align: left; }}
  th {{ background: #111827; color: #ffffff; }}
  .sev-critical {{ color: #991b1b; }} .sev-high {{ color: #dc2626; }}
  .sev-medium {{ color: #d97706; }} .sev-low {{ color: #2563eb; }}
</style>
</head>
<body>
  <h1>Unified Web Security Triage Report</h1>
  <div class="summary">
    <strong>Total Unique Findings:</strong> {len(unique)} &nbsp;|&nbsp;
    <strong>Duplicates Removed:</strong> {len(findings) - len(unique)}
  </div>
  <table>
    <thead><tr><th>Severity</th><th>Source Tool</th><th>Finding</th><th>Target / IP</th><th>Evidence</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
</body>
</html>"""
    Path(out_file).write_text(page, encoding="utf-8")
    return len(unique)


def create_demo_files():
    Path("demo_zap.json").write_text(json.dumps({
        "site": [{"@name": "http://127.0.0.1:8000", "alerts": [
            {"name": "Missing Anti-clickjacking Header", "riskcode": "2", "instances": [{"uri": "/"}, {"uri": "/login"}]},
            {"name": "SQL Injection - SQLite", "riskcode": "3", "instances": [{"uri": "/api/tickets?id=1"}]},
        ]}]
    }, indent=2), encoding="utf-8")

    Path("demo_access.log").write_text(
        '203.0.113.45 - - [19/Nov/2026:10:01:10 +0530] "GET /api/tickets?id=1%20UNION%20SELECT%201,2-- HTTP/1.1" 500 512\n'
        '203.0.113.45 - - [19/Nov/2026:10:01:12 +0530] "GET /download?file=../../etc/passwd HTTP/1.1" 403 256\n'
        '198.51.100.77 - - [19/Nov/2026:10:02:01 +0530] "GET /search?q=<script>alert(1)</script> HTTP/1.1" 200 840\n',
        encoding="utf-8"
    )
    return "demo_zap.json", "demo_access.log"


def main():
    parser = argparse.ArgumentParser(description="Multi-Tool Web Security Triage Hub (OWASP ZAP + Access Logs)")
    parser.add_argument("--zap", help="Path to OWASP ZAP JSON report")
    parser.add_argument("--log", help="Path to Nginx/Apache access.log")
    parser.add_argument("--out", default="web_triage_report.html", help="Output HTML report filename")
    parser.add_argument("--demo", action="store_true", help="Generate sample ZAP + log files and run demo")
    args = parser.parse_args()

    if args.demo:
        args.zap, args.log = create_demo_files()
    if not args.zap and not args.log:
        parser.error("Provide --zap, --log, or --demo.")

    all_findings = []
    if args.zap:
        all_findings.extend(parse_zap_json(args.zap))
    if args.log:
        all_findings.extend(parse_access_log(args.log))

    unique_count = generate_html_report(all_findings, args.out)
    print(f"[✓] Processed {len(all_findings)} raw alerts -> {unique_count} unique findings saved to {args.out}")


if __name__ == "__main__":
    main()
