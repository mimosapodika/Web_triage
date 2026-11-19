cat << 'EOF' > README.md
# Web Triage Hub (OWASP ZAP + Access Log Analyzer)

A zero-dependency Python CLI tool that ingests OWASP ZAP JSON scan exports and Nginx/Apache access logs, detects live web attacks (SQLi, XSS, Path Traversal), deduplicates findings, and generates an XSS-safe HTML triage report.

## Usage
```bash
# Run with built-in demo files
python3 web_triage_hub.py --demo

# Run with real OWASP ZAP JSON and server logs
python3 web_triage_hub.py --zap scan.json --log access.log --out report.html
