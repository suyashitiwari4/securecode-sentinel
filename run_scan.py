import json
from pathlib import Path

from app.services.runner import run_scanners
from app.services.scanner import parse_gitleaks, parse_semgrep

root = Path(__file__).resolve().parent
target = root / "sample_vuln"

results = run_scanners(target_dir=target, output_dir=root / "reports")

findings = []
for name, result in results.items():
    print(f"\n{name}: {result}")

if results["semgrep"]["success"]:
    findings += parse_semgrep(results["semgrep"]["report_path"])
if results["gitleaks"]["success"]:
    findings += parse_gitleaks(results["gitleaks"]["report_path"], source_dir=target)

out = root / "combined_report.json"
out.write_text(json.dumps(findings, indent=2), encoding="utf-8")
print(f"\nTotal findings: {len(findings)}")
print(f"Saved to: {out}")