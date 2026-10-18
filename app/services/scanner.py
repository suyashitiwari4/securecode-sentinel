import json
from pathlib import Path

SEVERITY_MAP = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}


def load_json_report(report_path):
    path = Path(report_path)
    if not path.exists():
        raise FileNotFoundError(f"Report not found: {path}")
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def read_source_line(file_path, line, base_dir=None):
    """Return the stripped source line, or '' if it can't be read."""
    candidates = [Path(file_path)]
    if base_dir:
        candidates.append(Path(base_dir) / file_path)
    for p in candidates:
        if p.is_file() and line:
            lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
            if 1 <= line <= len(lines):
                return lines[line - 1].strip()
    return ""


def parse_semgrep(report_path):
    report = load_json_report(report_path)
    findings = []
    for r in report.get("results", []):
        extra = r.get("extra", {})
        line = r.get("start", {}).get("line")
        rule_id = r.get("check_id", "unknown")
        findings.append({
            "scanner": "Semgrep",
            "rule_id": rule_id,
            "severity": SEVERITY_MAP.get(extra.get("severity", "").upper(), "UNKNOWN"),
            "file": r.get("path", ""),
            "line": line,
            "title": rule_id.split(".")[-1],
            "message": extra.get("message", ""),
            "evidence": read_source_line(r.get("path", ""), line),
            "status": "OPEN",
        })
    return findings


def parse_gitleaks(report_path, source_dir="sample_vuln"):
    report = load_json_report(report_path)
    if not isinstance(report, list):
        raise ValueError("Unexpected Gitleaks report format")
    findings = []
    for r in report:
        line = r.get("StartLine")
        file_path = r.get("File", "")
        evidence = read_source_line(file_path, line, base_dir=source_dir)
        secret = r.get("Secret")
        if secret:
            evidence = evidence.replace(secret, "[REDACTED]")
        findings.append({
            "scanner": "Gitleaks",
            "rule_id": r.get("RuleID", "unknown"),
            "severity": "HIGH",  # app convention, not assigned by Gitleaks
            "file": file_path,
            "line": line,
            "title": r.get("Description", "Potential secret detected"),
            "message": r.get("Description", "Potential secret detected"),
            "evidence": evidence,
            "status": "OPEN",
        })
    return findings


def combine_reports(semgrep_path, gitleaks_path):
    return parse_semgrep(semgrep_path) + parse_gitleaks(gitleaks_path)


def main():
    findings = combine_reports("semgrep_report.json", "gitleaks_report.json")
    out = Path("combined_report.json")
    out.write_text(json.dumps(findings, indent=2), encoding="utf-8")
    print(f"Total findings: {len(findings)}")
    print(f"Combined report saved to: {out.resolve()}")


if __name__ == "__main__":
    main()