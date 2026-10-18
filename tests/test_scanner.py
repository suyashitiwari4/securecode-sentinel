import json

import pytest

from app.services.scanner import (
    combine_reports,
    load_json_report,
    parse_gitleaks,
    parse_semgrep,
)


def write_json(path, data):
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def test_missing_report_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_json_report(tmp_path / "nope.json")


def test_semgrep_parsing_and_severity_mapping(tmp_path):
    source = tmp_path / "vuln.py"
    source.write_text("x = 1\nresult = eval(user_input)\n", encoding="utf-8")

    report = write_json(tmp_path / "semgrep.json", {
        "results": [{
            "check_id": "python.lang.security.audit.eval-detected",
            "path": str(source),
            "start": {"line": 2},
            "extra": {"severity": "ERROR", "message": "eval is dangerous"},
        }]
    })

    findings = parse_semgrep(report)

    assert len(findings) == 1
    f = findings[0]
    assert f["scanner"] == "Semgrep"
    assert f["severity"] == "HIGH"          # ERROR -> HIGH
    assert f["line"] == 2
    assert f["title"] == "eval-detected"
    assert f["evidence"] == "result = eval(user_input)"
    assert f["status"] == "OPEN"


def test_semgrep_empty_results(tmp_path):
    report = write_json(tmp_path / "semgrep.json", {"results": []})
    assert parse_semgrep(report) == []


def test_gitleaks_redacts_secret(tmp_path):
    source = tmp_path / "vuln.py"
    source.write_text('api_key = "FAKESECRET123456"\n', encoding="utf-8")

    report = write_json(tmp_path / "gitleaks.json", [{
        "RuleID": "generic-api-key",
        "Description": "Generic API Key",
        "File": "vuln.py",
        "StartLine": 1,
        "Secret": "FAKESECRET123456",
    }])

    findings = parse_gitleaks(report, source_dir=tmp_path)

    assert len(findings) == 1
    assert findings[0]["scanner"] == "Gitleaks"
    assert "FAKESECRET123456" not in findings[0]["evidence"]
    assert "[REDACTED]" in findings[0]["evidence"]


def test_gitleaks_empty_list(tmp_path):
    report = write_json(tmp_path / "gitleaks.json", [])
    assert parse_gitleaks(report) == []


def test_gitleaks_unexpected_format_raises(tmp_path):
    report = write_json(tmp_path / "gitleaks.json", {"oops": "not a list"})
    with pytest.raises(ValueError):
        parse_gitleaks(report)


def test_combine_reports(tmp_path):
    semgrep = write_json(tmp_path / "s.json", {"results": [{
        "check_id": "a.b.rule", "path": "x.py", "start": {"line": 1},
        "extra": {"severity": "WARNING", "message": "m"},
    }]})
    gitleaks = write_json(tmp_path / "g.json", [{
        "RuleID": "r", "File": "x.py", "StartLine": 1, "Secret": "",
    }])

    findings = combine_reports(semgrep, gitleaks)

    assert [f["scanner"] for f in findings] == ["Semgrep", "Gitleaks"]
    assert findings[0]["severity"] == "MEDIUM"   # WARNING -> MEDIUM