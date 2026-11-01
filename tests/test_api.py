import pytest


def semgrep_result(rule, line, severity="ERROR"):
    return {
        "check_id": f"python.test.{rule}",
        "path": "sample_vuln/vuln.py",
        "start": {"line": line},
        "extra": {"severity": severity, "message": rule},
    }


def start_scan(client):
    r = client.post("/api/scans", json={"target": "sample_vuln"})
    assert r.status_code == 202
    return r.json()["id"]  # TestClient finishes the background task before returning


def test_health(client):
    assert client.get("/health").json() == {"status": "ok"}


def test_rejects_path_outside_allowed_targets(client):
    assert client.post("/api/scans", json={"target": "../.."}).status_code == 400


def test_unknown_scan_returns_404(client):
    assert client.get("/api/scans/does-not-exist").status_code == 404


def test_scan_starts_running_then_completes(client, fake_scanners):
    fake_scanners(semgrep=[semgrep_result("a", 1), semgrep_result("b", 2)])
    created = client.post("/api/scans", json={"target": "sample_vuln"})
    assert created.status_code == 202
    assert created.json()["status"] == "running"

    scan = client.get(f"/api/scans/{created.json()['id']}").json()
    assert scan["status"] == "completed"
    assert scan["finding_count"] == 2
    assert scan["severity_counts"] == {"HIGH": 2}


def test_filters(client, fake_scanners):
    fake_scanners(semgrep=[semgrep_result("a", 1, "ERROR"), semgrep_result("b", 2, "WARNING")])
    scan_id = start_scan(client)

    high = client.get(f"/api/findings?scan_id={scan_id}&severity=HIGH").json()
    assert high["total"] == 1
    medium = client.get(f"/api/findings?scan_id={scan_id}&severity=MEDIUM").json()
    assert medium["items"][0]["rule_id"].endswith(".b")
    by_rule = client.get(f"/api/findings?scan_id={scan_id}&rule_id=test.a").json()
    assert by_rule["total"] == 1


def test_invalid_filter_value_rejected(client):
    assert client.get("/api/findings?severity=BOGUS").status_code == 422


def test_update_finding_status_and_audit_log(client, fake_scanners):
    fake_scanners(semgrep=[semgrep_result("a", 1)])
    scan_id = start_scan(client)
    finding_id = client.get(f"/api/findings?scan_id={scan_id}").json()["items"][0]["id"]

    r = client.patch(f"/api/findings/{finding_id}", json={"status": "FALSE_POSITIVE"})
    assert r.status_code == 200 and r.json()["status"] == "FALSE_POSITIVE"
    assert client.patch(f"/api/findings/{finding_id}", json={"status": "NONSENSE"}).status_code == 422

    actions = [a["action"] for a in client.get("/api/audit-logs").json()]
    assert "finding.status_changed" in actions
    assert "scan.started" in actions


def test_compare_scans(client, fake_scanners):
    fake_scanners(semgrep=[semgrep_result("a", 1), semgrep_result("b", 2)])
    old_id = start_scan(client)
    fake_scanners(semgrep=[semgrep_result("b", 2), semgrep_result("c", 3)])
    new_id = start_scan(client)

    diff = client.get(f"/api/scans/{new_id}/compare/{old_id}").json()
    assert diff["summary"] == {"new": 1, "resolved": 1, "still_open": 1}
    assert diff["new"][0]["rule_id"].endswith(".c")
    assert diff["resolved"][0]["rule_id"].endswith(".a")


def test_scanner_failure_marks_scan_failed(client, monkeypatch):
    failure = {"success": False, "error": "tool missing"}
    monkeypatch.setattr("app.main.run_scanners",
                        lambda target_dir, output_dir: {"semgrep": failure, "gitleaks": failure})
    scan_id = start_scan(client)
    scan = client.get(f"/api/scans/{scan_id}").json()
    assert scan["status"] == "failed"
    assert set(scan["errors"]) == {"semgrep", "gitleaks"}


@pytest.mark.integration
def test_real_scanners_end_to_end(client):
    scan_id = start_scan(client)
    scan = client.get(f"/api/scans/{scan_id}").json()
    assert scan["status"] == "completed"
    assert scan["finding_count"] > 0