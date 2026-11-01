from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_health():
    assert client.get("/health").json() == {"status": "ok"}


def test_rejects_path_outside_allowed_targets():
    r = client.post("/api/scans", json={"target": "../.."})
    assert r.status_code == 400


def test_unknown_scan_returns_404():
    assert client.get("/api/scans/does-not-exist").status_code == 404


def test_create_and_fetch_scan():
    created = client.post("/api/scans", json={"target": "sample_vuln"})
    assert created.status_code == 201
    scan_id = created.json()["id"]

    fetched = client.get(f"/api/scans/{scan_id}")
    assert fetched.status_code == 200
    assert fetched.json()["id"] == scan_id
def test_update_finding_status():
    scan = client.post("/api/scans", json={"target": "sample_vuln"}).json()
    finding_id = scan["findings"][0]["id"]

    r = client.patch(f"/api/findings/{finding_id}", json={"status": "FALSE_POSITIVE"})
    assert r.status_code == 200
    assert r.json()["status"] == "FALSE_POSITIVE"

    bad = client.patch(f"/api/findings/{finding_id}", json={"status": "NONSENSE"})
    assert bad.status_code == 422