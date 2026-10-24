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