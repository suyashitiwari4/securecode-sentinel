import json
import os
from pathlib import Path

from dotenv import load_dotenv

# Must run BEFORE app.db is imported: point everything at the test database.
load_dotenv()
os.environ["DATABASE_URL"] = os.environ["DATABASE_URL"].rsplit("/", 1)[0] + "/sentinel_test"

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

from app import models  # noqa: F401
from app.db import Base, engine
from app.main import app


@pytest.fixture(scope="session", autouse=True)
def _schema():
    assert engine.url.database.endswith("_test"), "Refusing to touch a non-test database"
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    yield


@pytest.fixture(autouse=True)
def _clean_tables():
    with engine.begin() as conn:
        conn.execute(text("TRUNCATE findings, scans, audit_logs RESTART IDENTITY CASCADE"))
    yield


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def fake_scanners(monkeypatch):
    """Replace the real Semgrep/Gitleaks run with canned reports (fast, deterministic)."""
    def install(semgrep=(), gitleaks=()):
        def fake_run(target_dir, output_dir):
            out = Path(output_dir)
            out.mkdir(parents=True, exist_ok=True)
            s, g = out / "semgrep_report.json", out / "gitleaks_report.json"
            s.write_text(json.dumps({"results": list(semgrep)}), encoding="utf-8")
            g.write_text(json.dumps(list(gitleaks)), encoding="utf-8")
            return {
                "semgrep": {"success": True, "exit_code": 0, "report_path": str(s)},
                "gitleaks": {"success": True, "exit_code": 1, "report_path": str(g)},
            }
        monkeypatch.setattr("app.main.run_scanners", fake_run)
    return install