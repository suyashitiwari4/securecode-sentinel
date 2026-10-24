import uuid
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from app.services.runner import run_scanners
from app.services.scanner import parse_gitleaks, parse_semgrep

ROOT = Path(__file__).resolve().parent.parent
REPORTS_DIR = ROOT / "reports"

# Only these folders may be scanned. Never accept arbitrary paths from a client.
ALLOWED_TARGETS = [ROOT / "sample_vuln"]

app = FastAPI(title="SecureCode Sentinel")

SCANS = {}  # in-memory for now; replaced by PostgreSQL next


class ScanRequest(BaseModel):
    target: str = "sample_vuln"


def resolve_target(raw):
    target = (ROOT / raw).resolve()
    if not any(target.is_relative_to(a.resolve()) for a in ALLOWED_TARGETS):
        raise HTTPException(status_code=400, detail="Target path is not allowed")
    if not target.is_dir():
        raise HTTPException(status_code=404, detail="Target directory not found")
    return target


def summarize(scan):
    return {k: scan[k] for k in ("id", "target", "status", "created_at", "finding_count")}


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/api/scans", status_code=201)
def create_scan(body: ScanRequest):
    target = resolve_target(body.target)
    scan_id = str(uuid.uuid4())

    results = run_scanners(target_dir=target, output_dir=REPORTS_DIR / scan_id)

    findings, errors = [], {}
    if results["semgrep"]["success"]:
        findings += parse_semgrep(results["semgrep"]["report_path"])
    else:
        errors["semgrep"] = results["semgrep"].get("error")
    if results["gitleaks"]["success"]:
        findings += parse_gitleaks(results["gitleaks"]["report_path"], source_dir=target)
    else:
        errors["gitleaks"] = results["gitleaks"].get("error")

    for i, f in enumerate(findings, start=1):
        f["id"] = i

    status = "completed" if not errors else ("failed" if len(errors) == 2 else "partial")
    scan = {
        "id": scan_id,
        "target": body.target,
        "status": status,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "finding_count": len(findings),
        "errors": errors,
        "findings": findings,
    }
    SCANS[scan_id] = scan
    return scan


@app.get("/api/scans")
def list_scans():
    return [summarize(s) for s in SCANS.values()]


@app.get("/api/scans/{scan_id}")
def get_scan(scan_id: str):
    scan = SCANS.get(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan