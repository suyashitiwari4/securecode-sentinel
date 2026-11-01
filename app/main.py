import uuid
from pathlib import Path
from typing import Literal

from fastapi import Depends, FastAPI, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db import get_db
from app.model import Finding, Scan
from app.services.runner import run_scanners
from app.services.scanner import parse_gitleaks, parse_semgrep

ROOT = Path(__file__).resolve().parent.parent
REPORTS_DIR = ROOT / "reports"
ALLOWED_TARGETS = [ROOT / "sample_vuln"]  # never scan arbitrary client paths

app = FastAPI(title="SecureCode Sentinel")


class ScanRequest(BaseModel):
    target: str = "sample_vuln"


class FindingUpdate(BaseModel):
    status: Literal["OPEN", "FIXED", "FALSE_POSITIVE", "ACCEPTED_RISK"]


def resolve_target(raw):
    target = (ROOT / raw).resolve()
    if not any(target.is_relative_to(a.resolve()) for a in ALLOWED_TARGETS):
        raise HTTPException(status_code=400, detail="Target path is not allowed")
    if not target.is_dir():
        raise HTTPException(status_code=404, detail="Target directory not found")
    return target


def finding_dict(f):
    return {
        "id": f.id, "scan_id": f.scan_id, "scanner": f.scanner, "rule_id": f.rule_id,
        "severity": f.severity, "file": f.file, "line": f.line, "title": f.title,
        "message": f.message, "evidence": f.evidence, "status": f.status,
    }


def scan_dict(s, with_findings=False):
    data = {
        "id": s.id, "target": s.target, "status": s.status,
        "created_at": s.created_at.isoformat(), "errors": s.errors,
        "finding_count": len(s.findings),
    }
    if with_findings:
        data["findings"] = [finding_dict(f) for f in s.findings]
    return data


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/api/scans", status_code=201)
def create_scan(body: ScanRequest, db: Session = Depends(get_db)):
    target = resolve_target(body.target)
    scan_id = str(uuid.uuid4())

    results = run_scanners(target_dir=target, output_dir=REPORTS_DIR / scan_id)

    parsed, errors = [], {}
    if results["semgrep"]["success"]:
        parsed += parse_semgrep(results["semgrep"]["report_path"])
    else:
        errors["semgrep"] = results["semgrep"].get("error")
    if results["gitleaks"]["success"]:
        parsed += parse_gitleaks(results["gitleaks"]["report_path"], source_dir=target)
    else:
        errors["gitleaks"] = results["gitleaks"].get("error")

    status = "completed" if not errors else ("failed" if len(errors) == 2 else "partial")
    scan = Scan(id=scan_id, target=body.target, status=status, errors=errors)
    scan.findings = [
        Finding(**{k: f[k] for k in (
            "scanner", "rule_id", "severity", "file", "line",
            "title", "message", "evidence", "status")})
        for f in parsed
    ]
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return scan_dict(scan, with_findings=True)


@app.get("/api/scans")
def list_scans(db: Session = Depends(get_db)):
    scans = db.scalars(select(Scan).order_by(Scan.created_at.desc())).all()
    return [scan_dict(s) for s in scans]


@app.get("/api/scans/{scan_id}")
def get_scan(scan_id: str, db: Session = Depends(get_db)):
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan_dict(scan, with_findings=True)


@app.get("/api/findings/{finding_id}")
def get_finding(finding_id: int, db: Session = Depends(get_db)):
    finding = db.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    return finding_dict(finding)


@app.patch("/api/findings/{finding_id}")
def update_finding(finding_id: int, body: FindingUpdate, db: Session = Depends(get_db)):
    finding = db.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    finding.status = body.status
    db.commit()
    return finding_dict(finding)