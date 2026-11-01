import logging
import uuid
from pathlib import Path
from typing import Literal

from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.db import SessionLocal, get_db
from app.models import AuditLog, Finding, Scan, utcnow
from app.services.runner import run_scanners
from app.services.scanner import make_fingerprint, parse_gitleaks, parse_semgrep

logger = logging.getLogger("sentinel")

ROOT = Path(__file__).resolve().parent.parent
REPORTS_DIR = ROOT / "reports"
ALLOWED_TARGETS = [ROOT / "sample_vuln"]  # never scan arbitrary client paths

Severity = Literal["HIGH", "MEDIUM", "LOW", "UNKNOWN"]
FindingStatus = Literal["OPEN", "FIXED", "FALSE_POSITIVE", "ACCEPTED_RISK"]
FINDING_FIELDS = ("scanner", "rule_id", "severity", "file", "line",
                  "title", "message", "evidence", "status", "fingerprint")

app = FastAPI(title="SecureCode Sentinel")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],  # Vite dev server
    allow_methods=["GET", "POST", "PATCH"],
    allow_headers=["*"],
)


class ScanRequest(BaseModel):
    target: str = "sample_vuln"


class FindingUpdate(BaseModel):
    status: FindingStatus


# ---------- helpers ----------

def resolve_target(raw):
    target = (ROOT / raw).resolve()
    if not any(target.is_relative_to(a.resolve()) for a in ALLOWED_TARGETS):
        raise HTTPException(status_code=400, detail="Target path is not allowed")
    if not target.is_dir():
        raise HTTPException(status_code=404, detail="Target directory not found")
    return target


def audit(db, action, entity_type, entity_id, details=None):
    db.add(AuditLog(action=action, entity_type=entity_type,
                    entity_id=str(entity_id), details=details or {}))


def finding_dict(f):
    return {
        "id": f.id, "scan_id": f.scan_id, "scanner": f.scanner, "rule_id": f.rule_id,
        "severity": f.severity, "file": f.file, "line": f.line, "title": f.title,
        "message": f.message, "evidence": f.evidence, "status": f.status,
    }


def scan_dict(db, s):
    rows = db.execute(
        select(Finding.severity, func.count())
        .where(Finding.scan_id == s.id)
        .group_by(Finding.severity)
    ).all()
    counts = {sev: n for sev, n in rows}
    return {
        "id": s.id, "target": s.target, "status": s.status, "errors": s.errors,
        "created_at": s.created_at.isoformat(),
        "finished_at": s.finished_at.isoformat() if s.finished_at else None,
        "finding_count": sum(counts.values()),
        "severity_counts": counts,
    }


def get_scan_or_404(db, scan_id):
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


# ---------- background job ----------

def execute_scan(scan_id: str, target: str):
    """Runs after the HTTP response is sent. Uses its own DB session."""
    db = SessionLocal()
    try:
        target_path = Path(target)
        results = run_scanners(target_dir=target_path, output_dir=REPORTS_DIR / scan_id)

        parsed, errors = [], {}
        if results["semgrep"]["success"]:
            parsed += parse_semgrep(results["semgrep"]["report_path"])
        else:
            errors["semgrep"] = results["semgrep"].get("error")
        if results["gitleaks"]["success"]:
            parsed += parse_gitleaks(results["gitleaks"]["report_path"], source_dir=target_path)
        else:
            errors["gitleaks"] = results["gitleaks"].get("error")

        for f in parsed:
            f["fingerprint"] = make_fingerprint(f, base_dir=target_path)

        scan = db.get(Scan, scan_id)
        scan.findings = [Finding(**{k: f[k] for k in FINDING_FIELDS}) for f in parsed]
        scan.errors = errors
        scan.status = "completed" if not errors else ("failed" if len(errors) == 2 else "partial")
        scan.finished_at = utcnow()
        audit(db, "scan.finished", "scan", scan_id,
              {"status": scan.status, "finding_count": len(parsed)})
        db.commit()
    except Exception:
        db.rollback()
        logger.exception("Scan %s crashed", scan_id)
        scan = db.get(Scan, scan_id)
        scan.status = "failed"
        scan.errors = {"internal": "Scan failed unexpectedly"}  # details stay in server logs
        scan.finished_at = utcnow()
        audit(db, "scan.crashed", "scan", scan_id)
        db.commit()
    finally:
        db.close()


# ---------- endpoints ----------

@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/api/scans", status_code=202)
def create_scan(body: ScanRequest, background: BackgroundTasks, db: Session = Depends(get_db)):
    target = resolve_target(body.target)
    scan = Scan(id=str(uuid.uuid4()), target=body.target, status="running", errors={})
    db.add(scan)
    audit(db, "scan.started", "scan", scan.id, {"target": body.target})
    db.commit()
    background.add_task(execute_scan, scan.id, str(target))
    return scan_dict(db, scan)


@app.get("/api/scans")
def list_scans(limit: int = Query(50, ge=1, le=200), db: Session = Depends(get_db)):
    scans = db.scalars(select(Scan).order_by(Scan.created_at.desc()).limit(limit)).all()
    return [scan_dict(db, s) for s in scans]


@app.get("/api/scans/{scan_id}")
def get_scan(scan_id: str, db: Session = Depends(get_db)):
    return scan_dict(db, get_scan_or_404(db, scan_id))


@app.get("/api/scans/{scan_id}/compare/{baseline_id}")
def compare_scans(scan_id: str, baseline_id: str, db: Session = Depends(get_db)):
    current = get_scan_or_404(db, scan_id)
    baseline = get_scan_or_404(db, baseline_id)
    if "running" in (current.status, baseline.status):
        raise HTTPException(status_code=409, detail="A scan is still running")

    cur = {f.fingerprint: f for f in current.findings if f.fingerprint}
    base = {f.fingerprint: f for f in baseline.findings if f.fingerprint}

    def pick(source, keys):
        return sorted((finding_dict(source[k]) for k in keys), key=lambda d: d["id"])

    new = pick(cur, cur.keys() - base.keys())
    resolved = pick(base, base.keys() - cur.keys())
    still_open = pick(cur, cur.keys() & base.keys())
    return {
        "scan_id": scan_id,
        "baseline_id": baseline_id,
        "summary": {"new": len(new), "resolved": len(resolved), "still_open": len(still_open)},
        "new": new,
        "resolved": resolved,
        "still_open": still_open,
    }


@app.get("/api/findings")
def list_findings(
    scan_id: str | None = None,
    severity: Severity | None = None,
    status: FindingStatus | None = None,
    file: str | None = None,
    rule_id: str | None = None,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
):
    query = select(Finding)
    if scan_id:
        query = query.where(Finding.scan_id == scan_id)
    if severity:
        query = query.where(Finding.severity == severity)
    if status:
        query = query.where(Finding.status == status)
    if file:
        query = query.where(Finding.file.ilike(f"%{file}%"))
    if rule_id:
        query = query.where(Finding.rule_id.ilike(f"%{rule_id}%"))

    total = db.scalar(select(func.count()).select_from(query.subquery()))
    rows = db.scalars(query.order_by(Finding.id).limit(limit).offset(offset)).all()
    return {"total": total, "items": [finding_dict(f) for f in rows]}


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
    audit(db, "finding.status_changed", "finding", finding_id,
          {"from": finding.status, "to": body.status})
    finding.status = body.status
    db.commit()
    return finding_dict(finding)


@app.get("/api/audit-logs")
def list_audit_logs(limit: int = Query(50, ge=1, le=200), db: Session = Depends(get_db)):
    logs = db.scalars(select(AuditLog).order_by(AuditLog.id.desc()).limit(limit)).all()
    return [{"id": a.id, "action": a.action, "entity_type": a.entity_type,
             "entity_id": a.entity_id, "details": a.details,
             "created_at": a.created_at.isoformat()} for a in logs]