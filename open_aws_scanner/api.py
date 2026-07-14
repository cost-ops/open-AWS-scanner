"""
Open AWS Scanner API
Simple, no-auth AWS cost waste scanner. Configure via config.env and go.
"""
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from apscheduler.schedulers.background import BackgroundScheduler
from .scanner import run_scan
from .database import SessionLocal, ScanResult, ScanRun, init_db
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from dotenv import load_dotenv
from datetime import datetime, timezone
import os

# Load config.env from current working directory if it exists
_config_path = os.path.join(os.getcwd(), "config.env")
if os.path.exists(_config_path):
    load_dotenv(_config_path)

# --- Config ---
SCAN_INTERVAL_HOURS = int(os.getenv("SCAN_INTERVAL_HOURS", "6"))
HOST = os.getenv("HOST", "0.0.0.0")
PORT = int(os.getenv("PORT", "8000"))

limiter = Limiter(key_func=get_remote_address)
app = FastAPI(
    title="Open AWS Scanner",
    version="1.0.0",
    description="Simple AWS waste detection — no admin, no auth, just results.",
)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

scheduler = BackgroundScheduler()


# --- Startup ---

@app.on_event("startup")
def startup_event():
    init_db()
    # Schedule recurring scans
    scheduler.add_job(
        func=run_scan,
        trigger="interval",
        hours=SCAN_INTERVAL_HOURS,
        id="scheduled_scan",
        replace_existing=True,
    )
    scheduler.start()
    print(f"[OPEN-SCANNER] Running. Scans every {SCAN_INTERVAL_HOURS}h.")


# --- Health ---

@app.get("/health")
def health_check():
    import inspect
    from . import scanner as scanner_module
    from . import __version__
    scanner_funcs = [name for name, obj in inspect.getmembers(scanner_module, inspect.isfunction)
                     if name.startswith("get_") and name not in ("get_aws_session", "get_mock_findings")]
    return {
        "status": "online",
        "version": __version__,
        "scan_interval_hours": SCAN_INTERVAL_HOURS,
        "scanner_count": len(scanner_funcs),
    }


@app.get("/status")
def scanner_status():
    """Detailed status for reporting to admin dashboards."""
    db = SessionLocal()
    total_findings = db.query(ScanResult).count()
    open_findings = db.query(ScanResult).filter(ScanResult.status.in_(["open", None])).count()
    total_runs = db.query(ScanRun).count()
    last_run = db.query(ScanRun).order_by(ScanRun.started_at.desc()).first()
    db.close()

    jobs = scheduler.get_jobs()
    active_scanners = len([j for j in jobs if j.id.startswith("scheduled")])

    import inspect
    from . import scanner as scanner_module
    from . import __version__
    scanner_funcs = [name for name, obj in inspect.getmembers(scanner_module, inspect.isfunction)
                     if name.startswith("get_") and name not in ("get_aws_session", "get_mock_findings")]

    return {
        "status": "online",
        "version": __version__,
        "scanner_count": len(scanner_funcs),
        "active_scanners": active_scanners,
        "scheduled_jobs": len(jobs),
        "scan_interval_hours": SCAN_INTERVAL_HOURS,
        "total_findings": total_findings,
        "open_findings": open_findings,
        "total_scan_runs": total_runs,
        "last_scan": last_run.completed_at.isoformat() if last_run and last_run.completed_at else None,
        "last_scan_status": last_run.status if last_run else None,
    }


# --- Dashboard ---

@app.get("/", include_in_schema=False)
def dashboard():
    db = SessionLocal()
    results = db.query(ScanResult).all()
    runs = db.query(ScanRun).order_by(ScanRun.started_at.desc()).limit(1).all()
    db.close()

    total = len(results)
    total_savings = sum(r.estimated_monthly_savings or 0 for r in results)
    open_count = sum(1 for r in results if (r.status or "open") == "open")
    fixed_count = sum(1 for r in results if r.status == "fixed")
    last_scan = runs[0].completed_at.isoformat() if runs and runs[0].completed_at else "Never"

    return {
        "app": "Open AWS Scanner",
        "status": "online",
        "total_findings": total,
        "open": open_count,
        "fixed": fixed_count,
        "potential_savings_per_month": f"${total_savings:.2f}",
        "last_scan": last_scan,
        "endpoints": {
            "POST /scan": "Trigger a scan",
            "GET /findings": "List findings (?status=open&resource_type=EC2_Instance)",
            "PUT /findings/{id}/status?status=fixed": "Update finding status",
            "GET /summary": "Savings breakdown by status",
            "GET /scans": "Scan run history",
            "GET /docs": "Swagger UI",
        },
    }


# --- Trigger Scan ---

@app.post("/scan")
def trigger_scan():
    """Trigger a scan now."""
    from threading import Thread
    Thread(target=run_scan).start()
    return {"status": "scan_triggered"}


# --- Get Findings ---

@app.get("/findings")
def get_findings(status: str = None, resource_type: str = None):
    """Get all findings, optionally filtered by status or resource_type."""
    db = SessionLocal()
    query = db.query(ScanResult).order_by(ScanResult.scanned_at.desc())
    if status:
        query = query.filter(ScanResult.status == status)
    if resource_type:
        query = query.filter(ScanResult.resource_type == resource_type)
    results = query.all()
    db.close()

    return [
        {
            "id": r.id,
            "resource_id": r.resource_id,
            "resource_name": r.resource_name,
            "resource_type": r.resource_type,
            "reason": r.reason,
            "estimated_monthly_savings": r.estimated_monthly_savings,
            "scanned_at": r.scanned_at.isoformat() if r.scanned_at else None,
            "tags": r.tags,
            "cpu_avg_percent": r.cpu_avg_percent,
            "memory_avg_percent": r.memory_avg_percent,
            "network_in_bytes": r.network_in_bytes,
            "network_out_bytes": r.network_out_bytes,
            "status": r.status or "open",
            "status_changed_at": r.status_changed_at.isoformat() if r.status_changed_at else None,
            "first_seen_at": r.first_seen_at.isoformat() if r.first_seen_at else None,
            "region": r.region,
        }
        for r in results
    ]


# --- Update Finding Status ---

@app.put("/findings/{finding_id}/status")
def update_finding_status(finding_id: int, status: str):
    """Update finding status: open, fixed, dismissed, in_progress"""
    if status not in ("open", "fixed", "dismissed", "in_progress"):
        raise HTTPException(status_code=400, detail="Status must be: open, fixed, dismissed, in_progress")
    db = SessionLocal()
    finding = db.query(ScanResult).filter(ScanResult.id == finding_id).first()
    if not finding:
        db.close()
        raise HTTPException(status_code=404, detail="Finding not found")
    finding.status = status
    finding.status_changed_at = datetime.now(timezone.utc)
    db.commit()
    db.close()
    return {"id": finding_id, "status": status}


# --- Summary ---

@app.get("/summary")
def findings_summary():
    """Summary of findings by status with savings totals."""
    db = SessionLocal()
    results = db.query(ScanResult).all()
    db.close()

    open_findings = [r for r in results if (r.status or "open") == "open"]
    fixed_findings = [r for r in results if r.status == "fixed"]
    dismissed_findings = [r for r in results if r.status == "dismissed"]
    in_progress = [r for r in results if r.status == "in_progress"]

    return {
        "total_findings": len(results),
        "total_potential_savings": sum(r.estimated_monthly_savings or 0 for r in results),
        "open": {
            "count": len(open_findings),
            "savings": sum(r.estimated_monthly_savings or 0 for r in open_findings),
        },
        "fixed": {
            "count": len(fixed_findings),
            "savings_realized": sum(r.estimated_monthly_savings or 0 for r in fixed_findings),
        },
        "dismissed": {
            "count": len(dismissed_findings),
            "savings": sum(r.estimated_monthly_savings or 0 for r in dismissed_findings),
        },
        "in_progress": {
            "count": len(in_progress),
            "savings": sum(r.estimated_monthly_savings or 0 for r in in_progress),
        },
    }


# --- Scan History ---

@app.get("/scans")
def get_scan_history():
    """Get recent scan runs."""
    db = SessionLocal()
    runs = db.query(ScanRun).order_by(ScanRun.started_at.desc()).limit(50).all()
    db.close()
    return [
        {
            "id": r.id,
            "status": r.status,
            "findings_count": r.findings_count,
            "errors": r.errors,
            "started_at": r.started_at.isoformat() if r.started_at else None,
            "completed_at": r.completed_at.isoformat() if r.completed_at else None,
        }
        for r in runs
    ]


# --- Run ---

def serve():
    """Start the API server."""
    import uvicorn
    uvicorn.run("open_aws_scanner.api:app", host=HOST, port=PORT, reload=False)


if __name__ == "__main__":
    serve()
