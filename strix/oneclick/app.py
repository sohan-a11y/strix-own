from __future__ import annotations

import asyncio
import importlib.util
import secrets
import shutil
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles

from . import config
from .models import ScanRequest
from .runner import JOBS, ScanJob, persist_public_jobs, start_job, stop_job, touch
from .security import TargetValidationError, validate_target_url

app = FastAPI(title="Strix One-Click", docs_url=None, redoc_url=None)
STATIC_DIR = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


def _require_local_request(request: Request) -> None:
    client_host = request.client.host if request.client else ""
    try:
        import ipaddress
        if client_host and not ipaddress.ip_address(client_host.split("%", 1)[0]).is_loopback:
            raise HTTPException(403, "This controller accepts requests only from loopback clients.")
    except ValueError:
        if client_host not in {"testclient", "localhost"}:
            raise HTTPException(403, "This controller accepts requests only from loopback clients.")
    origin = request.headers.get("origin")
    if origin:
        host = (urlsplit(origin).hostname or "").lower()
        if host not in {"127.0.0.1", "localhost", "::1"}:
            raise HTTPException(403, "Cross-origin requests are not accepted by this local controller.")


@app.get("/")
async def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/api/health")
async def health() -> dict[str, Any]:
    return {
        "ok": True,
        "strix_command": config.STRIX_COMMAND,
        "strix_available": bool(shutil.which(config.STRIX_COMMAND)),
        "strix_path": shutil.which(config.STRIX_COMMAND),
        "default_model": config.DEFAULT_MODEL,
        "playwright_optional": importlib.util.find_spec("playwright") is not None,
        "work_dir": str(config.WORK_DIR),
        "private_targets_enabled_by_environment": config.ALLOW_PRIVATE_TARGETS,
    }


@app.post("/api/scans", status_code=202)
async def create_scan(payload: ScanRequest, request: Request) -> dict[str, Any]:
    _require_local_request(request)
    if not payload.authorized:
        raise HTTPException(400, "Confirm that you own this target or have explicit written authorization to test it.")
    allow_private = payload.allow_private_target or config.ALLOW_PRIVATE_TARGETS
    try:
        target = validate_target_url(payload.target_url, allow_private=allow_private)
    except TargetValidationError as exc:
        raise HTTPException(400, str(exc)) from exc
    if payload.create_test_account:
        if not payload.account_recipe:
            raise HTTPException(400, "Add a signup-form recipe or disable automatic account creation.")
        if not payload.controlled_email_domain_confirmed or not payload.controlled_email_domain:
            raise HTTPException(400, "Confirm that the test-email domain and receiving inbox are under your control.")
    if bool(payload.existing_test_email) != bool(payload.existing_test_password):
        raise HTTPException(400, "Provide both existing test email and password, or leave both empty.")
    job_id = secrets.token_hex(6)
    job = ScanJob(
        id=job_id,
        target_url=target,
        model=payload.model,
        api_key=payload.api_key.get_secret_value(),
        api_base=payload.api_base,
        scan_mode=payload.scan_mode,
        max_budget_usd=payload.max_budget_usd,
        max_runtime_minutes=min(payload.max_runtime_minutes, max(5, config.MAX_RUNTIME_SECONDS // 60)),
        allow_private_target=allow_private,
        create_test_account=payload.create_test_account,
        controlled_email_domain=payload.controlled_email_domain,
        account_recipe=payload.account_recipe,
        existing_test_email=payload.existing_test_email,
        existing_test_password=payload.existing_test_password.get_secret_value() if payload.existing_test_password else None,
    )
    JOBS[job_id] = job
    touch(job, "queued", "Assessment queued")
    job.task = asyncio.create_task(start_job(job))
    persist_public_jobs()
    return job.public()


@app.get("/api/scans")
async def list_scans() -> list[dict[str, Any]]:
    return [job.public() for job in sorted(JOBS.values(), key=lambda value: value.created_at, reverse=True)]


@app.get("/api/scans/{job_id}")
async def get_scan(job_id: str) -> dict[str, Any]:
    job = JOBS.get(job_id)
    if not job:
        raise HTTPException(404, "Scan not found in this controller session.")
    return job.public()


@app.get("/api/scans/{job_id}/log", response_class=PlainTextResponse)
async def scan_log(job_id: str) -> str:
    job = JOBS.get(job_id)
    if not job:
        raise HTTPException(404, "Scan not found.")
    if not job.log_path or not job.log_path.is_file():
        return "\n".join(job.output_tail)
    return job.log_path.read_text(encoding="utf-8", errors="replace")[-50000:]


@app.get("/api/scans/{job_id}/report", response_class=PlainTextResponse)
async def scan_report(job_id: str) -> str:
    job = JOBS.get(job_id)
    if not job or not job.run_name or Path(job.run_name).name != job.run_name:
        raise HTTPException(404, "The final Strix report is not available yet.")
    report = config.WORK_DIR / "strix_runs" / job.run_name / "penetration_test_report.md"
    if not report.is_file():
        raise HTTPException(404, "The Markdown report has not been generated yet.")
    return report.read_text(encoding="utf-8", errors="replace")


@app.get("/api/scans/{job_id}/credentials")
async def scan_credentials(job_id: str, request: Request) -> dict[str, str | None]:
    _require_local_request(request)
    job = JOBS.get(job_id)
    if not job or not job.account:
        raise HTTPException(404, "No generated test account is available.")
    return {"email": job.account.email, "password": job.account.password}


@app.post("/api/scans/{job_id}/continue", status_code=202)
async def continue_scan(job_id: str, request: Request) -> dict[str, Any]:
    _require_local_request(request)
    job = JOBS.get(job_id)
    if not job or job.status != "needs_user_action":
        raise HTTPException(409, "This scan is not waiting for manual signup verification.")
    job.operator_continue.set()
    return job.public()


@app.post("/api/scans/{job_id}/stop")
async def stop_scan(job_id: str, request: Request) -> dict[str, Any]:
    _require_local_request(request)
    job = JOBS.get(job_id)
    if not job:
        raise HTTPException(404, "Scan not found.")
    await stop_job(job)
    return job.public()
