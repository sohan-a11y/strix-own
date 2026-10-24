from __future__ import annotations

import asyncio
import json
import os
import re
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import config
from .accounts import TestAccount, provision_test_account
from .models import SignupRecipe
from .security import validate_target_url

ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
RUN_RE = re.compile(r"strix_runs/([A-Za-z0-9_.-]+)")
JOBS: dict[str, "ScanJob"] = {}


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def redact(text: str, secrets_to_hide: list[str]) -> str:
    result = text
    for item in sorted((s for s in secrets_to_hide if s), key=len, reverse=True):
        result = result.replace(item, "[REDACTED]")
    return result


def safe_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    try:
        path.chmod(0o600)
    except OSError:
        pass


@dataclass
class ScanJob:
    id: str
    target_url: str
    model: str
    api_key: str
    api_base: str | None
    scan_mode: str
    max_budget_usd: float
    max_runtime_minutes: int
    allow_private_target: bool
    create_test_account: bool
    controlled_email_domain: str | None
    account_recipe: SignupRecipe | None
    existing_test_email: str | None = None
    existing_test_password: str | None = None
    status: str = "queued"
    message: str = "Queued"
    created_at: str = field(default_factory=now)
    updated_at: str = field(default_factory=now)
    started_at: str | None = None
    finished_at: str | None = None
    return_code: int | None = None
    run_name: str | None = None
    output_tail: deque[str] = field(default_factory=lambda: deque(maxlen=200))
    log_path: Path | None = None
    instruction_path: Path | None = None
    account: TestAccount | None = None
    process: asyncio.subprocess.Process | None = None
    task: asyncio.Task[Any] | None = None
    operator_continue: asyncio.Event = field(default_factory=asyncio.Event)
    secret_values: list[str] = field(default_factory=list)

    def public(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "target_url": self.target_url,
            "model": self.model,
            "scan_mode": self.scan_mode,
            "max_budget_usd": self.max_budget_usd,
            "max_runtime_minutes": self.max_runtime_minutes,
            "status": self.status,
            "message": self.message,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "return_code": self.return_code,
            "run_name": self.run_name,
            "output_tail": list(self.output_tail),
            "has_test_account": self.account is not None,
            "log_available": bool(self.log_path and self.log_path.is_file()),
        }


def touch(job: ScanJob, status: str, message: str) -> None:
    job.status = status
    job.message = message
    job.updated_at = now()


def persist_public_jobs() -> None:
    config.DATA_DIR.mkdir(parents=True, exist_ok=True)
    records = [job.public() for job in sorted(JOBS.values(), key=lambda item: item.created_at, reverse=True)]
    safe_write(config.DATA_DIR / "jobs.json", json.dumps(records, indent=2))


async def clear_api_secret(job: ScanJob) -> None:
    job.api_key = ""


def _scan_instruction(job: ScanJob) -> str:
    lines = [
        "Perform a thorough, evidence-driven web application security assessment.",
        "Stay within the supplied target origin and the owner's authorized scope.",
        "Use safe, non-destructive validation. Do not perform denial-of-service, persistence,",
        "mass account creation, destructive actions, or tests against unrelated third-party systems.",
        "Validate findings with reproducible evidence and counterevidence; distinguish confirmed",
        "issues from hypotheses and describe coverage limitations.",
    ]
    if job.account:
        lines.extend([
            "",
            "The following is a single authorized test account created for this assessment:",
            "Test email: " + job.account.email,
            "Test password: " + job.account.password,
            "Use it only for authenticated checks on the supplied target.",
            "Do not create additional accounts. Do not attempt to evade CAPTCHA, MFA, or email verification.",
        ])
    elif job.existing_test_email and job.existing_test_password:
        lines.extend([
            "",
            "Use this operator-supplied test account only on the supplied target:",
            "Test email: " + job.existing_test_email,
            "Test password: " + job.existing_test_password,
        ])
    return "\n".join(lines)


def _scrub_artifacts(job: ScanJob) -> None:
    if not job.run_name or Path(job.run_name).name != job.run_name:
        return
    run_dir = config.WORK_DIR / "strix_runs" / job.run_name
    if not run_dir.exists():
        return
    secrets_to_hide = [*job.secret_values]
    if job.account:
        secrets_to_hide += [job.account.email, job.account.password]
    if job.existing_test_email:
        secrets_to_hide.append(job.existing_test_email)
    if job.existing_test_password:
        secrets_to_hide.append(job.existing_test_password)
    for path in run_dir.rglob("*"):
        if not path.is_file() or path.stat().st_size > 5 * 1024 * 1024:
            continue
        try:
            original = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        sanitized = redact(original, secrets_to_hide)
        if sanitized != original:
            safe_write(path, sanitized)


async def _pause_for_operator(job: ScanJob, message: str) -> None:
    touch(job, "needs_user_action", message)
    persist_public_jobs()
    await job.operator_continue.wait()
    job.operator_continue.clear()


async def start_job(job: ScanJob) -> None:
    config.DATA_DIR.mkdir(parents=True, exist_ok=True)
    job_dir = config.DATA_DIR / job.id
    job_dir.mkdir(parents=True, exist_ok=True)
    job.log_path = job_dir / "controller.log"
    job.instruction_path = job_dir / "instructions.txt"
    if job.api_key:
        job.secret_values.append(job.api_key)
    if job.existing_test_password:
        job.secret_values.append(job.existing_test_password)
    touch(job, "preflight", "Checking target scope and configuration")
    persist_public_jobs()
    try:
        job.target_url = validate_target_url(job.target_url, allow_private=job.allow_private_target)
        if job.create_test_account:
            if job.account_recipe is None or not job.controlled_email_domain:
                raise ValueError("A signup recipe and a test-email domain you control are required.")
            touch(job, "provisioning", "Opening the target's signup form in a visible browser")
            job.account = await provision_test_account(
                job.target_url, job.account_recipe, job.controlled_email_domain,
                lambda text: _pause_for_operator(job, text),
            )
            job.secret_values.extend([job.account.email, job.account.password])
        safe_write(job.instruction_path, _scan_instruction(job))
        env = os.environ.copy()
        env["STRIX_LLM"] = job.model
        env["LLM_API_KEY"] = job.api_key
        if job.api_base:
            env["LLM_API_BASE"] = job.api_base
        started_dir = config.WORK_DIR / "strix_runs"
        before = {p.name for p in started_dir.iterdir() if p.is_dir()} if started_dir.is_dir() else set()
        command = [
            config.STRIX_COMMAND, "-n", "--target", job.target_url,
            "--instruction-file", str(job.instruction_path),
            "--scan-mode", job.scan_mode, "--max-budget", str(job.max_budget_usd),
        ]
        with job.log_path.open("a", encoding="utf-8") as log:
            log.write("Starting Strix One-Click assessment.\n")
            log.write(f"Target: {job.target_url}\nMode: {job.scan_mode}\n")
            log.flush()
            job.started_at = now()
            touch(job, "running", "Strix is running; live output is shown below")
            try:
                job.process = await asyncio.create_subprocess_exec(
                    *command,
                    cwd=str(config.WORK_DIR),
                    env=env,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.STDOUT,
                )
            except FileNotFoundError as exc:
                raise RuntimeError(
                    f"Could not find Strix executable {config.STRIX_COMMAND!r}. Install Strix or set STRIX_EXECUTABLE."
                ) from exc
            started = time.monotonic()
            instruction_removed = False
            assert job.process.stdout is not None
            while True:
                if time.monotonic() - started > job.max_runtime_minutes * 60:
                    touch(job, "stopping", "Runtime limit reached; terminating Strix")
                    job.process.terminate()
                    try:
                        await asyncio.wait_for(job.process.wait(), timeout=10)
                    except asyncio.TimeoutError:
                        job.process.kill()
                        await job.process.wait()
                    break
                try:
                    raw = await asyncio.wait_for(job.process.stdout.readline(), timeout=1.0)
                except asyncio.TimeoutError:
                    if job.process.returncode is not None:
                        break
                    continue
                if not raw:
                    break
                line = ANSI_RE.sub("", raw.decode("utf-8", errors="replace")).rstrip()
                safe_line = redact(line, job.secret_values)
                log.write(safe_line + "\n")
                log.flush()
                if safe_line:
                    job.output_tail.append(safe_line)
                match = RUN_RE.search(line)
                if match:
                    job.run_name = match.group(1)
                if not instruction_removed and (
                    "penetration test initiated" in line.lower() or time.monotonic() - started > 8
                ):
                    job.instruction_path.unlink(missing_ok=True)
                    instruction_removed = True
            job.return_code = await job.process.wait()
        if job.run_name is None and started_dir.is_dir():
            candidates = [p for p in started_dir.iterdir() if p.is_dir() and p.name not in before]
            if candidates:
                job.run_name = max(candidates, key=lambda p: p.stat().st_mtime).name
        if job.status in {"stopping", "stopped"}:
            touch(job, "stopped", "Scan stopped at the runtime limit or by the operator")
        elif job.return_code == 0:
            touch(job, "completed", "Strix completed. Review analyzed coverage and the final report.")
        elif job.return_code == 2:
            touch(job, "completed_with_findings", "Strix reported one or more vulnerabilities; review evidence and severity.")
        else:
            touch(job, "failed", f"Strix exited with code {job.return_code}. Review the controller log and run status.")
    except asyncio.CancelledError:
        if job.process and job.process.returncode is None:
            job.process.terminate()
            try:
                await asyncio.wait_for(job.process.wait(), timeout=5)
            except asyncio.TimeoutError:
                job.process.kill()
        touch(job, "stopped", "Scan was stopped before completion")
        raise
    except Exception as exc:
        touch(job, "failed", redact(str(exc), job.secret_values))
        job.output_tail.append("ERROR: " + redact(str(exc), job.secret_values))
        if job.log_path:
            with job.log_path.open("a", encoding="utf-8") as log:
                log.write("ERROR: " + redact(str(exc), job.secret_values) + "\n")
    finally:
        if job.instruction_path:
            job.instruction_path.unlink(missing_ok=True)
        _scrub_artifacts(job)
        job.finished_at = now()
        await clear_api_secret(job)
        job.secret_values = [s for s in job.secret_values if s != ""]
        persist_public_jobs()


async def stop_job(job: ScanJob) -> None:
    if job.process and job.process.returncode is None:
        touch(job, "stopping", "Stop requested by operator")
        job.process.terminate()
        try:
            await asyncio.wait_for(job.process.wait(), timeout=8)
        except asyncio.TimeoutError:
            job.process.kill()
    elif job.task and not job.task.done():
        job.operator_continue.set()
        job.task.cancel()
        try:
            await job.task
        except asyncio.CancelledError:
            pass
    touch(job, "stopped", "Stopped by operator")
    await clear_api_secret(job)
    persist_public_jobs()
