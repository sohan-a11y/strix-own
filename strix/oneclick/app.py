from __future__ import annotations

import asyncio
import importlib.util
import ipaddress
import json
import secrets
import shutil
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit

from pydantic import ValidationError

from . import config
from .models import ScanRequest
from .runner import (
    JOBS,
    JOBS_LOCK,
    ScanJob,
    clear_api_secret,
    persist_public_jobs,
    start_job,
    stop_job,
    touch,
)
from .security import TargetValidationError, validate_target_url

STATIC_DIR = Path(__file__).parent / "static"
LOOP = asyncio.new_event_loop()
LOOP_READY = threading.Event()
_LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1", "testserver"}


async def _run_job(job: ScanJob) -> None:
    if job.stop_requested:
        touch(job, "stopped", "Stopped before the scan process was started")
        await clear_api_secret(job)
        persist_public_jobs()
        return
    job.task = asyncio.current_task()
    await start_job(job)


def _run_event_loop() -> None:
    asyncio.set_event_loop(LOOP)
    LOOP_READY.set()
    LOOP.run_forever()


def _require_local(handler: BaseHTTPRequestHandler) -> bool:
    host_header = handler.headers.get("Host", "")
    host = (urlsplit("//" + host_header).hostname or "").lower()
    if host not in _LOCAL_HOSTS:
        return False
    client = handler.client_address[0] if handler.client_address else ""
    try:
        if not ipaddress.ip_address(client.split("%", 1)[0]).is_loopback:
            return False
    except ValueError:
        if client not in {"testclient", "localhost"}:
            return False
    origin = handler.headers.get("Origin")
    if origin:
        parsed_origin = urlsplit(origin)
        origin_host = (parsed_origin.hostname or "").lower()
        if origin_host not in _LOCAL_HOSTS or parsed_origin.scheme.lower() != "http":
            return False
        try:
            origin_port = parsed_origin.port or 80
            request_port = urlsplit("//" + host_header).port or 80
        except ValueError:
            return False
        if origin_host != host or origin_port != request_port:
            return False
    return True


class OneClickHandler(BaseHTTPRequestHandler):
    server_version = "StrixOneClick/0.1"
    sys_version = ""

    def log_message(self, fmt: str, *args: Any) -> None:
        # Avoid logging target paths and request contents in the controller's terminal.
        return

    def _send(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; connect-src 'self'; style-src 'self'; "
            "script-src 'self'; img-src 'self' data:",
        )
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status: int, data: Any) -> None:
        self._send(
            status,
            json.dumps(data, ensure_ascii=False).encode("utf-8"),
            "application/json; charset=utf-8",
        )

    def _text(
        self,
        status: int,
        data: str,
        content_type: str = "text/plain; charset=utf-8",
    ) -> None:
        self._send(status, data.encode("utf-8", errors="replace"), content_type)

    def _read_json(self) -> dict[str, Any]:
        raw_length = self.headers.get("Content-Length", "0")
        try:
            length = int(raw_length)
        except ValueError as exc:
            raise ValueError("Invalid request body length.") from exc
        if length <= 0 or length > 1_000_000:
            raise ValueError("Request body must be between 1 byte and 1 MB.")
        try:
            body = json.loads(self.rfile.read(length))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ValueError("Request body must be valid JSON.") from exc
        if not isinstance(body, dict):
            raise ValueError("Request body must be a JSON object.")
        return body

    def _api_guard(self) -> bool:
        if _require_local(self):
            return True
        self._json(
            403,
            {"detail": "This API is local-only. Use the controller at 127.0.0.1 or localhost."},
        )
        return False

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlsplit(self.path)
        path = parsed.path
        if path == "/":
            self._serve_static("index.html", "text/html; charset=utf-8")
            return
        if path in {"/static/app.js", "/static/style.css"}:
            asset = path.rsplit("/", 1)[-1]
            content_type = (
                "application/javascript; charset=utf-8"
                if asset.endswith(".js")
                else "text/css; charset=utf-8"
            )
            self._serve_static(asset, content_type)
            return
        if path.startswith("/api/") and not self._api_guard():
            return
        if path == "/api/health":
            self._json(200, {
                "ok": True,
                "strix_command": config.STRIX_COMMAND,
                "strix_available": bool(shutil.which(config.STRIX_COMMAND)),
                "strix_path": shutil.which(config.STRIX_COMMAND),
                "default_model": config.DEFAULT_MODEL,
                "playwright_optional": importlib.util.find_spec("playwright") is not None,
                "work_dir": str(config.WORK_DIR),
                "private_targets_enabled_by_environment": config.ALLOW_PRIVATE_TARGETS,
            })
            return
        if path == "/api/scans":
            with JOBS_LOCK:
                scans = [
                    job.public()
                    for job in sorted(
                        JOBS.values(), key=lambda item: item.created_at, reverse=True
                    )
                ]
            self._json(200, scans)
            return

        route = path.strip("/").split("/")
        if len(route) >= 3 and route[0] == "api" and route[1] == "scans":
            job_id = unquote(route[2])
            with JOBS_LOCK:
                job = JOBS.get(job_id)
            if not job:
                self._json(404, {"detail": "Scan not found in this controller session."})
                return
            if len(route) == 3:
                self._json(200, job.public())
                return
            if len(route) == 4 and route[3] == "log":
                if job.log_path and job.log_path.is_file():
                    log = job.log_path.read_text(encoding="utf-8", errors="replace")[-50000:]
                else:
                    log = "\n".join(job.output_tail)
                self._text(200, log)
                return
            if len(route) == 4 and route[3] == "report":
                if not job.run_name or Path(job.run_name).name != job.run_name:
                    self._json(404, {"detail": "The final Strix report is not available yet."})
                    return
                report = (
                    config.WORK_DIR / "strix_runs" / job.run_name / "penetration_test_report.md"
                )
                if not report.is_file():
                    self._json(404, {"detail": "The Markdown report has not been generated yet."})
                    return
                self._text(
                    200,
                    report.read_text(encoding="utf-8", errors="replace"),
                    "text/markdown; charset=utf-8",
                )
                return
            if len(route) == 4 and route[3] == "credentials":
                if not job.account:
                    self._json(404, {"detail": "No generated test account is available."})
                    return
                self._json(200, {"email": job.account.email, "password": job.account.password})
                return
        self._json(404, {"detail": "Route not found."})

    def _serve_static(self, filename: str, content_type: str) -> None:
        file_path = STATIC_DIR / filename
        if not file_path.is_file():
            self._text(404, "Static asset not found.")
            return
        self._send(200, file_path.read_bytes(), content_type)

    def do_POST(self) -> None:  # noqa: N802
        if not self._api_guard():
            return
        path = urlsplit(self.path).path
        try:
            if path == "/api/scans":
                payload_dict = self._read_json()
                try:
                    payload = ScanRequest.model_validate(payload_dict)
                except ValidationError as exc:
                    errors = [
                        {
                            "loc": error.get("loc"),
                            "msg": error.get("msg"),
                            "type": error.get("type"),
                        }
                        for error in exc.errors(include_input=False)
                    ]
                    self._json(400, {"detail": errors})
                    return
                if not payload.authorized:
                    self._json(
                        400,
                        {
                            "detail": (
                                "Confirm that you own this target or have explicit written "
                                "authorization to test it."
                            )
                        },
                    )
                    return
                allow_private = payload.allow_private_target or config.ALLOW_PRIVATE_TARGETS
                try:
                    target = validate_target_url(payload.target_url, allow_private=allow_private)
                except TargetValidationError as exc:
                    self._json(400, {"detail": str(exc)})
                    return
                if payload.create_test_account:
                    if not payload.account_recipe:
                        self._json(
                            400,
                            {
                                "detail": (
                                    "Add a signup-form recipe or disable automatic "
                                    "account creation."
                                )
                            },
                        )
                        return
                    if (
                        not payload.controlled_email_domain_confirmed
                        or not payload.controlled_email_domain
                    ):
                        self._json(
                            400,
                            {
                                "detail": (
                                    "Confirm that the test-email domain and receiving inbox are "
                                    "under your control."
                                )
                            },
                        )
                        return
                if bool(payload.existing_test_email) != bool(payload.existing_test_password):
                    self._json(
                        400,
                        {
                            "detail": (
                                "Provide both existing test email and password, or "
                                "leave both empty."
                            )
                        },
                    )
                    return
                job_id = secrets.token_hex(6)
                job = ScanJob(
                    id=job_id,
                    target_url=target,
                    model=payload.model,
                    api_key=payload.api_key.get_secret_value(),
                    api_base=payload.api_base,
                    scan_mode=payload.scan_mode,
                    max_budget_usd=payload.max_budget_usd,
                    max_runtime_minutes=min(
                        payload.max_runtime_minutes,
                        max(5, config.MAX_RUNTIME_SECONDS // 60),
                    ),
                    allow_private_target=allow_private,
                    create_test_account=payload.create_test_account,
                    controlled_email_domain=payload.controlled_email_domain,
                    account_recipe=payload.account_recipe,
                    existing_test_email=payload.existing_test_email,
                    existing_test_password=(
                        payload.existing_test_password.get_secret_value()
                        if payload.existing_test_password
                        else None
                    ),
                    imap_host=payload.imap_host,
                    imap_port=payload.imap_port,
                    imap_username=payload.imap_username,
                    imap_password=(
                        payload.imap_password.get_secret_value()
                        if payload.imap_password
                        else None
                    ),
                )
                with JOBS_LOCK:
                    JOBS[job_id] = job
                touch(job, "queued", "Assessment queued")
                asyncio.run_coroutine_threadsafe(_run_job(job), LOOP)
                persist_public_jobs()
                self._json(202, job.public())
                return

            route = path.strip("/").split("/")
            if len(route) == 4 and route[0] == "api" and route[1] == "scans":
                job_id = unquote(route[2])
                with JOBS_LOCK:
                    job = JOBS.get(job_id)
                if not job:
                    self._json(404, {"detail": "Scan not found."})
                    return
                if route[3] == "continue":
                    if job.status != "needs_user_action":
                        self._json(
                            409,
                            {"detail": "This scan is not waiting for manual signup verification."},
                        )
                        return
                    LOOP.call_soon_threadsafe(job.operator_continue.set)
                    self._json(202, job.public())
                    return
                if route[3] == "stop":
                    future = asyncio.run_coroutine_threadsafe(stop_job(job), LOOP)
                    try:
                        future.result(timeout=15)
                    except Exception as exc:  # noqa: BLE001
                        self._json(
                            500,
                            {"detail": "Could not stop the scan cleanly: " + type(exc).__name__},
                        )
                        return
                    self._json(200, job.public())
                    return
            self._json(404, {"detail": "Route not found."})
        except ValueError as exc:
            self._json(400, {"detail": str(exc)})
        except Exception as exc:  # noqa: BLE001
            self._json(500, {"detail": "Controller error: " + type(exc).__name__})

    def send_error(
        self, code: int, message: str | None = None, explain: str | None = None
    ) -> None:  # noqa: N802, ARG002
        self._json(code, {"detail": message or "Request failed."})


class LocalServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def serve(port: int = 8765) -> None:
    config.DATA_DIR.mkdir(parents=True, exist_ok=True)
    if not LOOP.is_running():
        thread = threading.Thread(
            target=_run_event_loop, name="strix-oneclick-event-loop", daemon=True
        )
        thread.start()
        if not LOOP_READY.wait(timeout=5):
            raise RuntimeError("The background scan event loop did not start.")
    server = LocalServer(("127.0.0.1", port), OneClickHandler)
    sys.stdout.write("Strix One-Click dashboard: http://127.0.0.1:" + str(port) + "\n")
    sys.stdout.write("Local-only controller. Do not expose this port to a network.\n")
    sys.stdout.flush()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        sys.stdout.write("\nStopping Strix One-Click controller…\n")
    finally:
        server.shutdown()
        server.server_close()
        for job in list(JOBS.values()):
            future = asyncio.run_coroutine_threadsafe(stop_job(job), LOOP)
            try:
                future.result(timeout=10)
            except Exception:  # noqa: BLE001
                pass
        LOOP.call_soon_threadsafe(LOOP.stop)
