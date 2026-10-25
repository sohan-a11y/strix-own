from __future__ import annotations

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest

from strix.oneclick import app as oneclick_app
from strix.oneclick import config
from strix.oneclick.runner import JOBS, JOBS_LOCK


class TargetHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        body = b"<!doctype html><title>Test application</title><h1>Test application</h1>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _fmt: str, *_args: object) -> None:
        return


@pytest.fixture(scope="module", autouse=True)
def background_event_loop() -> None:
    if not oneclick_app.LOOP.is_running():
        thread = threading.Thread(
            target=oneclick_app._run_event_loop,
            name="test-strix-oneclick-loop",
            daemon=True,
        )
        thread.start()
        assert oneclick_app.LOOP_READY.wait(timeout=5), "dashboard event loop did not start"


@pytest.fixture
def dashboard(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> object:
    data_dir = tmp_path / "controller-data"
    work_dir = tmp_path / "work"
    data_dir.mkdir()
    work_dir.mkdir()
    monkeypatch.setattr(config, "DATA_DIR", data_dir)
    monkeypatch.setattr(config, "WORK_DIR", work_dir)
    monkeypatch.setattr(config, "MAX_RUNTIME_SECONDS", 900)

    fake_cli = tmp_path / "fake-strix"
    fake_cli.write_text(
        """#!/usr/bin/env python3
import os
import sys
import urllib.request
from pathlib import Path

args = sys.argv[1:]
target = args[args.index("--target") + 1]
instruction_file = Path(args[args.index("--instruction-file") + 1])
assert os.environ.get("STRIX_LLM") == "test-provider/test-model"
assert os.environ.get("LLM_API_KEY") == "test-secret-api-key"
assert instruction_file.is_file()
with urllib.request.urlopen(target, timeout=5) as response:
    assert response.status == 200
run_dir = Path.cwd() / "strix_runs" / "oneclick-e2e"
run_dir.mkdir(parents=True, exist_ok=True)
(run_dir / "penetration_test_report.md").write_text(
    "# Mock end-to-end report\\n\\nController launch and target reachability succeeded.\\n",
    encoding="utf-8",
)
(run_dir / "vulnerabilities.json").write_text("[]", encoding="utf-8")
print("Penetration test initiated", flush=True)
print("Output: strix_runs/oneclick-e2e", flush=True)
""",
        encoding="utf-8",
    )
    fake_cli.chmod(0o755)
    monkeypatch.setattr(config, "STRIX_COMMAND", str(fake_cli))

    target = ThreadingHTTPServer(("127.0.0.1", 0), TargetHandler)
    target_thread = threading.Thread(target=target.serve_forever, daemon=True)
    target_thread.start()
    target_url = f"http://127.0.0.1:{target.server_address[1]}"

    with JOBS_LOCK:
        JOBS.clear()
    server = oneclick_app.LocalServer(("127.0.0.1", 0), oneclick_app.OneClickHandler)
    dashboard_thread = threading.Thread(target=server.serve_forever, daemon=True)
    dashboard_thread.start()
    base_url = f"http://127.0.0.1:{server.server_address[1]}"

    class Context:
        def __init__(self) -> None:
            self.base_url = base_url
            self.target_url = target_url
            self.work_dir = work_dir
            self.data_dir = data_dir

    try:
        yield Context()
    finally:
        server.shutdown()
        server.server_close()
        dashboard_thread.join(timeout=5)
        target.shutdown()
        target.server_close()
        target_thread.join(timeout=5)
        with JOBS_LOCK:
            JOBS.clear()


def _request(
    url: str,
    data: dict[str, object] | None = None,
    headers: dict[str, str] | None = None,
):
    request = Request(
        url,
        data=json.dumps(data).encode("utf-8") if data is not None else None,
        headers={"Content-Type": "application/json", **(headers or {})},
        method="POST" if data is not None else "GET",
    )
    return urlopen(request, timeout=10)


def test_dashboard_serves_ui_and_health(dashboard: object) -> None:
    with _request(dashboard.base_url + "/") as response:
        page = response.read().decode("utf-8")
        assert response.status == 200
        assert "Start security assessment" in page

    with _request(dashboard.base_url + "/api/health") as response:
        health = json.loads(response.read())
        assert health["ok"] is True
        assert health["strix_available"] is True


def test_dashboard_runs_mock_strix_end_to_end(dashboard: object) -> None:
    payload = {
        "target_url": dashboard.target_url,
        "model": "test-provider/test-model",
        "api_key": "test-secret-api-key",
        "scan_mode": "quick",
        "max_budget_usd": 0.5,
        "max_runtime_minutes": 5,
        "authorized": True,
        "allow_private_target": True,
    }
    with _request(dashboard.base_url + "/api/scans", payload) as response:
        scan = json.loads(response.read())
        assert response.status == 202
        scan_id = scan["id"]

    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        with _request(dashboard.base_url + f"/api/scans/{scan_id}") as response:
            scan = json.loads(response.read())
        if scan["status"] in {
            "completed",
            "completed_with_findings",
            "failed",
            "stopped",
        }:
            break
        time.sleep(0.1)

    assert scan["status"] == "completed", scan
    assert scan["run_name"] == "oneclick-e2e"

    with _request(dashboard.base_url + f"/api/scans/{scan_id}/report") as response:
        report = response.read().decode("utf-8")
    assert "Controller launch and target reachability succeeded" in report

    with _request(dashboard.base_url + f"/api/scans/{scan_id}/log") as response:
        log = response.read().decode("utf-8")
    assert "test-secret-api-key" not in log

    jobs_json = (dashboard.data_dir / "jobs.json").read_text(encoding="utf-8")
    assert "test-secret-api-key" not in jobs_json
    report_file = (
        dashboard.work_dir
        / "strix_runs"
        / "oneclick-e2e"
        / "penetration_test_report.md"
    )
    assert report_file.is_file()


def test_dashboard_requires_authorization(dashboard: object) -> None:
    payload = {
        "target_url": dashboard.target_url,
        "model": "test-provider/test-model",
        "api_key": "test-secret-api-key",
        "authorized": False,
    }
    with pytest.raises(HTTPError) as error:
        _request(dashboard.base_url + "/api/scans", payload)
    assert error.value.code == 400


def test_api_rejects_non_local_host_header(dashboard: object) -> None:
    with pytest.raises(HTTPError) as error:
        _request(dashboard.base_url + "/api/health", headers={"Host": "example.invalid"})
    assert error.value.code == 403
