from __future__ import annotations

import importlib.util
import json
import sqlite3
import sys
from pathlib import Path


SCRIPT_PATH = (
    Path(__file__).resolve().parents[2]
    / "optional-skills"
    / "observability"
    / "vercel-observability-loop"
    / "scripts"
    / "vercel_observability.py"
)


def load_module():
    spec = importlib.util.spec_from_file_location("vercel_observability_skill", SCRIPT_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_preflight_reads_vercel_linked_project(tmp_path: Path, monkeypatch):
    mod = load_module()
    project_dir = tmp_path / "app"
    (project_dir / ".vercel").mkdir(parents=True)
    (project_dir / ".vercel" / "project.json").write_text(
        json.dumps(
            {
                "projectId": "prj_123",
                "orgId": "team_456",
                "projectName": "demo-app",
            }
        ),
        encoding="utf-8",
    )
    (project_dir / "vercel.json").write_text("{}", encoding="utf-8")

    monkeypatch.setattr(mod.shutil, "which", lambda name: "/opt/homebrew/bin/vercel")

    def fake_run(cmd, **kwargs):
        joined = " ".join(cmd)
        if joined == "vercel --version":
            return mod.subprocess.CompletedProcess(cmd, 0, stdout="Vercel CLI 50.31.0\n", stderr="")
        if joined == "vercel --help":
            return mod.subprocess.CompletedProcess(cmd, 0, stdout="Commands:\n  api\n", stderr="")
        if joined == "vercel whoami --no-color --non-interactive":
            return mod.subprocess.CompletedProcess(cmd, 0, stdout="rewbs\n", stderr="")
        raise AssertionError(f"Unexpected command: {cmd}")

    monkeypatch.setattr(mod, "run_command", fake_run)

    result = mod.run_preflight(project_dir)

    assert result["project"]["linked"] is True
    assert result["project"]["project_id"] == "prj_123"
    assert result["cli"]["logged_in"] is True
    assert result["recommended_mode"] == "runtime-or-drain"


def test_collect_runtime_logs_persists_json_lines(tmp_path: Path, monkeypatch):
    mod = load_module()
    runtime_paths = mod.resolve_paths(tmp_path / ".hermes" / "observability")

    sample_lines = "\n".join(
        [
            json.dumps(
                {
                    "timestamp": "2026-03-16T01:02:03Z",
                    "level": "error",
                    "message": "Database timeout for /api/orders",
                    "path": "/api/orders",
                    "statusCode": 500,
                    "requestId": "req_123",
                    "source": "serverless",
                }
            ),
            json.dumps(
                {
                    "timestamp": "2026-03-16T01:04:05Z",
                    "level": "info",
                    "message": "render home page",
                    "path": "/",
                    "statusCode": 200,
                    "requestId": "req_456",
                    "source": "edge-function",
                }
            ),
        ]
    )

    def fake_run(cmd, **kwargs):
        return mod.subprocess.CompletedProcess(cmd, 0, stdout=sample_lines, stderr="")

    monkeypatch.setattr(mod, "run_command", fake_run)

    result = mod.collect_runtime_logs(
        cwd=tmp_path,
        base_dir=runtime_paths["state_dir"],
        since="30m",
        until=None,
        project=None,
        environment=None,
        level=None,
        source=None,
        limit=100,
        search=None,
        request_id=None,
        status_code=None,
    )

    assert result["success"] is True
    assert result["stored"] == 2

    conn = sqlite3.connect(runtime_paths["db_path"])
    try:
        count = conn.execute("SELECT COUNT(*) FROM log_events").fetchone()[0]
    finally:
        conn.close()
    assert count == 2


def test_verify_signature_uses_hmac_sha1():
    mod = load_module()
    body = b'{"message":"hello"}'
    secret = "shared-secret"
    signature = mod.hmac.new(secret.encode("utf-8"), body, "sha1").hexdigest()

    assert mod.verify_signature(body, signature, secret) is True
    assert mod.verify_signature(body, "bad-signature", secret) is False


def test_build_drain_payload_includes_self_served_source():
    mod = load_module()

    payload = mod.build_drain_payload(
        name="hermes-observability",
        target_url="https://example.trycloudflare.com",
        project_id="prj_123",
        sources=["serverless", "static"],
        headers={"X-Test": "1"},
        secret="secret",
        delivery_format="json",
    )

    assert payload["name"] == "hermes-observability"
    assert payload["projectIds"] == ["prj_123"]
    assert payload["source"] == {"kind": "self-served"}
    assert payload["sources"] == ["serverless", "static"]
    assert payload["headers"]["X-Test"] == "1"


def test_normalize_log_record_handles_vercel_millisecond_timestamps_and_empty_messages():
    mod = load_module()

    record = mod.normalize_log_record(
        {
            "id": "4chxq-1773620260046-25aa70eb0443",
            "timestamp": 1773620260046,
            "deploymentId": "dpl_123",
            "projectId": "prj_123",
            "level": "info",
            "message": "",
            "source": "serverless",
            "domain": "portal.nousresearch.com",
            "requestMethod": "POST",
            "requestPath": "/refresh",
            "responseStatusCode": 0,
            "environment": "production",
            "traceId": "",
        },
        "runtime",
    )

    assert record["observed_at"] == "2026-03-16T00:17:40.046000Z"
    assert record["path"] == "/refresh"
    assert record["host"] == "portal.nousresearch.com"
    assert record["status_code"] == 0
    assert record["message"] == "POST /refresh -> 0 serverless"
    assert record["request_id"] == "4chxq-1773620260046-25aa70eb0443"


def test_analyze_rows_flags_noisy_and_missing_context(tmp_path: Path):
    mod = load_module()
    repo_root = tmp_path / "repo"
    (repo_root / "app" / "api").mkdir(parents=True)
    (repo_root / "app" / "api" / "orders.ts").write_text("export function handler() {}", encoding="utf-8")

    rows = []
    for index in range(12):
        rows.append(
            {
                "fingerprint": "noise",
                "origin": "runtime",
                "source": "edge-function",
                "level": "info",
                "status_code": 200,
                "request_id": f"req_{index}",
                "deployment_id": None,
                "environment": "preview",
                "path": "/",
                "host": None,
                "message": "Rendered landing page",
                "raw_json": "{}",
            }
        )
    rows.append(
        {
            "fingerprint": "bug",
            "origin": "runtime",
            "source": "serverless",
            "level": "error",
            "status_code": 500,
            "request_id": None,
            "deployment_id": None,
            "environment": "production",
            "path": "/api/orders",
            "host": None,
            "message": "Internal Server Error",
            "raw_json": "{}",
        }
    )

    analysis = mod.analyze_rows(rows, repo_root, sample_limit=3)

    assert analysis["summary"]["bug_candidates"] >= 1
    assert analysis["summary"]["noisy_log_candidates"] >= 1
    assert analysis["summary"]["missing_context_candidates"] >= 1
    assert any("orders.ts" in ",".join(item["likely_files"]) for item in analysis["bug_candidates"])


def test_live_session_runs_end_to_end_and_scopes_analysis(tmp_path: Path, monkeypatch):
    mod = load_module()
    runtime_paths = mod.resolve_paths(tmp_path / ".hermes" / "observability")
    calls: dict[str, object] = {}

    monkeypatch.setattr(
        mod,
        "run_preflight",
        lambda cwd: {
            "success": True,
            "cli": {"installed": True, "logged_in": True, "api_supported": True},
            "project": {"project_id": "prj_123"},
        },
    )
    monkeypatch.setattr(
        mod,
        "start_receiver_background",
        lambda **kwargs: {
            "success": True,
            "server": object(),
            "thread": object(),
            "startup": {
                "listening": "http://127.0.0.1:4319",
                "port": 4319,
                "db_path": str(runtime_paths["db_path"]),
                "raw_dir": str(runtime_paths["raw_dir"]),
            },
        },
    )
    monkeypatch.setattr(
        mod,
        "start_tunnel",
        lambda **kwargs: {
            "success": True,
            "provider": "cloudflared",
            "public_url": "https://demo.trycloudflare.com",
            "command": ["cloudflared", "tunnel"],
            "process": object(),
            "reader_thread": object(),
        },
    )
    monkeypatch.setattr(
        mod,
        "ensure_drain",
        lambda **kwargs: {
            "success": True,
            "action": "create",
            "response": {"json": {"id": "drn_123"}},
        },
    )

    row_ids = iter([10, 16])
    monkeypatch.setattr(mod, "get_max_row_id", lambda db_path: next(row_ids))
    monkeypatch.setattr(mod.time, "sleep", lambda seconds: calls.setdefault("slept", seconds))
    monkeypatch.setattr(
        mod,
        "delete_drain",
        lambda **kwargs: {"success": True, "deleted": kwargs["drain_id"]},
    )
    monkeypatch.setattr(mod, "stop_tunnel", lambda process, reader_thread: {"success": True, "status": "stopped"})
    monkeypatch.setattr(mod, "stop_receiver_background", lambda server, thread: {"success": True, "status": "stopped"})

    def fake_analyze_database(**kwargs):
        calls["analyze_kwargs"] = kwargs
        return {
            "success": True,
            "report_path": str(kwargs["report_path"]),
            "analysis": {
                "summary": {
                    "records": 2,
                    "clusters": 1,
                    "bug_candidates": 1,
                    "noisy_log_candidates": 0,
                    "missing_context_candidates": 0,
                }
            },
        }

    monkeypatch.setattr(mod, "analyze_database", fake_analyze_database)

    result = mod.run_live_session(
        cwd=tmp_path,
        base_dir=runtime_paths["state_dir"],
        minutes=0.05,
        bind="127.0.0.1",
        port=4319,
        secret="shared-secret",
        name_prefix="session",
        project_id=None,
        scope=None,
        sources=["serverless"],
        headers=None,
        delivery_format="json",
        tunnel="auto",
        tunnel_timeout=10.0,
        environment="production",
        limit=250,
        sample_limit=15,
        report_path=None,
    )

    assert result["success"] is True
    assert calls["slept"] == 3.0
    assert result["session"]["drain_id"] == "drn_123"
    assert result["session"]["drain_name"].startswith("session-")
    assert result["cleanup"]["drain"]["deleted"] == "drn_123"

    analyze_kwargs = calls["analyze_kwargs"]
    assert analyze_kwargs["origins"] == ["drain"]
    assert analyze_kwargs["min_row_id"] == 10
    assert analyze_kwargs["max_row_id"] == 16
    assert analyze_kwargs["environment"] == "production"
    assert analyze_kwargs["limit"] == 250
    assert analyze_kwargs["sample_limit"] == 15
    assert analyze_kwargs["report_path"].name.startswith("live-session-")


def test_live_session_cleans_up_receiver_and_tunnel_when_drain_creation_fails(tmp_path: Path, monkeypatch):
    mod = load_module()
    runtime_paths = mod.resolve_paths(tmp_path / ".hermes" / "observability")
    calls = {"stop_tunnel": 0, "stop_receiver": 0, "analyze": 0}

    monkeypatch.setattr(
        mod,
        "run_preflight",
        lambda cwd: {
            "success": True,
            "cli": {"installed": True, "logged_in": True, "api_supported": True},
            "project": {"project_id": "prj_123"},
        },
    )
    monkeypatch.setattr(
        mod,
        "start_receiver_background",
        lambda **kwargs: {
            "success": True,
            "server": object(),
            "thread": object(),
            "startup": {
                "listening": "http://127.0.0.1:4319",
                "port": 4319,
                "db_path": str(runtime_paths["db_path"]),
                "raw_dir": str(runtime_paths["raw_dir"]),
            },
        },
    )
    monkeypatch.setattr(
        mod,
        "start_tunnel",
        lambda **kwargs: {
            "success": True,
            "provider": "cloudflared",
            "public_url": "https://demo.trycloudflare.com",
            "command": ["cloudflared", "tunnel"],
            "process": object(),
            "reader_thread": object(),
        },
    )
    monkeypatch.setattr(
        mod,
        "ensure_drain",
        lambda **kwargs: {"success": False, "phase": "create", "response": {"stderr": "boom"}},
    )
    monkeypatch.setattr(mod, "get_max_row_id", lambda db_path: 0)
    monkeypatch.setattr(
        mod,
        "stop_tunnel",
        lambda process, reader_thread: calls.__setitem__("stop_tunnel", calls["stop_tunnel"] + 1) or {"success": True},
    )
    monkeypatch.setattr(
        mod,
        "stop_receiver_background",
        lambda server, thread: calls.__setitem__("stop_receiver", calls["stop_receiver"] + 1) or {"success": True},
    )
    monkeypatch.setattr(mod, "delete_drain", lambda **kwargs: (_ for _ in ()).throw(AssertionError("delete_drain should not be called")))
    monkeypatch.setattr(
        mod,
        "analyze_database",
        lambda **kwargs: calls.__setitem__("analyze", calls["analyze"] + 1) or {"success": True},
    )

    result = mod.run_live_session(
        cwd=tmp_path,
        base_dir=runtime_paths["state_dir"],
        minutes=0.01,
        bind="127.0.0.1",
        port=4319,
        secret="shared-secret",
        name_prefix="session",
        project_id=None,
        scope=None,
        sources=["serverless"],
        headers=None,
        delivery_format="json",
        tunnel="auto",
        tunnel_timeout=10.0,
        environment=None,
        limit=None,
        sample_limit=20,
        report_path=None,
    )

    assert result["success"] is False
    assert result["phase"] == "ensure-drain"
    assert calls["stop_tunnel"] == 1
    assert calls["stop_receiver"] == 1
    assert calls["analyze"] == 0
