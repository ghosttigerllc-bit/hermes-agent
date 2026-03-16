#!/usr/bin/env python3
"""Vercel observability helper for Hermes optional skill workflows."""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import hmac
import json
import queue
import re
import secrets
import shutil
import sqlite3
import subprocess
import sys
import threading
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Iterable, Sequence
from urllib.parse import urlparse


DEFAULT_STATE_DIR = Path(".hermes") / "observability"
DEFAULT_DB_NAME = "logs.sqlite3"
DEFAULT_RAW_DIR_NAME = "raw"
DEFAULT_STATE_FILE = "vercel_state.json"
DEFAULT_REPORT_DIR = "reports"
DEFAULT_DRAIN_SOURCES = [
    "serverless",
    "edge-function",
    "edge-middleware",
    "static",
]
GENERIC_ERROR_MESSAGES = {
    "error",
    "internal server error",
    "unexpected error",
    "request failed",
    "failed",
}
FINGERPRINT_NUMBER_RE = re.compile(r"\b\d+\b")
FINGERPRINT_HEX_RE = re.compile(r"\b[0-9a-f]{8,}\b", re.IGNORECASE)
FINGERPRINT_UUID_RE = re.compile(
    r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
    re.IGNORECASE,
)
PATH_TOKEN_RE = re.compile(r"[A-Za-z0-9_-]{3,}")
STACK_PATH_RE = re.compile(r"([A-Za-z0-9_./-]+\.(?:ts|tsx|js|jsx|py|go|rb|java|php|mjs|cjs))")
TUNNEL_URL_RE = re.compile(
    r"https://[A-Za-z0-9.-]+\.(?:trycloudflare\.com|ngrok(?:-free)?\.app|ngrok\.io)\b"
)


@dataclass
class Cluster:
    fingerprint: str
    records: list[dict[str, Any]]

    @property
    def count(self) -> int:
        return len(self.records)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def utc_now_iso() -> str:
    return utc_now().isoformat().replace("+00:00", "Z")


def ensure_state_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path


def ensure_db(db_path: Path) -> Path:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS log_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ingested_at TEXT NOT NULL,
                observed_at TEXT,
                origin TEXT NOT NULL,
                source TEXT,
                level TEXT,
                status_code INTEGER,
                request_id TEXT,
                deployment_id TEXT,
                environment TEXT,
                path TEXT,
                host TEXT,
                message TEXT,
                fingerprint TEXT NOT NULL,
                raw_json TEXT NOT NULL
            )
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_log_events_observed_at ON log_events(observed_at)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_log_events_fingerprint ON log_events(fingerprint)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_log_events_origin ON log_events(origin)"
        )
        conn.commit()
    finally:
        conn.close()
    return db_path


def ensure_runtime_paths(base_dir: Path) -> dict[str, Path]:
    state_dir = ensure_state_dir(base_dir)
    raw_dir = ensure_state_dir(state_dir / DEFAULT_RAW_DIR_NAME)
    report_dir = ensure_state_dir(state_dir / DEFAULT_REPORT_DIR)
    db_path = ensure_db(state_dir / DEFAULT_DB_NAME)
    state_path = state_dir / DEFAULT_STATE_FILE
    return {
        "state_dir": state_dir,
        "raw_dir": raw_dir,
        "report_dir": report_dir,
        "db_path": db_path,
        "state_path": state_path,
    }


def emit(payload: dict[str, Any], exit_code: int = 0) -> int:
    print(json.dumps(payload, indent=2, sort_keys=True))
    return exit_code


def nested_lookup(item: Any, key: str) -> Any:
    value = item
    for part in key.split("."):
        if isinstance(value, dict) and part in value:
            value = value[part]
        else:
            return None
    return value


def first_present(item: dict[str, Any], keys: Sequence[str]) -> Any:
    for key in keys:
        value = nested_lookup(item, key)
        if value not in (None, "", [], {}):
            return value
    return None


def parse_timestamp(value: Any) -> str | None:
    if value in (None, ""):
        return None
    if isinstance(value, (int, float)):
        numeric = float(value)
        if numeric > 1e18:
            numeric /= 1e9
        elif numeric > 1e15:
            numeric /= 1e6
        elif numeric > 1e12:
            numeric /= 1e3
        return datetime.fromtimestamp(numeric, tz=timezone.utc).isoformat().replace(
            "+00:00", "Z"
        )

    text = str(value).strip()
    if not text:
        return None

    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(text).astimezone(timezone.utc).isoformat().replace(
            "+00:00", "Z"
        )
    except ValueError:
        pass

    for fmt in ("%a, %d %b %Y %H:%M:%S %z", "%Y-%m-%d %H:%M:%S"):
        with contextlib.suppress(ValueError):
            dt = datetime.strptime(str(value), fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    return None


def parse_int(value: Any) -> int | None:
    if value in (None, ""):
        return None
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return None


def normalize_message_template(message: str) -> str:
    normalized = message.strip().lower()
    normalized = FINGERPRINT_UUID_RE.sub("<uuid>", normalized)
    normalized = FINGERPRINT_HEX_RE.sub("<hex>", normalized)
    normalized = FINGERPRINT_NUMBER_RE.sub("<num>", normalized)
    normalized = re.sub(r"'[^']*'", "'<str>'", normalized)
    normalized = re.sub(r'"[^"]*"', '"<str>"', normalized)
    normalized = re.sub(r"\s+", " ", normalized)
    return normalized[:512]


def compute_fingerprint(source: str | None, path: str | None, message: str, status_code: int | None) -> str:
    basis = "|".join(
        [
            (source or "").lower(),
            (path or "").lower(),
            str(status_code or ""),
            normalize_message_template(message),
        ]
    )
    return hashlib.sha1(basis.encode("utf-8")).hexdigest()


def guess_level(raw: dict[str, Any], status_code: int | None) -> str:
    level = str(
        first_present(
            raw,
            ["level", "severity", "status", "type", "metadata.level", "event.level"],
        )
        or ""
    ).strip().lower()
    if level:
        return level
    if status_code is not None and status_code >= 500:
        return "error"
    if status_code is not None and status_code >= 400:
        return "warning"
    return "info"


def extract_path_and_host(raw: dict[str, Any]) -> tuple[str | None, str | None]:
    path_value = first_present(raw, ["path", "requestPath", "request.path", "metadata.path"])
    host_value = first_present(raw, ["host", "domain", "request.host", "metadata.host"])
    url_value = first_present(raw, ["url", "request.url", "metadata.url"])

    if url_value:
        parsed = urlparse(str(url_value))
        if not path_value and parsed.path:
            path_value = parsed.path
        if not host_value and parsed.netloc:
            host_value = parsed.netloc
    return (
        str(path_value).strip() if path_value else None,
        str(host_value).strip() if host_value else None,
    )


def build_fallback_message(
    raw: dict[str, Any],
    *,
    path_value: str | None,
    status_code: int | None,
) -> str:
    method = str(first_present(raw, ["requestMethod", "method", "request.method"]) or "").strip().upper()
    source = str(first_present(raw, ["source", "runtime", "category"]) or "").strip().lower()
    status_text = f" -> {status_code}" if status_code is not None else ""
    parts = [part for part in (method, path_value or "", status_text.strip(), source) if part]
    if parts:
        return " ".join(parts)
    return json.dumps(raw, ensure_ascii=True, sort_keys=True)


def normalize_log_record(raw: dict[str, Any], origin: str) -> dict[str, Any]:
    observed_at = parse_timestamp(
        first_present(
            raw,
            [
                "timestamp",
                "time",
                "created",
                "createdAt",
                "date",
                "date_sent",
                "event.timestamp",
                "metadata.timestamp",
            ],
        )
    )
    path_value, host_value = extract_path_and_host(raw)
    status_code = parse_int(
        first_present(
            raw, ["statusCode", "responseStatusCode", "status_code", "status", "response.statusCode"]
        )
    )
    raw_message = first_present(
        raw,
        [
            "message",
            "msg",
            "text",
            "error.message",
            "event.message",
            "metadata.message",
        ],
    )
    message = str(raw_message or "").strip()
    if not message:
        message = build_fallback_message(raw, path_value=path_value, status_code=status_code).strip()
    source = str(
        first_present(raw, ["source", "runtime", "category", "event.source"]) or ""
    ).strip().lower() or None
    level = guess_level(raw, status_code)
    request_id = first_present(raw, ["requestId", "request_id", "reqId", "request.id", "traceId", "id"])
    deployment_id = first_present(
        raw,
        ["deploymentId", "deployment_id", "deployment.id", "metadata.deploymentId"],
    )
    environment = first_present(raw, ["environment", "env", "target", "metadata.environment"])
    fingerprint = compute_fingerprint(source, path_value, message, status_code)

    return {
        "ingested_at": utc_now_iso(),
        "observed_at": observed_at,
        "origin": origin,
        "source": source,
        "level": level,
        "status_code": status_code,
        "request_id": str(request_id).strip() if request_id else None,
        "deployment_id": str(deployment_id).strip() if deployment_id else None,
        "environment": str(environment).strip() if environment else None,
        "path": path_value,
        "host": host_value,
        "message": message[:4000],
        "fingerprint": fingerprint,
        "raw_json": json.dumps(raw, ensure_ascii=True, sort_keys=True),
    }


def write_raw_payload(raw_dir: Path, origin: str, text: str) -> Path:
    raw_dir.mkdir(parents=True, exist_ok=True)
    name = f"{int(time.time() * 1000)}-{origin}-{uuid.uuid4().hex[:8]}.json"
    path = raw_dir / name
    path.write_text(text, encoding="utf-8")
    return path


def insert_records(db_path: Path, records: Iterable[dict[str, Any]]) -> int:
    rows = list(records)
    if not rows:
        return 0

    conn = sqlite3.connect(db_path)
    try:
        conn.executemany(
            """
            INSERT INTO log_events (
                ingested_at, observed_at, origin, source, level, status_code,
                request_id, deployment_id, environment, path, host, message,
                fingerprint, raw_json
            ) VALUES (
                :ingested_at, :observed_at, :origin, :source, :level, :status_code,
                :request_id, :deployment_id, :environment, :path, :host, :message,
                :fingerprint, :raw_json
            )
            """,
            rows,
        )
        conn.commit()
    finally:
        conn.close()
    return len(rows)


def get_max_row_id(db_path: Path) -> int:
    conn = sqlite3.connect(db_path)
    try:
        row = conn.execute("SELECT COALESCE(MAX(id), 0) FROM log_events").fetchone()
    finally:
        conn.close()
    return int((row or [0])[0] or 0)


def iter_drain_entries(payload: Any) -> Iterable[dict[str, Any]]:
    if isinstance(payload, list):
        for item in payload:
            if isinstance(item, dict):
                yield item
        return

    if not isinstance(payload, dict):
        return

    for key in ("logs", "entries", "events", "records", "payload", "data"):
        value = payload.get(key)
        if isinstance(value, list) and value and all(isinstance(item, dict) for item in value):
            for item in value:
                yield item
            return

    yield payload


def verify_signature(body: bytes, signature: str | None, secret: str | None) -> bool:
    if not secret:
        return True
    if not signature:
        return False
    expected = hmac.new(secret.encode("utf-8"), body, "sha1").hexdigest()
    return hmac.compare_digest(expected, signature.strip())


def run_command(
    args: Sequence[str],
    *,
    cwd: Path | None = None,
    input_text: str | None = None,
) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            list(args),
            cwd=str(cwd) if cwd else None,
            capture_output=True,
            text=True,
            input=input_text,
            check=False,
        )
    except FileNotFoundError as exc:
        return subprocess.CompletedProcess(list(args), 127, stdout="", stderr=str(exc))


def read_project_link(cwd: Path) -> dict[str, Any]:
    linked = {"linked": False, "path": None}
    project_file = cwd / ".vercel" / "project.json"
    if not project_file.exists():
        return linked

    with contextlib.suppress(json.JSONDecodeError, OSError):
        data = json.loads(project_file.read_text(encoding="utf-8"))
        linked.update(
            {
                "linked": True,
                "path": str(project_file),
                "project_id": data.get("projectId"),
                "org_id": data.get("orgId"),
                "project_name": data.get("projectName"),
            }
        )
    return linked


def run_preflight(cwd: Path) -> dict[str, Any]:
    cli_path = shutil.which("vercel")
    project_link = read_project_link(cwd)
    vercel_json = cwd / "vercel.json"

    cli = {
        "installed": bool(cli_path),
        "path": cli_path,
        "version": None,
        "logged_in": False,
        "user": None,
        "api_supported": False,
    }

    if cli_path:
        version_run = run_command(["vercel", "--version"], cwd=cwd)
        if version_run.returncode == 0:
            cli["version"] = version_run.stdout.strip()

        help_run = run_command(["vercel", "--help"], cwd=cwd)
        cli["api_supported"] = help_run.returncode == 0 and "api" in (
            help_run.stdout + help_run.stderr
        )

        whoami = run_command(["vercel", "whoami", "--no-color", "--non-interactive"], cwd=cwd)
        if whoami.returncode == 0:
            cli["logged_in"] = True
            cli["user"] = whoami.stdout.strip()

    recommended_mode = "runtime-only"
    if cli["installed"] and cli["logged_in"] and cli["api_supported"] and project_link["linked"]:
        recommended_mode = "runtime-or-drain"

    return {
        "success": True,
        "cwd": str(cwd),
        "vercel_json": str(vercel_json) if vercel_json.exists() else None,
        "project": project_link,
        "cli": cli,
        "recommended_mode": recommended_mode,
    }


def resolve_paths(base_dir: Path | None) -> dict[str, Path]:
    return ensure_runtime_paths((base_dir or DEFAULT_STATE_DIR).resolve())


def collect_runtime_logs(
    *,
    cwd: Path,
    base_dir: Path | None,
    since: str | None,
    until: str | None,
    project: str | None,
    environment: str | None,
    level: str | None,
    source: list[str] | None,
    limit: int,
    search: str | None,
    request_id: str | None,
    status_code: str | None,
) -> dict[str, Any]:
    runtime_paths = resolve_paths(base_dir)
    cmd = ["vercel", "logs", "--json", "--no-color", "--non-interactive", "--limit", str(limit)]
    if since:
        cmd.extend(["--since", since])
    if until:
        cmd.extend(["--until", until])
    if project:
        cmd.extend(["--project", project])
    if environment:
        cmd.extend(["--environment", environment])
    if level:
        cmd.extend(["--level", level])
    if search:
        cmd.extend(["--search", search])
    if request_id:
        cmd.extend(["--request-id", request_id])
    if status_code:
        cmd.extend(["--status-code", status_code])
    for item in source or []:
        cmd.extend(["--source", item])

    result = run_command(cmd, cwd=cwd)
    if result.returncode != 0:
        return {
            "success": False,
            "command": cmd,
            "stderr": result.stderr.strip(),
            "stdout": result.stdout.strip(),
        }

    raw_lines = [line for line in result.stdout.splitlines() if line.strip()]
    parsed: list[dict[str, Any]] = []
    invalid_lines: list[str] = []
    for line in raw_lines:
        with contextlib.suppress(json.JSONDecodeError):
            parsed.append(json.loads(line))
            continue
        invalid_lines.append(line)

    raw_path = write_raw_payload(runtime_paths["raw_dir"], "runtime", "\n".join(raw_lines))
    inserted = insert_records(
        runtime_paths["db_path"],
        [normalize_log_record(item, "runtime") for item in parsed],
    )
    return {
        "success": True,
        "command": cmd,
        "stored": inserted,
        "parsed_lines": len(parsed),
        "invalid_lines": invalid_lines,
        "raw_path": str(raw_path),
        "db_path": str(runtime_paths["db_path"]),
    }


def load_state(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"drains": []}
    with contextlib.suppress(json.JSONDecodeError, OSError):
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            return data
    return {"drains": []}


def save_state(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def parse_header_pairs(values: list[str] | None) -> dict[str, str]:
    headers: dict[str, str] = {}
    for value in values or []:
        if "=" not in value:
            continue
        key, raw = value.split("=", 1)
        key = key.strip()
        raw = raw.strip()
        if key:
            headers[key] = raw
    return headers


def build_drain_payload(
    *,
    name: str,
    target_url: str,
    project_id: str | None,
    sources: list[str] | None,
    headers: dict[str, str] | None,
    secret: str | None,
    delivery_format: str,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "name": name,
        "url": target_url,
        "headers": headers or {},
        "deliveryFormat": delivery_format,
        "sources": sources or list(DEFAULT_DRAIN_SOURCES),
        "source": {"kind": "self-served"},
    }
    if project_id:
        payload["projectIds"] = [project_id]
    if secret:
        payload["secret"] = secret
    return payload


def vercel_api(
    endpoint: str,
    *,
    cwd: Path,
    method: str = "GET",
    scope: str | None = None,
    input_payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    cmd = ["vercel", "api", endpoint, "--method", method.upper(), "--raw", "--no-color", "--non-interactive"]
    if scope:
        cmd.extend(["--scope", scope])
    input_text = None
    if input_payload is not None:
        cmd.extend(["--input", "-"])
        input_text = json.dumps(input_payload)

    result = run_command(cmd, cwd=cwd, input_text=input_text)
    parsed: Any = None
    if result.stdout.strip():
        with contextlib.suppress(json.JSONDecodeError):
            parsed = json.loads(result.stdout)

    return {
        "success": result.returncode == 0,
        "command": cmd,
        "stdout": result.stdout.strip(),
        "stderr": result.stderr.strip(),
        "json": parsed,
    }


def extract_drains(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if isinstance(payload, dict):
        for key in ("drains", "items", "data"):
            value = payload.get(key)
            if isinstance(value, list):
                return [item for item in value if isinstance(item, dict)]
    return []


def drain_matches_project(drain: dict[str, Any], project_id: str | None) -> bool:
    if not project_id:
        return True
    raw_ids = drain.get("projectIds") or drain.get("projects") or []
    if isinstance(raw_ids, list):
        return project_id in raw_ids
    return False


def find_existing_drain(drains: list[dict[str, Any]], name: str, project_id: str | None) -> dict[str, Any] | None:
    for drain in drains:
        if str(drain.get("name") or "").strip() != name:
            continue
        if drain_matches_project(drain, project_id):
            return drain
    return None


def ensure_drain(
    *,
    cwd: Path,
    base_dir: Path | None,
    name: str,
    target_url: str,
    project_id: str | None,
    scope: str | None,
    sources: list[str] | None,
    headers: dict[str, str] | None,
    secret: str | None,
    delivery_format: str,
    update_existing: bool,
) -> dict[str, Any]:
    runtime_paths = resolve_paths(base_dir)
    if not project_id:
        project_id = read_project_link(cwd).get("project_id")

    drains_response = vercel_api("/v1/drains", cwd=cwd, scope=scope)
    if not drains_response["success"]:
        return {"success": False, "phase": "list", **drains_response}

    drains = extract_drains(drains_response["json"])
    existing = find_existing_drain(drains, name, project_id)
    payload = build_drain_payload(
        name=name,
        target_url=target_url,
        project_id=project_id,
        sources=sources,
        headers=headers,
        secret=secret,
        delivery_format=delivery_format,
    )

    action = "create"
    response: dict[str, Any]
    if existing and update_existing:
        drain_id = existing.get("id") or existing.get("uid")
        response = vercel_api(
            f"/v1/drains/{drain_id}",
            cwd=cwd,
            scope=scope,
            method="PATCH",
            input_payload=payload,
        )
        action = "update"
    elif existing:
        response = {
            "success": True,
            "command": [],
            "stdout": "",
            "stderr": "",
            "json": existing,
        }
        action = "reuse"
    else:
        response = vercel_api(
            "/v1/drains",
            cwd=cwd,
            scope=scope,
            method="POST",
            input_payload=payload,
        )

    state = load_state(runtime_paths["state_path"])
    if response.get("success") and isinstance(response.get("json"), dict):
        drain_info = {
            "name": name,
            "project_id": project_id,
            "target_url": target_url,
            "updated_at": utc_now_iso(),
            "drain": response["json"],
        }
        state["last_drain"] = drain_info
        drains_state = [item for item in state.get("drains", []) if item.get("name") != name]
        drains_state.append(drain_info)
        state["drains"] = drains_state
        save_state(runtime_paths["state_path"], state)

    return {
        "success": response.get("success", False),
        "action": action,
        "payload": payload,
        "project_id": project_id,
        "state_path": str(runtime_paths["state_path"]),
        "response": response,
    }


def delete_drain(
    *,
    cwd: Path,
    base_dir: Path | None,
    drain_id: str,
    scope: str | None,
) -> dict[str, Any]:
    runtime_paths = resolve_paths(base_dir)
    response = vercel_api(f"/v1/drains/{drain_id}", cwd=cwd, scope=scope, method="DELETE")
    state = load_state(runtime_paths["state_path"])
    state["drains"] = [
        item for item in state.get("drains", []) if str(item.get("drain", {}).get("id")) != drain_id
    ]
    if state.get("last_drain", {}).get("drain", {}).get("id") == drain_id:
        state.pop("last_drain", None)
    save_state(runtime_paths["state_path"], state)
    return {"success": response["success"], "response": response, "state_path": str(runtime_paths["state_path"])}


def parse_time_expr(expr: str | None) -> str | None:
    if not expr:
        return None
    text = expr.strip()
    if not text:
        return None

    if re.fullmatch(r"\d+[smhd]", text):
        amount = int(text[:-1])
        unit = text[-1]
        delta = {
            "s": timedelta(seconds=amount),
            "m": timedelta(minutes=amount),
            "h": timedelta(hours=amount),
            "d": timedelta(days=amount),
        }[unit]
        return (utc_now() - delta).isoformat().replace("+00:00", "Z")
    parsed = parse_timestamp(text)
    return parsed


def fetch_rows(
    *,
    db_path: Path,
    since: str | None,
    until: str | None,
    limit: int | None,
    environment: str | None,
    min_row_id: int | None = None,
    max_row_id: int | None = None,
    origins: list[str] | None = None,
) -> list[dict[str, Any]]:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    clauses = []
    values: list[Any] = []

    since_iso = parse_time_expr(since)
    until_iso = parse_time_expr(until)
    if since_iso:
        clauses.append("COALESCE(observed_at, ingested_at) >= ?")
        values.append(since_iso)
    if until_iso:
        clauses.append("COALESCE(observed_at, ingested_at) <= ?")
        values.append(until_iso)
    if environment:
        clauses.append("environment = ?")
        values.append(environment)
    if min_row_id is not None:
        clauses.append("id > ?")
        values.append(int(min_row_id))
    if max_row_id is not None:
        clauses.append("id <= ?")
        values.append(int(max_row_id))
    if origins:
        placeholders = ", ".join("?" for _ in origins)
        clauses.append(f"origin IN ({placeholders})")
        values.extend(origins)

    sql = "SELECT * FROM log_events"
    if clauses:
        sql += " WHERE " + " AND ".join(clauses)
    sql += " ORDER BY COALESCE(observed_at, ingested_at) DESC"
    if limit:
        sql += f" LIMIT {int(limit)}"

    try:
        rows = [dict(row) for row in conn.execute(sql, values)]
    finally:
        conn.close()
    return rows


def list_repo_files(repo_root: Path) -> list[str]:
    rg_path = shutil.which("rg")
    if rg_path:
        result = run_command([rg_path, "--files", "."], cwd=repo_root)
        if result.returncode == 0:
            return [line.strip() for line in result.stdout.splitlines() if line.strip()]

    files: list[str] = []
    for path in repo_root.rglob("*"):
        if path.is_file():
            with contextlib.suppress(ValueError):
                files.append(str(path.relative_to(repo_root)))
    return files


def score_file(file_path: str, cluster: Cluster) -> int:
    path_hints = {record.get("path") or "" for record in cluster.records}
    message_hints = " ".join(record.get("message") or "" for record in cluster.records[:5]).lower()
    score = 0
    lower_path = file_path.lower()

    for path_hint in path_hints:
        for token in PATH_TOKEN_RE.findall(path_hint.lower()):
            if token in lower_path:
                score += 2
    for stack_hit in STACK_PATH_RE.findall(message_hints):
        if stack_hit.lower() in lower_path:
            score += 5
    if "/api/" in " ".join(path_hints) and any(part in lower_path for part in ("/api/", "api/")):
        score += 3
    return score


def suggest_files(cluster: Cluster, repo_files: list[str], max_items: int = 5) -> list[str]:
    scored = []
    for file_path in repo_files:
        score = score_file(file_path, cluster)
        if score > 0:
            scored.append((score, file_path))
    scored.sort(key=lambda item: (-item[0], item[1]))
    return [path for _, path in scored[:max_items]]


def classify_severity(cluster: Cluster) -> str:
    status_codes = [record["status_code"] for record in cluster.records if record.get("status_code") is not None]
    levels = {str(record.get("level") or "").lower() for record in cluster.records}
    if any(code >= 500 for code in status_codes) or {"fatal", "error"} & levels:
        return "high"
    if any(code >= 400 for code in status_codes) or "warning" in levels:
        return "medium"
    return "low"


def looks_noisy(cluster: Cluster) -> bool:
    levels = {str(record.get("level") or "").lower() for record in cluster.records}
    return cluster.count >= 10 and not {"fatal", "error", "warning"} & levels


def missing_context(cluster: Cluster) -> bool:
    severity = classify_severity(cluster)
    if severity == "low":
        return False
    representative = cluster.records[0]
    message = normalize_message_template(str(representative.get("message") or ""))
    return (
        not representative.get("path")
        or not representative.get("request_id")
        or message in GENERIC_ERROR_MESSAGES
    )


def build_fix_proposal(cluster: Cluster, likely_files: list[str]) -> str:
    representative = cluster.records[0]
    path_value = representative.get("path") or "the affected route"
    severity = classify_severity(cluster)
    if looks_noisy(cluster):
        return (
            f"Demote or remove the repeated happy-path log around {path_value}. "
            "If the log is still useful for debugging, guard it behind a debug flag or sample it."
        )
    if missing_context(cluster):
        return (
            f"Add structured error logging at the boundary for {path_value} with request id, "
            "deployment id, status code, and the upstream dependency involved."
        )
    if severity == "high":
        suffix = ""
        if likely_files:
            suffix = f" Start with {likely_files[0]}."
        return (
            f"Inspect the failing code path for {path_value}, reproduce against the recent log sample, "
            f"and add a regression test before changing behavior.{suffix}"
        )
    return (
        f"Review the warning path for {path_value}, tighten validation or error handling, "
        "and decide whether the log should stay at warning level."
    )


def analyze_rows(rows: list[dict[str, Any]], repo_root: Path, sample_limit: int) -> dict[str, Any]:
    clusters_by_fp: dict[str, Cluster] = {}
    for row in rows:
        cluster = clusters_by_fp.setdefault(row["fingerprint"], Cluster(fingerprint=row["fingerprint"], records=[]))
        cluster.records.append(row)

    repo_files = list_repo_files(repo_root)
    ordered = sorted(
        clusters_by_fp.values(),
        key=lambda cluster: (
            {"high": 0, "medium": 1, "low": 2}[classify_severity(cluster)],
            -cluster.count,
        ),
    )

    def make_entry(cluster: Cluster) -> dict[str, Any]:
        representative = cluster.records[0]
        likely_files = suggest_files(cluster, repo_files)
        return {
            "fingerprint": cluster.fingerprint,
            "count": cluster.count,
            "severity": classify_severity(cluster),
            "origin": representative.get("origin"),
            "source": representative.get("source"),
            "path": representative.get("path"),
            "level": representative.get("level"),
            "status_code": representative.get("status_code"),
            "message_samples": [record.get("message") for record in cluster.records[:sample_limit]],
            "likely_files": likely_files,
            "proposal": build_fix_proposal(cluster, likely_files),
        }

    bug_clusters = [make_entry(cluster) for cluster in ordered if classify_severity(cluster) != "low"]
    noisy_clusters = [make_entry(cluster) for cluster in ordered if looks_noisy(cluster)]
    missing_clusters = [make_entry(cluster) for cluster in ordered if missing_context(cluster)]

    return {
        "summary": {
            "records": len(rows),
            "clusters": len(ordered),
            "bug_candidates": len(bug_clusters),
            "noisy_log_candidates": len(noisy_clusters),
            "missing_context_candidates": len(missing_clusters),
        },
        "bug_candidates": bug_clusters,
        "noisy_log_candidates": noisy_clusters,
        "missing_context_candidates": missing_clusters,
    }


def render_markdown_report(
    analysis: dict[str, Any],
    *,
    report_path: Path,
    since: str | None,
    until: str | None,
) -> Path:
    report_path.parent.mkdir(parents=True, exist_ok=True)
    summary = analysis["summary"]
    lines = [
        "# Vercel Observability Report",
        "",
        f"- Generated: {utc_now_iso()}",
        f"- Window start: {since or 'unspecified'}",
        f"- Window end: {until or 'now'}",
        f"- Records analyzed: {summary['records']}",
        f"- Fingerprint clusters: {summary['clusters']}",
        "",
        "## Bug Candidates",
    ]

    for index, item in enumerate(analysis["bug_candidates"], start=1):
        lines.extend(
            [
                f"### {index}. {item['severity'].title()} severity cluster",
                "",
                f"- Count: {item['count']}",
                f"- Source: {item.get('source') or 'unknown'}",
                f"- Path: {item.get('path') or 'unknown'}",
                f"- Level: {item.get('level') or 'unknown'}",
                f"- Status code: {item.get('status_code') or 'n/a'}",
                f"- Proposal: {item['proposal']}",
            ]
        )
        if item["likely_files"]:
            lines.append(f"- Likely files: {', '.join(item['likely_files'])}")
        lines.append("- Message samples:")
        for sample in item["message_samples"][:3]:
            lines.append(f"  - {sample}")
        lines.append("")

    lines.append("## Noisy Log Candidates")
    if not analysis["noisy_log_candidates"]:
        lines.append("")
        lines.append("- None detected in this window.")
    else:
        for item in analysis["noisy_log_candidates"]:
            lines.extend(
                [
                    "",
                    f"- {item.get('path') or 'unknown path'}: {item['count']} repeated entries",
                    f"  Proposal: {item['proposal']}",
                ]
            )

    lines.append("")
    lines.append("## Missing Context Candidates")
    if not analysis["missing_context_candidates"]:
        lines.append("")
        lines.append("- None detected in this window.")
    else:
        for item in analysis["missing_context_candidates"]:
            lines.extend(
                [
                    "",
                    f"- {item.get('path') or 'unknown path'}: {item['count']} entries lack useful context",
                    f"  Proposal: {item['proposal']}",
                ]
            )

    report_path.write_text("\n".join(lines).strip() + "\n", encoding="utf-8")
    return report_path


def analyze_database(
    *,
    cwd: Path,
    base_dir: Path | None,
    since: str | None,
    until: str | None,
    environment: str | None,
    limit: int | None,
    sample_limit: int,
    report_path: Path | None,
    min_row_id: int | None = None,
    max_row_id: int | None = None,
    origins: list[str] | None = None,
) -> dict[str, Any]:
    runtime_paths = resolve_paths(base_dir)
    rows = fetch_rows(
        db_path=runtime_paths["db_path"],
        since=since,
        until=until,
        limit=limit,
        environment=environment,
        min_row_id=min_row_id,
        max_row_id=max_row_id,
        origins=origins,
    )
    analysis = analyze_rows(rows, cwd, sample_limit=sample_limit)
    response = {
        "success": True,
        "db_path": str(runtime_paths["db_path"]),
        "analysis": analysis,
    }
    if report_path:
        written = render_markdown_report(
            analysis,
            report_path=report_path,
            since=since,
            until=until,
        )
        response["report_path"] = str(written)
    return response


def serve_receiver(
    *,
    base_dir: Path | None,
    bind: str,
    port: int,
    secret: str | None,
) -> int:
    runtime_paths = resolve_paths(base_dir)
    server, startup = create_receiver_server(
        runtime_paths=runtime_paths,
        bind=bind,
        port=port,
        secret=secret,
    )
    print(json.dumps(startup, sort_keys=True), flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        return emit({"success": True, "status": "stopped"})
    finally:
        server.server_close()
    return 0


def create_receiver_handler(
    *,
    runtime_paths: dict[str, Path],
    bind: str,
    secret: str | None,
) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        server_version = "HermesVercelDrain/1.0"

        def _send(self, status: int, payload: dict[str, Any]) -> None:
            body = json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: Any) -> None:
            sys.stdout.write("%s - - [%s] %s\n" % (self.address_string(), self.log_date_time_string(), format % args))

        def do_GET(self) -> None:
            if self.path not in ("/", "/healthz"):
                self._send(404, {"success": False, "error": "Not found"})
                return
            current_port = self.server.server_address[1]
            self._send(
                200,
                {
                    "success": True,
                    "status": "ok",
                    "listening": f"http://{bind}:{current_port}",
                    "db_path": str(runtime_paths["db_path"]),
                },
            )

        def do_POST(self) -> None:
            try:
                content_length = int(self.headers.get("Content-Length") or "0")
            except ValueError:
                self._send(400, {"success": False, "error": "Invalid Content-Length"})
                return

            body = self.rfile.read(content_length)
            if not verify_signature(body, self.headers.get("x-vercel-signature"), secret):
                self._send(401, {"success": False, "error": "Signature verification failed"})
                return

            try:
                payload = json.loads(body.decode("utf-8"))
            except json.JSONDecodeError as exc:
                self._send(400, {"success": False, "error": f"Invalid JSON: {exc}"})
                return

            entries = list(iter_drain_entries(payload))
            raw_path = write_raw_payload(runtime_paths["raw_dir"], "drain", body.decode("utf-8"))
            inserted = insert_records(
                runtime_paths["db_path"],
                [normalize_log_record(item, "drain") for item in entries],
            )
            self._send(200, {"success": True, "stored": inserted, "raw_path": str(raw_path)})

    return Handler


def create_receiver_server(
    *,
    runtime_paths: dict[str, Path],
    bind: str,
    port: int,
    secret: str | None,
) -> tuple[ThreadingHTTPServer, dict[str, Any]]:
    server = ThreadingHTTPServer(
        (bind, port),
        create_receiver_handler(runtime_paths=runtime_paths, bind=bind, secret=secret),
    )
    actual_port = int(server.server_address[1])
    startup = {
        "success": True,
        "listening": f"http://{bind}:{actual_port}",
        "port": actual_port,
        "db_path": str(runtime_paths["db_path"]),
        "raw_dir": str(runtime_paths["raw_dir"]),
    }
    return server, startup


def start_receiver_background(
    *,
    base_dir: Path | None,
    bind: str,
    port: int,
    secret: str | None,
) -> dict[str, Any]:
    runtime_paths = resolve_paths(base_dir)
    server, startup = create_receiver_server(
        runtime_paths=runtime_paths,
        bind=bind,
        port=port,
        secret=secret,
    )
    thread = threading.Thread(
        target=server.serve_forever,
        name="vercel-observability-receiver",
        daemon=True,
    )
    thread.start()
    return {"success": True, "server": server, "thread": thread, "startup": startup}


def stop_receiver_background(
    server: ThreadingHTTPServer | None,
    thread: threading.Thread | None,
    *,
    timeout: float = 5.0,
) -> dict[str, Any]:
    if server is None:
        return {"success": True, "status": "not-running"}
    server.shutdown()
    server.server_close()
    if thread is not None:
        thread.join(timeout=timeout)
    return {"success": True, "status": "stopped"}


def select_tunnel_provider(tunnel: str) -> str | None:
    if tunnel == "cloudflared":
        return "cloudflared" if shutil.which("cloudflared") else None
    if tunnel == "ngrok":
        return "ngrok" if shutil.which("ngrok") else None
    for candidate in ("cloudflared", "ngrok"):
        if shutil.which(candidate):
            return candidate
    return None


def build_tunnel_command(*, provider: str, bind: str, port: int) -> list[str]:
    local_url = f"http://{bind}:{port}"
    if provider == "cloudflared":
        return ["cloudflared", "tunnel", "--url", local_url, "--no-autoupdate"]
    if provider == "ngrok":
        return ["ngrok", "http", local_url, "--log", "stdout"]
    raise ValueError(f"Unsupported tunnel provider: {provider}")


def stop_process(
    process: subprocess.Popen[str] | None,
    *,
    timeout: float = 10.0,
) -> dict[str, Any]:
    if process is None:
        return {"success": True, "status": "not-running", "exit_code": None}
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=timeout)
    return {"success": True, "status": "stopped", "exit_code": process.returncode}


def start_tunnel(
    *,
    tunnel: str,
    bind: str,
    port: int,
    timeout: float = 30.0,
) -> dict[str, Any]:
    provider = select_tunnel_provider(tunnel)
    if not provider:
        return {
            "success": False,
            "error": "No supported tunnel binary found. Install cloudflared or ngrok.",
            "requested_tunnel": tunnel,
        }

    command = build_tunnel_command(provider=provider, bind=bind, port=port)
    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
    except OSError as exc:
        return {
            "success": False,
            "error": str(exc),
            "requested_tunnel": tunnel,
            "provider": provider,
            "command": command,
        }

    output_queue: queue.Queue[str] = queue.Queue()
    output_lines: list[str] = []

    def read_output() -> None:
        assert process.stdout is not None
        with process.stdout:
            for line in process.stdout:
                clean = line.rstrip()
                output_lines.append(clean)
                output_queue.put(clean)

    reader_thread = threading.Thread(
        target=read_output,
        name="vercel-observability-tunnel",
        daemon=True,
    )
    reader_thread.start()

    public_url = None
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None and output_queue.empty():
            break
        try:
            line = output_queue.get(timeout=0.25)
        except queue.Empty:
            continue
        match = TUNNEL_URL_RE.search(line)
        if match:
            public_url = match.group(0)
            break

    if not public_url:
        stop_process(process)
        reader_thread.join(timeout=1.0)
        return {
            "success": False,
            "error": "Tunnel started but no public URL was detected in its output.",
            "provider": provider,
            "command": command,
            "output_tail": output_lines[-20:],
        }

    return {
        "success": True,
        "provider": provider,
        "command": command,
        "public_url": public_url,
        "process": process,
        "reader_thread": reader_thread,
        "output_tail": output_lines[-20:],
    }


def stop_tunnel(
    process: subprocess.Popen[str] | None,
    reader_thread: threading.Thread | None,
    *,
    timeout: float = 10.0,
) -> dict[str, Any]:
    result = stop_process(process, timeout=timeout)
    if reader_thread is not None:
        reader_thread.join(timeout=1.0)
    return result


def extract_drain_id(payload: dict[str, Any] | None) -> str | None:
    if not isinstance(payload, dict):
        return None
    for key in ("id", "uid"):
        value = payload.get(key)
        if value:
            return str(value)
    return None


def default_live_session_report_path(runtime_paths: dict[str, Path]) -> Path:
    timestamp = utc_now().strftime("%Y%m%dT%H%M%SZ")
    return runtime_paths["report_dir"] / f"live-session-{timestamp}.md"


def run_live_session(
    *,
    cwd: Path,
    base_dir: Path | None,
    minutes: float,
    bind: str,
    port: int,
    secret: str | None,
    name_prefix: str,
    project_id: str | None,
    scope: str | None,
    sources: list[str] | None,
    headers: dict[str, str] | None,
    delivery_format: str,
    tunnel: str,
    tunnel_timeout: float,
    environment: str | None,
    limit: int | None,
    sample_limit: int,
    report_path: Path | None,
) -> dict[str, Any]:
    runtime_paths = resolve_paths(base_dir)
    preflight = run_preflight(cwd)
    if not preflight["cli"]["installed"]:
        return {"success": False, "phase": "preflight", "error": "Vercel CLI is not installed.", "preflight": preflight}
    if not preflight["cli"]["logged_in"]:
        return {"success": False, "phase": "preflight", "error": "Vercel CLI is not logged in.", "preflight": preflight}
    if not preflight["cli"]["api_supported"]:
        return {"success": False, "phase": "preflight", "error": "This Vercel CLI does not support `vercel api`.", "preflight": preflight}

    resolved_project_id = project_id or preflight["project"].get("project_id")
    if not resolved_project_id:
        return {
            "success": False,
            "phase": "preflight",
            "error": "No linked Vercel project was found. Pass --project-id or link the repo first.",
            "preflight": preflight,
        }

    session_suffix = uuid.uuid4().hex[:8]
    drain_name = f"{name_prefix.rstrip('-')}-{session_suffix}"
    shared_secret = secret or secrets.token_hex(20)
    actual_report_path = report_path or default_live_session_report_path(runtime_paths)

    receiver_server: ThreadingHTTPServer | None = None
    receiver_thread: threading.Thread | None = None
    tunnel_process: subprocess.Popen[str] | None = None
    tunnel_reader_thread: threading.Thread | None = None
    tunnel_result: dict[str, Any] | None = None
    drain_result: dict[str, Any] | None = None
    drain_id: str | None = None
    capture_started_at: str | None = None
    capture_finished_at: str | None = None
    cleanup: dict[str, Any] = {}
    start_row_id = get_max_row_id(runtime_paths["db_path"])

    try:
        receiver_result = start_receiver_background(
            base_dir=runtime_paths["state_dir"],
            bind=bind,
            port=port,
            secret=shared_secret,
        )
        receiver_server = receiver_result["server"]
        receiver_thread = receiver_result["thread"]
        receiver_startup = receiver_result["startup"]
        actual_port = int(receiver_startup["port"])

        tunnel_result = start_tunnel(
            tunnel=tunnel,
            bind=bind,
            port=actual_port,
            timeout=tunnel_timeout,
        )
        if not tunnel_result["success"]:
            return {
                "success": False,
                "phase": "tunnel",
                "preflight": preflight,
                "receiver": receiver_startup,
                "tunnel": tunnel_result,
            }

        tunnel_process = tunnel_result["process"]
        tunnel_reader_thread = tunnel_result["reader_thread"]
        drain_result = ensure_drain(
            cwd=cwd,
            base_dir=runtime_paths["state_dir"],
            name=drain_name,
            target_url=tunnel_result["public_url"],
            project_id=resolved_project_id,
            scope=scope,
            sources=sources,
            headers=headers,
            secret=shared_secret,
            delivery_format=delivery_format,
            update_existing=False,
        )
        if not drain_result["success"]:
            return {
                "success": False,
                "phase": "ensure-drain",
                "preflight": preflight,
                "receiver": receiver_startup,
                "tunnel": {
                    "success": True,
                    "provider": tunnel_result["provider"],
                    "public_url": tunnel_result["public_url"],
                    "command": tunnel_result["command"],
                },
                "drain": drain_result,
            }
        if drain_result["action"] == "reuse":
            return {
                "success": False,
                "phase": "ensure-drain",
                "error": f"Drain name collision for {drain_name}. Try again or pass a different --name-prefix.",
                "drain": drain_result,
            }

        drain_id = extract_drain_id(drain_result.get("response", {}).get("json"))
        if not drain_id:
            return {
                "success": False,
                "phase": "ensure-drain",
                "error": "Drain creation succeeded but no drain id was returned.",
                "drain": drain_result,
            }

        capture_started_at = utc_now_iso()
        time.sleep(max(0.0, minutes) * 60.0)
        capture_finished_at = utc_now_iso()
    finally:
        if drain_id:
            cleanup["drain"] = delete_drain(
                cwd=cwd,
                base_dir=runtime_paths["state_dir"],
                drain_id=drain_id,
                scope=scope,
            )
        if tunnel_process is not None or tunnel_reader_thread is not None:
            cleanup["tunnel"] = stop_tunnel(tunnel_process, tunnel_reader_thread)
        if receiver_server is not None or receiver_thread is not None:
            cleanup["receiver"] = stop_receiver_background(receiver_server, receiver_thread)

    end_row_id = get_max_row_id(runtime_paths["db_path"])
    analysis = analyze_database(
        cwd=cwd,
        base_dir=runtime_paths["state_dir"],
        since=capture_started_at,
        until=capture_finished_at,
        environment=environment,
        limit=limit,
        sample_limit=sample_limit,
        report_path=actual_report_path,
        min_row_id=start_row_id,
        max_row_id=end_row_id,
        origins=["drain"],
    )
    return {
        "success": True,
        "phase": "complete",
        "preflight": preflight,
        "session": {
            "minutes": minutes,
            "capture_started_at": capture_started_at,
            "capture_finished_at": capture_finished_at,
            "drain_name": drain_name,
            "drain_id": drain_id,
            "project_id": resolved_project_id,
            "shared_secret": shared_secret,
            "receiver_url": receiver_startup["listening"],
            "public_tunnel_url": tunnel_result["public_url"] if tunnel_result else None,
            "tunnel_provider": tunnel_result["provider"] if tunnel_result else None,
            "rows_start": start_row_id,
            "rows_end": end_row_id,
        },
        "cleanup": cleanup,
        "analysis": analysis,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Vercel observability helper")
    parser.add_argument(
        "--base-dir",
        default=str(DEFAULT_STATE_DIR),
        help="Workspace-local state directory (default: .hermes/observability)",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("preflight", help="Inspect Vercel project linkage and CLI state")

    collect = subparsers.add_parser("collect-runtime", help="Collect recent runtime logs via vercel logs")
    collect.add_argument("--since", default="30m")
    collect.add_argument("--until")
    collect.add_argument("--project")
    collect.add_argument("--environment")
    collect.add_argument("--level")
    collect.add_argument("--source", action="append")
    collect.add_argument("--limit", type=int, default=100)
    collect.add_argument("--search")
    collect.add_argument("--request-id")
    collect.add_argument("--status-code")

    serve = subparsers.add_parser("serve", help="Start a local HTTP receiver for drain traffic")
    serve.add_argument("--bind", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=4319)
    serve.add_argument("--secret")

    ensure = subparsers.add_parser("ensure-drain", help="Create, update, or reuse a Vercel drain")
    ensure.add_argument("--name", default="hermes-observability")
    ensure.add_argument("--target-url", required=True)
    ensure.add_argument("--project-id")
    ensure.add_argument("--scope")
    ensure.add_argument("--source", action="append")
    ensure.add_argument("--header", action="append")
    ensure.add_argument("--secret")
    ensure.add_argument("--delivery-format", default="json")
    ensure.add_argument("--no-update-existing", action="store_true")

    delete = subparsers.add_parser("delete-drain", help="Delete a drain by id")
    delete.add_argument("--drain-id", required=True)
    delete.add_argument("--scope")

    analyze = subparsers.add_parser("analyze", help="Analyze stored logs and optionally write a report")
    analyze.add_argument("--since", default="30m")
    analyze.add_argument("--until")
    analyze.add_argument("--environment")
    analyze.add_argument("--limit", type=int)
    analyze.add_argument("--sample-limit", type=int, default=20)
    analyze.add_argument("--report-path")

    live = subparsers.add_parser(
        "live-session",
        help="Run a full live capture session: receiver, tunnel, drain, timed collection, cleanup, analysis",
    )
    live.add_argument("--minutes", type=float, required=True)
    live.add_argument("--bind", default="127.0.0.1")
    live.add_argument("--port", type=int, default=4319)
    live.add_argument("--secret")
    live.add_argument("--name-prefix", default="hermes-observability-live")
    live.add_argument("--project-id")
    live.add_argument("--scope")
    live.add_argument("--source", action="append")
    live.add_argument("--header", action="append")
    live.add_argument("--delivery-format", default="json")
    live.add_argument("--tunnel", choices=["auto", "cloudflared", "ngrok"], default="auto")
    live.add_argument("--tunnel-timeout", type=float, default=30.0)
    live.add_argument("--environment")
    live.add_argument("--limit", type=int)
    live.add_argument("--sample-limit", type=int, default=20)
    live.add_argument("--report-path")

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    cwd = Path.cwd()
    base_dir = Path(args.base_dir).resolve()

    if args.command == "preflight":
        return emit(run_preflight(cwd))

    if args.command == "collect-runtime":
        return emit(
            collect_runtime_logs(
                cwd=cwd,
                base_dir=base_dir,
                since=args.since,
                until=args.until,
                project=args.project,
                environment=args.environment,
                level=args.level,
                source=args.source,
                limit=args.limit,
                search=args.search,
                request_id=args.request_id,
                status_code=args.status_code,
            ),
            exit_code=0,
        )

    if args.command == "serve":
        return serve_receiver(base_dir=base_dir, bind=args.bind, port=args.port, secret=args.secret)

    if args.command == "ensure-drain":
        return emit(
            ensure_drain(
                cwd=cwd,
                base_dir=base_dir,
                name=args.name,
                target_url=args.target_url,
                project_id=args.project_id,
                scope=args.scope,
                sources=args.source,
                headers=parse_header_pairs(args.header),
                secret=args.secret,
                delivery_format=args.delivery_format,
                update_existing=not args.no_update_existing,
            )
        )

    if args.command == "delete-drain":
        return emit(delete_drain(cwd=cwd, base_dir=base_dir, drain_id=args.drain_id, scope=args.scope))

    if args.command == "analyze":
        report_path = Path(args.report_path).resolve() if args.report_path else None
        return emit(
            analyze_database(
                cwd=cwd,
                base_dir=base_dir,
                since=args.since,
                until=args.until,
                environment=args.environment,
                limit=args.limit,
                sample_limit=args.sample_limit,
                report_path=report_path,
            )
        )

    if args.command == "live-session":
        report_path = Path(args.report_path).resolve() if args.report_path else None
        result = run_live_session(
            cwd=cwd,
            base_dir=base_dir,
            minutes=args.minutes,
            bind=args.bind,
            port=args.port,
            secret=args.secret,
            name_prefix=args.name_prefix,
            project_id=args.project_id,
            scope=args.scope,
            sources=args.source,
            headers=parse_header_pairs(args.header),
            delivery_format=args.delivery_format,
            tunnel=args.tunnel,
            tunnel_timeout=args.tunnel_timeout,
            environment=args.environment,
            limit=args.limit,
            sample_limit=args.sample_limit,
            report_path=report_path,
        )
        return emit(result, exit_code=0 if result.get("success") else 1)

    parser.error(f"Unknown command: {args.command}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
