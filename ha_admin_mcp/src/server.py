from __future__ import annotations

import fnmatch
import base64
import json
import os
import re
import shutil
import sqlite3
import subprocess
import time
import urllib.error
import urllib.request
import urllib.parse
import uuid
import glob
import hashlib
import socket
import struct
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

ADDON_OPTIONS = Path("/data/options.json")
APP_VERSION = "0.1.27"
CONFIG_ROOT = Path("/config")
DEFAULT_BACKUP_DIR = Path("/backup/ha-admin-mcp")
AUDIT_LOG = DEFAULT_BACKUP_DIR / "audit.log"
MAX_READ_BYTES = 20_000_000
SUPPORTED_PROTOCOL_VERSIONS = {"2025-06-18", "2025-03-26", "2024-11-05"}
S6_ENV_DIR = Path("/run/s6/container_environment")
MCP_PATH = "/api/mcp"
LOG_LEVEL = "info"
DANGEROUS_PATHS = {"/", "/config", "/backup", "/data", "/share", "/ssl", "/addons", "/usr", "/bin", "/sbin", "/etc", "/root", "/var"}
READ_ONLY_HINTS = ("get", "list", "read", "search", "hash", "stat", "tail", "check", "render", "overview", "summary")
DESTRUCTIVE_HINTS = ("delete", "remove", "restart", "stop", "write", "patch", "set", "save", "run", "shell", "control", "call", "fire", "manage")
LOVELACE_STORAGE_EDIT_WARNING = (
    "Reminder: storage-backed Lovelace edits are not the preferred path for UI changes. "
    "Use live_lovelace_get_config/live_lovelace_save_config or the Home Assistant UI path when changing dashboards, "
    "then verify the rendered UI."
)
TEXT_EXTENSIONS = {
    ".conf",
    ".css",
    ".csv",
    ".env",
    ".html",
    ".ini",
    ".js",
    ".json",
    ".log",
    ".md",
    ".py",
    ".sh",
    ".sql",
    ".txt",
    ".yaml",
    ".yml",
}


def load_options() -> dict[str, Any]:
    if ADDON_OPTIONS.exists():
        return json.loads(ADDON_OPTIONS.read_text())
    return {
        "admin_token": os.environ.get("ADMIN_TOKEN", ""),
        "bind_host": os.environ.get("BIND_HOST", "0.0.0.0"),
        "port": int(os.environ.get("PORT", "8124")),
        "command_timeout_seconds": int(os.environ.get("COMMAND_TIMEOUT_SECONDS", "300")),
    }


OPTIONS = load_options()


def get_supervisor_token() -> str:
    for name in ("SUPERVISOR_TOKEN", "HASSIO_TOKEN"):
        token = os.environ.get(name)
        if token:
            return token.strip()
        token_file = S6_ENV_DIR / name
        if token_file.exists():
            value = token_file.read_text().strip()
            if value:
                return value
    raise RuntimeError("SUPERVISOR_TOKEN/HASSIO_TOKEN is not available")


def text_result(value: Any) -> dict[str, Any]:
    text = value if isinstance(value, str) else json.dumps(value, indent=2, default=str)
    return {"content": [{"type": "text", "text": text}]}


def image_result(data: bytes, mime_type: str = "image/png") -> dict[str, Any]:
    return {
        "content": [
            {
                "type": "image",
                "mimeType": mime_type,
                "data": base64.b64encode(data).decode(),
            }
        ]
    }


def path_info(path: Path) -> dict[str, Any]:
    stat = path.lstat()
    return {
        "path": str(path),
        "exists": path.exists(),
        "is_file": path.is_file(),
        "is_dir": path.is_dir(),
        "is_symlink": path.is_symlink(),
        "size": stat.st_size,
        "mode": oct(stat.st_mode),
        "uid": stat.st_uid,
        "gid": stat.st_gid,
        "modified": stat.st_mtime,
    }


def read_limited(path: Path, max_bytes: int = MAX_READ_BYTES) -> tuple[str, bool]:
    data = path.read_bytes()
    truncated = len(data) > max_bytes
    if truncated:
        data = data[:max_bytes]
    return data.decode("utf-8", errors="replace"), truncated


def read_bytes_limited(path: Path, max_bytes: int = MAX_READ_BYTES) -> tuple[bytes, bool]:
    data = path.read_bytes()
    truncated = len(data) > max_bytes
    if truncated:
        data = data[:max_bytes]
    return data, truncated


def supervisor_request(method: str, endpoint: str, data: Any | None = None) -> Any:
    token = get_supervisor_token()
    endpoint = "/" + endpoint.lstrip("/")
    body = None if data is None else json.dumps(data).encode()
    request = urllib.request.Request(
        f"http://supervisor{endpoint}",
        data=body,
        method=method.upper(),
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=120) as response:
            payload = response.read().decode()
            if not payload:
                return {"status": response.status}
            try:
                return json.loads(payload)
            except json.JSONDecodeError:
                return {"status": response.status, "content": payload}
    except urllib.error.HTTPError as err:
        payload = err.read().decode(errors="replace")
        raise RuntimeError(f"Supervisor API {err.code}: {payload}") from err


def maybe_query(endpoint: str, query: dict[str, Any]) -> str:
    clean = {key: value for key, value in query.items() if value not in (None, "")}
    if not clean:
        return endpoint
    separator = "&" if "?" in endpoint else "?"
    return endpoint + separator + urllib.parse.urlencode(clean)


def ha_request(method: str, endpoint: str, data: Any | None = None) -> Any:
    token = get_supervisor_token()
    endpoint = "/" + endpoint.lstrip("/")
    body = None if data is None else json.dumps(data).encode()
    request = urllib.request.Request(
        f"http://supervisor/core/api{endpoint}",
        data=body,
        method=method.upper(),
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=120) as response:
            payload = response.read().decode()
            if not payload:
                return {"status": response.status}
            try:
                return json.loads(payload)
            except json.JSONDecodeError:
                return {"status": response.status, "content": payload}
    except urllib.error.HTTPError as err:
        payload = err.read().decode(errors="replace")
        raise RuntimeError(f"Home Assistant API {err.code}: {payload}") from err


def ws_read_exact(sock: socket.socket, size: int) -> bytes:
    chunks = []
    remaining = size
    while remaining > 0:
        chunk = sock.recv(remaining)
        if not chunk:
            raise RuntimeError("WebSocket closed unexpectedly")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def ws_send_text(sock: socket.socket, message: dict[str, Any]) -> None:
    payload = json.dumps(message, default=str).encode()
    header = bytearray([0x81])
    length = len(payload)
    if length < 126:
        header.append(0x80 | length)
    elif length < 65536:
        header.append(0x80 | 126)
        header.extend(struct.pack("!H", length))
    else:
        header.append(0x80 | 127)
        header.extend(struct.pack("!Q", length))
    mask = os.urandom(4)
    header.extend(mask)
    masked = bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload))
    sock.sendall(bytes(header) + masked)


def ws_recv_text(sock: socket.socket) -> dict[str, Any]:
    while True:
        first, second = ws_read_exact(sock, 2)
        opcode = first & 0x0F
        masked = bool(second & 0x80)
        length = second & 0x7F
        if length == 126:
            length = struct.unpack("!H", ws_read_exact(sock, 2))[0]
        elif length == 127:
            length = struct.unpack("!Q", ws_read_exact(sock, 8))[0]
        mask = ws_read_exact(sock, 4) if masked else b""
        payload = ws_read_exact(sock, length)
        if masked:
            payload = bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload))
        if opcode == 0x8:
            raise RuntimeError("WebSocket closed")
        if opcode == 0x9:
            continue
        if opcode == 0x1:
            return json.loads(payload.decode("utf-8"))


def ha_ws_call(message: dict[str, Any], timeout: int = 30) -> dict[str, Any]:
    token = get_supervisor_token()
    key = base64.b64encode(os.urandom(16)).decode()
    request = (
        "GET /core/websocket HTTP/1.1\r\n"
        "Host: supervisor\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        "Sec-WebSocket-Version: 13\r\n\r\n"
    ).encode()
    with socket.create_connection(("supervisor", 80), timeout=timeout) as sock:
        sock.settimeout(timeout)
        sock.sendall(request)
        response = b""
        while b"\r\n\r\n" not in response:
            response += sock.recv(4096)
            if len(response) > 20000:
                raise RuntimeError("WebSocket handshake response too large")
        header = response.split(b"\r\n\r\n", 1)[0].decode(errors="replace")
        if " 101 " not in header.splitlines()[0]:
            raise RuntimeError(f"WebSocket handshake failed: {header}")
        auth_required = ws_recv_text(sock)
        if auth_required.get("type") != "auth_required":
            raise RuntimeError(f"Unexpected WebSocket auth message: {auth_required}")
        ws_send_text(sock, {"type": "auth", "access_token": token})
        auth_ok = ws_recv_text(sock)
        if auth_ok.get("type") != "auth_ok":
            raise RuntimeError(f"WebSocket auth failed: {auth_ok}")
        command = dict(message)
        command.setdefault("id", 1)
        ws_send_text(sock, command)
        while True:
            response_msg = ws_recv_text(sock)
            if response_msg.get("id") == command["id"]:
                return response_msg


def http_request(args: dict[str, Any]) -> dict[str, Any]:
    method = str(args.get("method") or ("POST" if args.get("data") is not None or args.get("text") is not None else "GET")).upper()
    headers = {str(key): str(value) for key, value in (args.get("headers") or {}).items()}
    body = None
    if args.get("text") is not None:
        body = str(args["text"]).encode()
    elif args.get("data") is not None:
        body = json.dumps(args["data"]).encode()
        headers.setdefault("Content-Type", "application/json")
    request = urllib.request.Request(args["url"], data=body, method=method, headers=headers)
    timeout = int(args.get("timeout") or 120)
    max_bytes = int(args.get("max_bytes") or 2_000_000)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            data = response.read(max_bytes + 1)
            truncated = len(data) > max_bytes
            if truncated:
                data = data[:max_bytes]
            text = data.decode("utf-8", errors="replace")
            return {
                "url": args["url"],
                "status": response.status,
                "headers": dict(response.headers.items()),
                "content": text,
                "truncated": truncated,
            }
    except urllib.error.HTTPError as err:
        data = err.read(max_bytes + 1)
        truncated = len(data) > max_bytes
        if truncated:
            data = data[:max_bytes]
        return {
            "url": args["url"],
            "status": err.code,
            "headers": dict(err.headers.items()),
            "content": data.decode("utf-8", errors="replace"),
            "truncated": truncated,
        }


def tool_annotations(name: str) -> dict[str, Any]:
    lowered = name.lower()
    read_only = lowered.startswith(READ_ONLY_HINTS) or any(lowered.startswith(f"ha_{hint}") for hint in READ_ONLY_HINTS)
    destructive = any(hint in lowered for hint in DESTRUCTIVE_HINTS)
    if read_only and not destructive:
        return {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True}
    return {"readOnlyHint": False, "destructiveHint": destructive, "idempotentHint": False}


def audit_event(action: str, details: dict[str, Any]) -> None:
    try:
        DEFAULT_BACKUP_DIR.mkdir(parents=True, exist_ok=True)
        row = {"time": datetime.now(timezone.utc).isoformat(), "action": action, "details": details}
        with AUDIT_LOG.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(row, default=str) + "\n")
    except Exception as err:
        print(f"[ha-admin-mcp] audit log failed: {err}", flush=True)


def path_hash(path: Path) -> str | None:
    if not path.exists() or not path.is_file():
        return None
    return hash_file(path, "sha256")["hexdigest"]


def require_expected_hash(path: Path, expected_hash: str | None) -> None:
    if not expected_hash:
        return
    actual = path_hash(path)
    if actual != expected_hash:
        raise ValueError(f"expected_hash mismatch for {path}: expected {expected_hash}, actual {actual}")


def is_dangerous_path(path: Path) -> bool:
    try:
        resolved = str(path.resolve())
    except OSError:
        resolved = str(path.absolute())
    normalized = resolved.replace("\\", "/").rstrip("/") or "/"
    return normalized in DANGEROUS_PATHS


def require_force_for_path(path: Path, args: dict[str, Any], operation: str) -> None:
    if (is_dangerous_path(path) or (path.is_dir() and args.get("recursive"))) and not bool(args.get("force")):
        raise ValueError(f"{operation} on {path} requires force=true")


def tool_schema(name: str, description: str, properties: dict[str, Any], required: list[str] | None = None) -> dict[str, Any]:
    return {
        "name": name,
        "description": description,
        "annotations": tool_annotations(name),
        "inputSchema": {
            "type": "object",
            "properties": properties,
            "required": required or [],
        },
    }


TOOLS = [
    tool_schema(
        "run_command",
        "Run an arbitrary shell command with the app's privileged access",
        {
            "command": {"type": "string"},
            "cwd": {"type": "string"},
            "timeout": {"type": "integer", "minimum": 1, "maximum": 3600},
            "max_output_bytes": {"type": "integer", "minimum": 1000, "maximum": 1000000},
        },
        ["command"],
    ),
    tool_schema(
        "run_shell",
        "Run an arbitrary shell command with an explicit shell executable",
        {
            "command": {"type": "string"},
            "shell": {"type": "string"},
            "cwd": {"type": "string"},
            "timeout": {"type": "integer", "minimum": 1, "maximum": 3600},
            "max_output_bytes": {"type": "integer", "minimum": 1000, "maximum": 1000000},
        },
        ["command"],
    ),
    tool_schema(
        "get_environment",
        "Return selected process and s6 environment values, redacting token contents",
        {"include_values": {"type": "boolean"}},
        [],
    ),
    tool_schema("get_target_identity", "Return the HA target identity this MCP app is controlling", {}, []),
    tool_schema("get_version", "Compatibility tool: return Home Assistant Core version", {}, []),
    tool_schema(
        "search_tools",
        "Search this MCP server's tool catalog by name, description, or schema",
        {"query": {"type": "string"}, "limit": {"type": "integer", "minimum": 1, "maximum": 50}},
        ["query"],
    ),
    tool_schema(
        "batch_call_tools",
        "Call multiple MCP tools sequentially and return compact per-call results",
        {
            "calls": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {"name": {"type": "string"}, "arguments": {"type": "object"}},
                    "required": ["name"],
                },
            },
            "stop_on_error": {"type": "boolean"},
        },
        ["calls"],
    ),
    tool_schema("stat_path", "Return filesystem metadata for any visible path", {"path": {"type": "string"}}, ["path"]),
    tool_schema(
        "list_dir",
        "List a directory visible to the app",
        {"path": {"type": "string"}, "limit": {"type": "integer", "minimum": 1, "maximum": 10000}},
        ["path"],
    ),
    tool_schema(
        "read_file",
        "Read a file visible to the app",
        {"path": {"type": "string"}, "max_bytes": {"type": "integer", "minimum": 1, "maximum": 100000000}},
        ["path"],
    ),
    tool_schema(
        "read_file_window",
        "Read a byte window from a visible file so large files can be inspected without transport truncation",
        {"path": {"type": "string"}, "offset": {"type": "integer", "minimum": 0}, "length": {"type": "integer", "minimum": 1, "maximum": 10000000}},
        ["path"],
    ),
    tool_schema(
        "read_file_lines",
        "Read a line-numbered window from a visible text file",
        {"path": {"type": "string"}, "start_line": {"type": "integer", "minimum": 1}, "line_count": {"type": "integer", "minimum": 1, "maximum": 10000}},
        ["path"],
    ),
    tool_schema(
        "read_file_base64",
        "Read any visible file as base64 for binary-safe transfer",
        {"path": {"type": "string"}, "max_bytes": {"type": "integer", "minimum": 1, "maximum": 100000000}},
        ["path"],
    ),
    tool_schema(
        "write_file_base64",
        "Write a visible file from base64 content, creating parent directories if needed",
        {"path": {"type": "string"}, "content_base64": {"type": "string"}, "mode": {"type": "string"}, "dry_run": {"type": "boolean"}, "expected_hash": {"type": "string"}},
        ["path", "content_base64"],
    ),
    tool_schema(
        "write_file",
        "Write a file visible to the app, creating parent directories if needed",
        {"path": {"type": "string"}, "content": {"type": "string"}, "mode": {"type": "string"}, "dry_run": {"type": "boolean"}, "expected_hash": {"type": "string"}},
        ["path", "content"],
    ),
    tool_schema(
        "delete_path",
        "Delete any visible file or directory",
        {"path": {"type": "string"}, "recursive": {"type": "boolean"}, "force": {"type": "boolean"}, "dry_run": {"type": "boolean"}},
        ["path"],
    ),
    tool_schema(
        "search_files",
        "Search filenames and text file contents under any visible directory",
        {
            "path": {"type": "string"},
            "query": {"type": "string"},
            "filename": {"type": "string"},
            "recursive": {"type": "boolean"},
            "limit": {"type": "integer", "minimum": 1, "maximum": 10000},
            "max_file_bytes": {"type": "integer", "minimum": 1, "maximum": 100000000},
        },
        ["path"],
    ),
    tool_schema(
        "glob_paths",
        "Expand filesystem glob patterns visible to the app",
        {"pattern": {"type": "string"}, "limit": {"type": "integer", "minimum": 1, "maximum": 10000}},
        ["pattern"],
    ),
    tool_schema(
        "hash_file",
        "Return cryptographic hashes for a visible file",
        {"path": {"type": "string"}, "algorithm": {"type": "string"}},
        ["path"],
    ),
    tool_schema(
        "ha_api",
        "Call the Home Assistant REST API through the Supervisor token",
        {"method": {"type": "string"}, "endpoint": {"type": "string"}, "data": {"type": "object"}},
        ["endpoint"],
    ),
    tool_schema(
        "ha_ws_call",
        "Call the Home Assistant WebSocket API through the Supervisor token",
        {"message": {"type": "object"}, "timeout": {"type": "integer", "minimum": 1, "maximum": 120}},
        ["message"],
    ),
    tool_schema(
        "supervisor_api",
        "Call the Home Assistant Supervisor API",
        {"method": {"type": "string"}, "endpoint": {"type": "string"}, "data": {"type": "object"}},
        ["endpoint"],
    ),
    tool_schema(
        "http_request",
        "Make an arbitrary HTTP request from inside the HA app container",
        {
            "method": {"type": "string"},
            "url": {"type": "string"},
            "headers": {"type": "object"},
            "data": {"type": "object"},
            "text": {"type": "string"},
            "timeout": {"type": "integer", "minimum": 1, "maximum": 300},
            "max_bytes": {"type": "integer", "minimum": 1, "maximum": 100000000},
        },
        ["url"],
    ),
    tool_schema("check_config", "Run Home Assistant Core config check through Supervisor", {}, []),
    tool_schema(
        "ha_cli",
        "Run common Home Assistant CLI-style actions through Supervisor/API calls, falling back to a local ha binary if present",
        {"args": {"type": "array", "items": {"type": "string"}}, "timeout": {"type": "integer", "minimum": 1, "maximum": 3600}, "max_output_bytes": {"type": "integer", "minimum": 1000, "maximum": 1000000}},
        ["args"],
    ),
    tool_schema("core_info", "Return Home Assistant Core info through Supervisor", {}, []),
    tool_schema("host_info", "Return Home Assistant host info through Supervisor", {}, []),
    tool_schema("supervisor_info", "Return Supervisor info", {}, []),
    tool_schema("store_info", "Return Supervisor store/repository info", {}, []),
    tool_schema(
        "app_info",
        "Return Supervisor app/add-on info for a slug",
        {"slug": {"type": "string"}},
        ["slug"],
    ),
    tool_schema(
        "app_logs",
        "Return Supervisor app/add-on logs for a slug",
        {"slug": {"type": "string"}},
        ["slug"],
    ),
    tool_schema(
        "app_control",
        "Start, stop, restart, rebuild, update, install, or uninstall a Supervisor app/add-on by slug",
        {
            "slug": {"type": "string"},
            "action": {"type": "string", "enum": ["start", "stop", "restart", "rebuild", "update", "install", "uninstall"]},
        },
        ["slug", "action"],
    ),
    tool_schema("restart_core", "Restart Home Assistant Core through Supervisor", {"force": {"type": "boolean"}}, []),
    tool_schema("stop_core", "Stop Home Assistant Core through Supervisor", {"force": {"type": "boolean"}}, []),
    tool_schema("start_core", "Start Home Assistant Core through Supervisor", {}, []),
    tool_schema("reload_core_config", "Reload Home Assistant core config through REST API", {}, []),
    tool_schema(
        "check_reload_readiness",
        "Run a config check and report common reload/restart options available through services",
        {},
        [],
    ),
    tool_schema(
        "check_config_and_reload",
        "Run config check, then reload selected domains/services if the check passes",
        {
            "domains": {"type": "array", "items": {"type": "string"}},
            "services": {"type": "array", "items": {"type": "object"}},
            "reload_core": {"type": "boolean"},
            "dry_run": {"type": "boolean"},
        },
        [],
    ),
    tool_schema(
        "reload_domain_config",
        "Reload a Home Assistant integration domain through /api/services/<domain>/reload when available",
        {"domain": {"type": "string"}, "data": {"type": "object"}},
        ["domain"],
    ),
    tool_schema(
        "call_service",
        "Call any Home Assistant service",
        {"domain": {"type": "string"}, "service": {"type": "string"}, "data": {"type": "object"}},
        ["domain", "service"],
    ),
    tool_schema(
        "get_states",
        "Return all Home Assistant states or one entity state",
        {"entity_id": {"type": "string"}},
        [],
    ),
    tool_schema(
        "get_entity",
        "Compatibility tool: get one entity with optional field projection",
        {"entity_id": {"type": "string"}, "fields": {"type": "array", "items": {"type": "string"}}, "detailed": {"type": "boolean"}},
        ["entity_id"],
    ),
    tool_schema(
        "entity_action",
        "Compatibility tool: turn an entity on, off, or toggle it",
        {"entity_id": {"type": "string"}, "action": {"type": "string", "enum": ["on", "off", "toggle"]}, "params": {"type": "object"}},
        ["entity_id", "action"],
    ),
    tool_schema(
        "list_entities",
        "Compatibility tool: list entities with optional domain, area, state, query, and projection filters",
        {
            "domain": {"type": "string"},
            "area": {"type": "string"},
            "state": {"type": "string"},
            "query": {"type": "string"},
            "fields": {"type": "array", "items": {"type": "string"}},
            "detailed": {"type": "boolean"},
            "limit": {"type": "integer", "minimum": 1, "maximum": 10000},
            "offset": {"type": "integer", "minimum": 0},
        },
        [],
    ),
    tool_schema(
        "search_entities",
        "Compatibility tool: text search entities across state, attributes, registry, and area",
        {"query": {"type": "string"}, "limit": {"type": "integer", "minimum": 1, "maximum": 10000}},
        ["query"],
    ),
    tool_schema(
        "get_entities_by_area",
        "Compatibility tool: list entities assigned to an area name or id",
        {"area": {"type": "string"}, "limit": {"type": "integer", "minimum": 1, "maximum": 10000}},
        ["area"],
    ),
    tool_schema(
        "domain_summary",
        "Compatibility tool: summarize one HA domain with counts, states, and examples",
        {"domain": {"type": "string"}, "example_limit": {"type": "integer", "minimum": 1, "maximum": 20}},
        ["domain"],
    ),
    tool_schema("system_overview", "Compatibility tool: compact overview of entities/domains/areas/system version", {}, []),
    tool_schema(
        "diagnostic_bundle",
        "Return a compact HA operator bundle: identity, config check, reload readiness, errors, updates, and optional entity/dashboard context",
        {
            "entity_id": {"type": "string"},
            "dashboard_id": {"type": "string"},
            "dashboard_url_path": {"type": "string"},
            "log_lines": {"type": "integer", "minimum": 1, "maximum": 1000},
        },
        [],
    ),
    tool_schema("list_automations", "Compatibility tool: list automation entities", {}, []),
    tool_schema("list_automation_configs", "List automation entities compactly with config ids and source hints", {"query": {"type": "string"}, "limit": {"type": "integer", "minimum": 1, "maximum": 10000}}, []),
    tool_schema("get_automation_config", "Get compact automation config/source context by entity_id, id, or query", {"entity_id": {"type": "string"}, "id": {"type": "string"}, "query": {"type": "string"}, "context_lines": {"type": "integer", "minimum": 1, "maximum": 200}}, []),
    tool_schema("list_script_configs", "List script entities compactly with config ids and source hints", {"query": {"type": "string"}, "limit": {"type": "integer", "minimum": 1, "maximum": 10000}}, []),
    tool_schema("get_script_config", "Get compact script config/source context by entity_id, id, or query", {"entity_id": {"type": "string"}, "id": {"type": "string"}, "query": {"type": "string"}, "context_lines": {"type": "integer", "minimum": 1, "maximum": 200}}, []),
    tool_schema("list_scene_configs", "List scene entities compactly with config ids and source hints", {"query": {"type": "string"}, "limit": {"type": "integer", "minimum": 1, "maximum": 10000}}, []),
    tool_schema("get_scene_config", "Get compact scene config/source context by entity_id, id, or query", {"entity_id": {"type": "string"}, "id": {"type": "string"}, "query": {"type": "string"}, "context_lines": {"type": "integer", "minimum": 1, "maximum": 200}}, []),
    tool_schema(
        "get_events",
        "Return Home Assistant event names",
        {},
        [],
    ),
    tool_schema(
        "get_services",
        "Return Home Assistant service descriptions",
        {},
        [],
    ),
    tool_schema(
        "get_history",
        "Return Home Assistant history for optional entity ids",
        {
            "timestamp": {"type": "string"},
            "filter_entity_id": {"type": "string"},
            "minimal_response": {"type": "boolean"},
            "no_attributes": {"type": "boolean"},
            "significant_changes_only": {"type": "boolean"},
        },
        [],
    ),
    tool_schema(
        "get_history_range",
        "Compatibility tool: get raw state-change history for one entity over an explicit time window",
        {"entity_id": {"type": "string"}, "start_time": {"type": "string"}, "end_time": {"type": "string"}},
        ["entity_id", "start_time"],
    ),
    tool_schema(
        "get_statistics",
        "Compatibility tool: get recorder long-term statistics for the last N hours",
        {"entity_id": {"type": "string"}, "hours": {"type": "integer", "minimum": 1, "maximum": 100000}, "period": {"type": "string"}},
        ["entity_id"],
    ),
    tool_schema(
        "get_statistics_range",
        "Compatibility tool: get recorder long-term statistics for one entity over a time window",
        {"entity_id": {"type": "string"}, "start_time": {"type": "string"}, "end_time": {"type": "string"}, "period": {"type": "string"}},
        ["entity_id", "start_time"],
    ),
    tool_schema(
        "get_error_log",
        "Compatibility tool: get/filter Home Assistant error log with counts",
        {
            "level": {"type": "string"},
            "integration": {"type": "string"},
            "search_term": {"type": "string"},
            "lines": {"type": "integer", "minimum": 1, "maximum": 100000},
        },
        [],
    ),
    tool_schema(
        "render_template",
        "Render a Home Assistant template",
        {"template": {"type": "string"}},
        ["template"],
    ),
    tool_schema(
        "fire_event",
        "Fire a Home Assistant event",
        {"event_type": {"type": "string"}, "event_data": {"type": "object"}},
        ["event_type"],
    ),
    tool_schema(
        "backup_path",
        "Copy a visible file or directory into /backup/ha-admin-mcp",
        {"path": {"type": "string"}, "label": {"type": "string"}},
        ["path"],
    ),
    tool_schema(
        "list_config_files",
        "List files under /config with optional recursion and pattern filtering",
        {
            "path": {"type": "string"},
            "pattern": {"type": "string"},
            "recursive": {"type": "boolean"},
            "limit": {"type": "integer", "minimum": 1, "maximum": 10000},
        },
        [],
    ),
    tool_schema(
        "read_config_file",
        "Read a file under /config by relative path",
        {"path": {"type": "string"}, "max_bytes": {"type": "integer", "minimum": 1, "maximum": 100000000}},
        ["path"],
    ),
    tool_schema(
        "read_config_lines",
        "Read a line-numbered window from a /config text file",
        {"path": {"type": "string"}, "start_line": {"type": "integer", "minimum": 1}, "line_count": {"type": "integer", "minimum": 1, "maximum": 10000}},
        ["path"],
    ),
    tool_schema(
        "write_config_file",
        "Write a text file under /config, optionally backing up to /backup/ha-admin-mcp and running config check",
        {
            "path": {"type": "string"},
            "content": {"type": "string"},
            "mode": {"type": "string"},
            "backup": {"type": "boolean"},
            "check_config": {"type": "boolean"},
            "dry_run": {"type": "boolean"},
            "expected_hash": {"type": "string"},
        },
        ["path", "content"],
    ),
    tool_schema(
        "search_config",
        "Search filenames and text contents under /config with compact results",
        {
            "path": {"type": "string"},
            "query": {"type": "string"},
            "filename": {"type": "string"},
            "recursive": {"type": "boolean"},
            "limit": {"type": "integer", "minimum": 1, "maximum": 10000},
            "max_file_bytes": {"type": "integer", "minimum": 1, "maximum": 100000000},
        },
        [],
    ),
    tool_schema(
        "patch_config_text",
        "Guarded text or regex replacement in a /config file, with dry-run, backup, expected_hash, and optional config check",
        {
            "path": {"type": "string"},
            "search": {"type": "string"},
            "replace": {"type": "string"},
            "regex": {"type": "boolean"},
            "count": {"type": "integer", "minimum": 0},
            "expected_count": {"type": "integer", "minimum": 0},
            "backup": {"type": "boolean"},
            "label": {"type": "string"},
            "dry_run": {"type": "boolean"},
            "expected_hash": {"type": "string"},
            "check_config": {"type": "boolean"},
        },
        ["path", "search", "replace"],
    ),
    tool_schema(
        "ensure_config_block",
        "Create, replace, or remove a marked text block in a /config file",
        {
            "path": {"type": "string"},
            "name": {"type": "string"},
            "content": {"type": "string"},
            "remove": {"type": "boolean"},
            "backup": {"type": "boolean"},
            "label": {"type": "string"},
            "dry_run": {"type": "boolean"},
            "expected_hash": {"type": "string"},
            "check_config": {"type": "boolean"},
        },
        ["path", "name"],
    ),
    tool_schema("list_packages", "List YAML package files under /config/packages", {"recursive": {"type": "boolean"}}, []),
    tool_schema(
        "read_package",
        "Read one package file under /config/packages",
        {"path": {"type": "string"}, "max_bytes": {"type": "integer", "minimum": 1, "maximum": 100000000}},
        ["path"],
    ),
    tool_schema(
        "write_package",
        "Write one package file under /config/packages with backup, dry-run, expected_hash, and optional config check",
        {"path": {"type": "string"}, "content": {"type": "string"}, "backup": {"type": "boolean"}, "dry_run": {"type": "boolean"}, "expected_hash": {"type": "string"}, "check_config": {"type": "boolean"}},
        ["path", "content"],
    ),
    tool_schema(
        "patch_package_text",
        "Guarded text or regex replacement in one /config/packages file",
        {
            "path": {"type": "string"},
            "search": {"type": "string"},
            "replace": {"type": "string"},
            "regex": {"type": "boolean"},
            "count": {"type": "integer", "minimum": 0},
            "expected_count": {"type": "integer", "minimum": 0},
            "backup": {"type": "boolean"},
            "dry_run": {"type": "boolean"},
            "expected_hash": {"type": "string"},
            "check_config": {"type": "boolean"},
        },
        ["path", "search", "replace"],
    ),
    tool_schema("list_secrets", "List top-level secret names from /config/secrets.yaml without returning values", {}, []),
    tool_schema("get_secret", "Read one top-level secret value from /config/secrets.yaml", {"name": {"type": "string"}}, ["name"]),
    tool_schema(
        "set_secret",
        "Create or replace one top-level secret in /config/secrets.yaml",
        {"name": {"type": "string"}, "value": {"type": "string"}, "backup": {"type": "boolean"}, "dry_run": {"type": "boolean"}, "expected_hash": {"type": "string"}},
        ["name", "value"],
    ),
    tool_schema(
        "delete_secret",
        "Delete one top-level secret from /config/secrets.yaml",
        {"name": {"type": "string"}, "backup": {"type": "boolean"}, "dry_run": {"type": "boolean"}, "expected_hash": {"type": "string"}, "force": {"type": "boolean"}},
        ["name"],
    ),
    tool_schema(
        "tail_log",
        "Return the last lines of a log file, defaulting to /config/home-assistant.log",
        {
            "path": {"type": "string"},
            "lines": {"type": "integer", "minimum": 1, "maximum": 5000},
            "max_bytes": {"type": "integer", "minimum": 1000, "maximum": 100000000},
        },
        [],
    ),
    tool_schema("list_storage_keys", "List Home Assistant .storage keys", {"include_backups": {"type": "boolean"}}, []),
    tool_schema(
        "list_storage_keys_filtered",
        "List Home Assistant .storage keys with pattern, text query, size, and limit filters",
        {
            "pattern": {"type": "string"},
            "query": {"type": "string"},
            "min_size": {"type": "integer", "minimum": 0},
            "max_size": {"type": "integer", "minimum": 0},
            "include_backups": {"type": "boolean"},
            "limit": {"type": "integer", "minimum": 1, "maximum": 10000},
        },
        [],
    ),
    tool_schema(
        "read_storage_key",
        "Read a Home Assistant .storage JSON key",
        {"key": {"type": "string"}, "max_bytes": {"type": "integer", "minimum": 1, "maximum": 100000000}},
        ["key"],
    ),
    tool_schema(
        "read_storage_key_window",
        "Read a byte window from a Home Assistant .storage key",
        {"key": {"type": "string"}, "offset": {"type": "integer", "minimum": 0}, "length": {"type": "integer", "minimum": 1, "maximum": 10000000}},
        ["key"],
    ),
    tool_schema(
        "search_storage_key",
        "Search text inside a Home Assistant .storage key",
        {"key": {"type": "string"}, "query": {"type": "string"}, "limit": {"type": "integer", "minimum": 1, "maximum": 10000}},
        ["key", "query"],
    ),
    tool_schema(
        "search_storage_json",
        "Search parsed JSON inside a Home Assistant .storage key and return compact JSON paths",
        {
            "key": {"type": "string"},
            "query": {"type": "string"},
            "field": {"type": "string"},
            "limit": {"type": "integer", "minimum": 1, "maximum": 10000},
            "max_bytes": {"type": "integer", "minimum": 1, "maximum": 100000000},
        },
        ["key", "query"],
    ),
    tool_schema(
        "read_storage_json_path",
        "Read one JSON subpath inside a Home Assistant .storage key",
        {"key": {"type": "string"}, "path": {"type": "string"}},
        ["key", "path"],
    ),
    tool_schema(
        "read_storage_json_paths",
        "Read multiple JSON subpaths inside a Home Assistant .storage key in one call",
        {"key": {"type": "string"}, "paths": {"type": "array", "items": {"type": "string"}}},
        ["key", "paths"],
    ),
    tool_schema(
        "patch_storage_json_path",
        "Patch, replace, or remove keys from one JSON subpath inside a Home Assistant .storage key",
        {
            "key": {"type": "string"},
            "path": {"type": "string"},
            "patch": {"type": "object"},
            "replace": {},
            "remove_keys": {"type": "array", "items": {"type": "string"}},
            "backup": {"type": "boolean"},
            "label": {"type": "string"},
            "dry_run": {"type": "boolean"},
            "expected_hash": {"type": "string"},
        },
        ["key", "path"],
    ),
    tool_schema(
        "search_entity_registry",
        "Filter core.entity_registry without returning the whole registry",
        {
            "entity_id": {"type": "string"},
            "domain": {"type": "string"},
            "platform": {"type": "string"},
            "device_id": {"type": "string"},
            "area_id": {"type": "string"},
            "disabled_by": {"type": "string"},
            "hidden_by": {"type": "string"},
            "query": {"type": "string"},
            "limit": {"type": "integer", "minimum": 1, "maximum": 10000},
        },
        [],
    ),
    tool_schema(
        "get_entity_registry_entry",
        "Get one core.entity_registry entry by entity_id, unique_id, or id",
        {"entity_id": {"type": "string"}, "unique_id": {"type": "string"}, "id": {"type": "string"}},
        [],
    ),
    tool_schema(
        "search_device_registry",
        "Filter core.device_registry without returning the whole registry",
        {
            "id": {"type": "string"},
            "name": {"type": "string"},
            "manufacturer": {"type": "string"},
            "model": {"type": "string"},
            "area_id": {"type": "string"},
            "query": {"type": "string"},
            "limit": {"type": "integer", "minimum": 1, "maximum": 10000},
        },
        [],
    ),
    tool_schema(
        "search_config_entries",
        "Filter core.config_entries without returning the whole file",
        {
            "entry_id": {"type": "string"},
            "domain": {"type": "string"},
            "title": {"type": "string"},
            "source": {"type": "string"},
            "query": {"type": "string"},
            "limit": {"type": "integer", "minimum": 1, "maximum": 10000},
        },
        [],
    ),
    tool_schema(
        "search_area_registry",
        "Filter core.area_registry without returning the whole file",
        {"id": {"type": "string"}, "name": {"type": "string"}, "query": {"type": "string"}, "limit": {"type": "integer", "minimum": 1, "maximum": 10000}},
        [],
    ),
    tool_schema(
        "search_floor_registry",
        "Filter core.floor_registry without returning the whole file",
        {"id": {"type": "string"}, "name": {"type": "string"}, "query": {"type": "string"}, "limit": {"type": "integer", "minimum": 1, "maximum": 10000}},
        [],
    ),
    tool_schema(
        "search_label_registry",
        "Filter core.label_registry without returning the whole file",
        {"id": {"type": "string"}, "name": {"type": "string"}, "query": {"type": "string"}, "limit": {"type": "integer", "minimum": 1, "maximum": 10000}},
        [],
    ),
    tool_schema(
        "patch_entity_registry_entry",
        "Patch one core.entity_registry entry by entity_id, unique_id, or id",
        {
            "entity_id": {"type": "string"},
            "unique_id": {"type": "string"},
            "id": {"type": "string"},
            "patch": {"type": "object"},
            "remove_keys": {"type": "array", "items": {"type": "string"}},
            "backup": {"type": "boolean"},
            "dry_run": {"type": "boolean"},
            "expected_hash": {"type": "string"},
        },
        [],
    ),
    tool_schema(
        "patch_device_registry_entry",
        "Patch one core.device_registry entry by id or name",
        {
            "id": {"type": "string"},
            "name": {"type": "string"},
            "patch": {"type": "object"},
            "remove_keys": {"type": "array", "items": {"type": "string"}},
            "backup": {"type": "boolean"},
            "dry_run": {"type": "boolean"},
            "expected_hash": {"type": "string"},
        },
        [],
    ),
    tool_schema(
        "sqlite_query",
        "Run a read-only SQLite query, defaulting to Home Assistant recorder DB",
        {
            "path": {"type": "string"},
            "query": {"type": "string"},
            "parameters": {"type": "array"},
            "limit": {"type": "integer", "minimum": 1, "maximum": 10000},
            "timeout": {"type": "integer", "minimum": 1, "maximum": 300},
        },
        ["query"],
    ),
    tool_schema(
        "recorder_purge",
        "Call recorder.purge with keep_days/repack/apply_filter options",
        {"keep_days": {"type": "integer", "minimum": 0}, "repack": {"type": "boolean"}, "apply_filter": {"type": "boolean"}, "dry_run": {"type": "boolean"}},
        [],
    ),
    tool_schema(
        "recorder_purge_entities",
        "Call recorder.purge_entities for specific entities/domains/globs",
        {
            "entity_id": {"type": "array", "items": {"type": "string"}},
            "domains": {"type": "array", "items": {"type": "string"}},
            "entity_globs": {"type": "array", "items": {"type": "string"}},
            "keep_days": {"type": "integer", "minimum": 0},
            "dry_run": {"type": "boolean"},
        },
        [],
    ),
    tool_schema("recorder_get_db_info", "Return recorder database file size, tables, and key row counts", {}, []),
    tool_schema("list_backups", "List Home Assistant backups through Supervisor", {}, []),
    tool_schema(
        "create_backup",
        "Create a full or partial Home Assistant backup through Supervisor",
        {"name": {"type": "string"}, "password": {"type": "string"}, "folders": {"type": "array", "items": {"type": "string"}}, "addons": {"type": "array", "items": {"type": "string"}}, "homeassistant": {"type": "boolean"}},
        [],
    ),
    tool_schema("get_backup_info", "Return Supervisor metadata for one backup slug", {"slug": {"type": "string"}}, ["slug"]),
    tool_schema(
        "delete_backup",
        "Delete one Home Assistant backup by slug",
        {"slug": {"type": "string"}, "force": {"type": "boolean"}, "dry_run": {"type": "boolean"}},
        ["slug"],
    ),
    tool_schema(
        "restore_backup",
        "Restore one Home Assistant backup by slug; this is intentionally force-gated",
        {"slug": {"type": "string"}, "password": {"type": "string"}, "partial": {"type": "boolean"}, "folders": {"type": "array", "items": {"type": "string"}}, "addons": {"type": "array", "items": {"type": "string"}}, "homeassistant": {"type": "boolean"}, "force": {"type": "boolean"}, "dry_run": {"type": "boolean"}},
        ["slug"],
    ),
    tool_schema(
        "read_lovelace_dashboards",
        "List or read Lovelace dashboard storage files",
        {"include_content": {"type": "boolean"}, "max_bytes": {"type": "integer", "minimum": 1, "maximum": 100000000}},
        [],
    ),
    tool_schema(
        "live_lovelace_get_config",
        "Read the active Lovelace config through the Home Assistant WebSocket API",
        {"url_path": {"type": "string"}, "dashboard_id": {"type": "string"}},
        [],
    ),
    tool_schema(
        "live_lovelace_get_outline",
        "Read a compact active Lovelace dashboard outline through the Home Assistant WebSocket API",
        {"url_path": {"type": "string"}, "dashboard_id": {"type": "string"}, "include_entities": {"type": "boolean"}},
        [],
    ),
    tool_schema(
        "live_lovelace_find_cards",
        "Find cards in active Lovelace config through the Home Assistant WebSocket API",
        {"url_path": {"type": "string"}, "dashboard_id": {"type": "string"}, "view_index": {"type": "integer", "minimum": 0}, "view_title": {"type": "string"}, "path": {"type": "string"}, "query": {"type": "string"}, "entity": {"type": "string"}, "card_type": {"type": "string"}, "limit": {"type": "integer", "minimum": 1, "maximum": 10000}},
        [],
    ),
    tool_schema(
        "live_lovelace_get_card",
        "Read exactly one card from active Lovelace config through the Home Assistant WebSocket API",
        {"url_path": {"type": "string"}, "dashboard_id": {"type": "string"}, "view_index": {"type": "integer", "minimum": 0}, "view_title": {"type": "string"}, "path": {"type": "string"}, "query": {"type": "string"}, "entity": {"type": "string"}, "card_type": {"type": "string"}, "expected_matches": {"type": "integer", "minimum": 1, "maximum": 100}},
        [],
    ),
    tool_schema(
        "live_lovelace_patch_card",
        "Patch exactly one card and save through the Home Assistant WebSocket API instead of storage writes",
        {"url_path": {"type": "string"}, "dashboard_id": {"type": "string"}, "view_index": {"type": "integer", "minimum": 0}, "view_title": {"type": "string"}, "path": {"type": "string"}, "query": {"type": "string"}, "entity": {"type": "string"}, "card_type": {"type": "string"}, "patch": {"type": "object"}, "replace": {"type": "object"}, "remove_keys": {"type": "array", "items": {"type": "string"}}, "expected_matches": {"type": "integer", "minimum": 1, "maximum": 100}, "backup": {"type": "boolean"}, "dry_run": {"type": "boolean"}, "force": {"type": "boolean"}},
        [],
    ),
    tool_schema(
        "live_lovelace_save_config",
        "Save Lovelace config through the Home Assistant WebSocket API instead of storage writes",
        {"url_path": {"type": "string"}, "dashboard_id": {"type": "string"}, "config": {"type": "object"}, "backup": {"type": "boolean"}, "dry_run": {"type": "boolean"}, "force": {"type": "boolean"}},
        ["config"],
    ),
    tool_schema("live_lovelace_resources", "List Lovelace resources through the Home Assistant WebSocket API", {}, []),
    tool_schema(
        "list_lovelace_dashboards",
        "List Lovelace dashboards from HA's dashboard registry with matching storage keys",
        {"include_config": {"type": "boolean"}, "max_bytes": {"type": "integer", "minimum": 1, "maximum": 100000000}},
        [],
    ),
    tool_schema(
        "get_lovelace_dashboard_outline",
        "Return a compact dashboard outline with view/card paths, titles, types, and entities",
        {"id": {"type": "string"}, "url_path": {"type": "string"}, "key": {"type": "string"}, "include_entities": {"type": "boolean"}, "include_badges": {"type": "boolean"}},
        [],
    ),
    tool_schema(
        "get_lovelace_dashboard",
        "Read one Lovelace dashboard by id, url_path, or storage key",
        {
            "id": {"type": "string"},
            "url_path": {"type": "string"},
            "key": {"type": "string"},
            "max_bytes": {"type": "integer", "minimum": 1, "maximum": 100000000},
        },
        [],
    ),
    tool_schema(
        "get_lovelace_view",
        "Read exactly one Lovelace dashboard view by index, title, path, or query",
        {
            "id": {"type": "string"},
            "url_path": {"type": "string"},
            "key": {"type": "string"},
            "view_index": {"type": "integer", "minimum": 0},
            "view_title": {"type": "string"},
            "view_path": {"type": "string"},
            "query": {"type": "string"},
            "include_cards": {"type": "boolean"},
            "expected_matches": {"type": "integer", "minimum": 1, "maximum": 100},
        },
        [],
    ),
    tool_schema(
        "get_lovelace_card",
        "Read exactly one Lovelace card by stable JSON path or narrow filters",
        {
            "id": {"type": "string"},
            "url_path": {"type": "string"},
            "key": {"type": "string"},
            "view_index": {"type": "integer", "minimum": 0},
            "view_title": {"type": "string"},
            "query": {"type": "string"},
            "entity": {"type": "string"},
            "card_type": {"type": "string"},
            "path": {"type": "string"},
            "expected_matches": {"type": "integer", "minimum": 1, "maximum": 100},
        },
        [],
    ),
    tool_schema(
        "find_lovelace_cards",
        "Find Lovelace cards in one dashboard and return stable JSON paths without saving changes",
        {
            "id": {"type": "string"},
            "url_path": {"type": "string"},
            "key": {"type": "string"},
            "view_index": {"type": "integer", "minimum": 0},
            "view_title": {"type": "string"},
            "query": {"type": "string"},
            "entity": {"type": "string"},
            "card_type": {"type": "string"},
            "path": {"type": "string"},
            "limit": {"type": "integer", "minimum": 1, "maximum": 10000},
        },
        [],
    ),
    tool_schema(
        "patch_lovelace_card",
        "Patch exactly one Lovelace card by path or filters while preserving the rest of the dashboard",
        {
            "id": {"type": "string"},
            "url_path": {"type": "string"},
            "key": {"type": "string"},
            "view_index": {"type": "integer", "minimum": 0},
            "view_title": {"type": "string"},
            "query": {"type": "string"},
            "entity": {"type": "string"},
            "card_type": {"type": "string"},
            "path": {"type": "string"},
            "patch": {"type": "object"},
            "replace": {"type": "object"},
            "remove_keys": {"type": "array", "items": {"type": "string"}},
            "expected_matches": {"type": "integer", "minimum": 1, "maximum": 100},
            "backup": {"type": "boolean"},
            "label": {"type": "string"},
            "dry_run": {"type": "boolean"},
            "expected_hash": {"type": "string"},
        },
        [],
    ),
    tool_schema(
        "patch_lovelace_json_path",
        "Patch, replace, append to, insert into, or remove one Lovelace dashboard JSON path",
        {
            "id": {"type": "string"},
            "url_path": {"type": "string"},
            "key": {"type": "string"},
            "path": {"type": "string"},
            "patch": {"type": "object"},
            "replace": {},
            "append": {},
            "insert": {},
            "index": {"type": "integer", "minimum": 0},
            "remove": {"type": "boolean"},
            "remove_keys": {"type": "array", "items": {"type": "string"}},
            "backup": {"type": "boolean"},
            "label": {"type": "string"},
            "dry_run": {"type": "boolean"},
            "expected_hash": {"type": "string"},
        },
        ["path"],
    ),
    tool_schema(
        "insert_lovelace_card",
        "Insert or append a card into one Lovelace view while preserving the rest of the dashboard",
        {
            "id": {"type": "string"},
            "url_path": {"type": "string"},
            "key": {"type": "string"},
            "view_index": {"type": "integer", "minimum": 0},
            "view_title": {"type": "string"},
            "view_path": {"type": "string"},
            "card": {"type": "object"},
            "index": {"type": "integer", "minimum": 0},
            "backup": {"type": "boolean"},
            "label": {"type": "string"},
            "dry_run": {"type": "boolean"},
            "expected_hash": {"type": "string"},
        },
        ["card"],
    ),
    tool_schema(
        "delete_lovelace_card",
        "Delete exactly one Lovelace card by path or filters while preserving the rest of the dashboard",
        {
            "id": {"type": "string"},
            "url_path": {"type": "string"},
            "key": {"type": "string"},
            "view_index": {"type": "integer", "minimum": 0},
            "view_title": {"type": "string"},
            "query": {"type": "string"},
            "entity": {"type": "string"},
            "card_type": {"type": "string"},
            "path": {"type": "string"},
            "expected_matches": {"type": "integer", "minimum": 1, "maximum": 100},
            "backup": {"type": "boolean"},
            "label": {"type": "string"},
            "dry_run": {"type": "boolean"},
            "expected_hash": {"type": "string"},
            "force": {"type": "boolean"},
        },
        [],
    ),
    tool_schema(
        "move_lovelace_card",
        "Move exactly one Lovelace card to another view/index while preserving the rest of the dashboard",
        {
            "id": {"type": "string"},
            "url_path": {"type": "string"},
            "key": {"type": "string"},
            "path": {"type": "string"},
            "query": {"type": "string"},
            "entity": {"type": "string"},
            "card_type": {"type": "string"},
            "view_index": {"type": "integer", "minimum": 0},
            "view_title": {"type": "string"},
            "target_view_index": {"type": "integer", "minimum": 0},
            "target_view_title": {"type": "string"},
            "target_index": {"type": "integer", "minimum": 0},
            "expected_matches": {"type": "integer", "minimum": 1, "maximum": 100},
            "backup": {"type": "boolean"},
            "label": {"type": "string"},
            "dry_run": {"type": "boolean"},
            "expected_hash": {"type": "string"},
        },
        [],
    ),
    tool_schema(
        "save_lovelace_dashboard",
        "Create or update a Lovelace dashboard by id or url_path and save its config/views",
        {
            "key": {"type": "string"},
            "id": {"type": "string"},
            "url_path": {"type": "string"},
            "title": {"type": "string"},
            "icon": {"type": "string"},
            "show_in_sidebar": {"type": "boolean"},
            "require_admin": {"type": "boolean"},
            "config": {"type": "object"},
            "views": {"type": "array"},
            "data": {"type": "object"},
            "content": {"type": "string"},
            "create": {"type": "boolean"},
            "backup": {"type": "boolean"},
            "label": {"type": "string"},
            "mode": {"type": "string"},
            "dry_run": {"type": "boolean"},
            "expected_hash": {"type": "string"},
        },
        [],
    ),
    tool_schema(
        "delete_lovelace_dashboard",
        "Delete a Lovelace dashboard registry entry and storage file by id, url_path, or key",
        {"id": {"type": "string"}, "url_path": {"type": "string"}, "key": {"type": "string"}, "backup": {"type": "boolean"}, "force": {"type": "boolean"}, "dry_run": {"type": "boolean"}},
        [],
    ),
    tool_schema(
        "write_storage_key",
        "Write a Home Assistant .storage key from JSON data or raw content",
        {"key": {"type": "string"}, "data": {"type": "object"}, "content": {"type": "string"}, "mode": {"type": "string"}, "dry_run": {"type": "boolean"}, "expected_hash": {"type": "string"}, "backup": {"type": "boolean"}},
        ["key"],
    ),
    tool_schema(
        "delete_storage_key",
        "Delete a Home Assistant .storage key",
        {"key": {"type": "string"}, "force": {"type": "boolean"}, "dry_run": {"type": "boolean"}},
        ["key"],
    ),
    tool_schema(
        "backup_storage_key",
        "Copy a Home Assistant .storage key into /backup/ha-admin-mcp",
        {"key": {"type": "string"}, "label": {"type": "string"}},
        ["key"],
    ),
]


UPSTREAM_HA_MCP_TOOL_NAMES = [
    "ha_get_addon",
    "ha_manage_addon",
    "ha_list_floors_areas",
    "ha_remove_area_or_floor",
    "ha_set_area_or_floor",
    "ha_manage_pipeline",
    "ha_config_get_automation",
    "ha_config_remove_automation",
    "ha_config_set_automation",
    "ha_get_blueprint",
    "ha_import_blueprint",
    "ha_config_get_calendar_events",
    "ha_config_remove_calendar_event",
    "ha_config_set_calendar_event",
    "ha_get_camera_image",
    "ha_get_dashboard_screenshot",
    "ha_config_delete_dashboard_resource",
    "ha_config_delete_dashboard",
    "ha_config_get_dashboard",
    "ha_config_list_dashboard_resources",
    "ha_config_set_dashboard_resource",
    "ha_config_set_dashboard",
    "ha_get_device",
    "ha_remove_device",
    "ha_set_device",
    "ha_manage_energy_prefs",
    "ha_get_entity_exposure",
    "ha_get_entity",
    "ha_remove_entity",
    "ha_set_entity",
    "ha_delete_file",
    "ha_list_files",
    "ha_read_file",
    "ha_write_file",
    "ha_config_list_groups",
    "ha_config_remove_group",
    "ha_config_set_group",
    "ha_get_hacs_info",
    "ha_manage_hacs",
    "ha_config_list_helpers",
    "ha_config_set_helper",
    "ha_remove_helpers_integrations",
    "ha_get_automation_traces",
    "ha_get_history",
    "ha_get_logs",
    "ha_get_integration",
    "ha_get_system_health",
    "ha_set_integration_enabled",
    "ha_config_get_category",
    "ha_config_get_label",
    "ha_config_remove_category",
    "ha_config_remove_label",
    "ha_config_set_category",
    "ha_config_set_label",
    "ha_config_get_scene",
    "ha_config_remove_scene",
    "ha_config_set_scene",
    "ha_config_get_script",
    "ha_config_remove_script",
    "ha_config_set_script",
    "ha_get_overview",
    "ha_get_state",
    "ha_search",
    "ha_bulk_control",
    "ha_call_event",
    "ha_call_service",
    "ha_get_operation_status",
    "ha_list_services",
    "ha_config_set_yaml",
    "ha_get_updates",
    "ha_manage_backup",
    "ha_manage_custom_tool",
    "ha_manage_theme",
    "ha_reload_core",
    "ha_restart",
    "ha_get_todo",
    "ha_remove_todo_item",
    "ha_set_todo_item",
    "ha_get_zone",
    "ha_remove_zone",
    "ha_set_zone",
    "ha_eval_template",
    "ha_install_mcp_tools",
    "ha_report_issue",
]


UPSTREAM_COMPAT_TOOL_SCHEMAS = [
    tool_schema(
        name,
        f"homeassistant-ai/ha-mcp compatibility shim for {name}; routed through this app's full-access HA admin primitives",
        {
            "entity_id": {"type": "string"},
            "identifier": {"type": "string"},
            "id": {"type": "string"},
            "name": {"type": "string"},
            "query": {"type": "string"},
            "domain": {"type": "string"},
            "service": {"type": "string"},
            "action": {"type": "string"},
            "data": {"type": "object"},
            "config": {"type": "object"},
            "path": {"type": "string"},
            "content": {"type": "string"},
            "template": {"type": "string"},
            "slug": {"type": "string"},
            "limit": {"type": "integer", "minimum": 1, "maximum": 10000},
            "start_time": {"type": "string"},
            "end_time": {"type": "string"},
            "hours": {"type": "integer", "minimum": 1, "maximum": 100000},
            "period": {"type": "string"},
            "backup": {"type": "boolean"},
            "dry_run": {"type": "boolean"},
            "force": {"type": "boolean"},
            "expected_hash": {"type": "string"},
        },
        [],
    )
    for name in UPSTREAM_HA_MCP_TOOL_NAMES
]


TOOLS.extend(UPSTREAM_COMPAT_TOOL_SCHEMAS)


RESOURCES = [
    {"uri": "ha://core/info", "name": "Home Assistant Core info", "mimeType": "application/json"},
    {"uri": "ha://supervisor/info", "name": "Supervisor info", "mimeType": "application/json"},
    {"uri": "ha://host/info", "name": "Host info", "mimeType": "application/json"},
    {"uri": "ha://states", "name": "Home Assistant states", "mimeType": "application/json"},
    {"uri": "ha://services", "name": "Home Assistant services", "mimeType": "application/json"},
    {"uri": "ha://events", "name": "Home Assistant events", "mimeType": "application/json"},
    {"uri": "ha://lovelace/dashboards", "name": "Lovelace dashboards", "mimeType": "application/json"},
    {"uri": "ha://config/configuration.yaml", "name": "configuration.yaml", "mimeType": "text/yaml"},
    {"uri": "ha://storage/core.entity_registry", "name": "Entity registry", "mimeType": "application/json"},
    {"uri": "ha://storage/core.device_registry", "name": "Device registry", "mimeType": "application/json"},
    {"uri": "ha://storage/core.config_entries", "name": "Config entries", "mimeType": "application/json"},
]


RESOURCE_TEMPLATES = [
    {
        "uriTemplate": "ha://state/{entity_id}",
        "name": "One Home Assistant entity state",
        "mimeType": "application/json",
    },
    {
        "uriTemplate": "ha://config/{path}",
        "name": "One file under /config",
        "mimeType": "text/plain",
    },
    {
        "uriTemplate": "ha://storage/{key}",
        "name": "One Home Assistant .storage key",
        "mimeType": "application/json",
    },
    {
        "uriTemplate": "ha://lovelace/dashboard/{id}",
        "name": "One Lovelace dashboard",
        "mimeType": "application/json",
    },
    {
        "uriTemplate": "ha://lovelace/view/{id}/{view}",
        "name": "One Lovelace dashboard view by title, path, or index",
        "mimeType": "application/json",
    },
]


PROMPTS = [
    {
        "name": "ha_admin_audit",
        "description": "Inspect HA health, logs, registries, config check, and reload readiness before making changes.",
        "arguments": [],
    },
    {
        "name": "lovelace_safe_patch",
        "description": "Workflow for finding and patching one Lovelace card without replacing the full dashboard blob.",
        "arguments": [
            {"name": "dashboard", "description": "Dashboard id, url path, or storage key", "required": False},
            {"name": "target", "description": "Entity, card title, card type, or query to locate", "required": False},
        ],
    },
    {
        "name": "config_safe_edit",
        "description": "Workflow for reading, editing, checking, and reloading Home Assistant config safely.",
        "arguments": [
            {"name": "path", "description": "Config file path relative to /config", "required": False},
        ],
    },
]


def call_tool(name: str, args: dict[str, Any]) -> Any:
    if name in UPSTREAM_HA_MCP_TOOL_NAMES:
        return call_upstream_compat_tool(name, args)
    if name == "run_command":
        timeout = int(args.get("timeout") or OPTIONS.get("command_timeout_seconds") or 300)
        max_output = int(args.get("max_output_bytes") or 20000)
        audit_event("run_command", {"command": args["command"], "cwd": args.get("cwd")})
        completed = subprocess.run(
            args["command"],
            cwd=args.get("cwd") or None,
            shell=True,
            text=True,
            capture_output=True,
            timeout=timeout,
        )
        return {
            "command": args["command"],
            "cwd": args.get("cwd"),
            "returncode": completed.returncode,
            "stdout": completed.stdout[:max_output],
            "stderr": completed.stderr[:max_output],
            "stdout_truncated": len(completed.stdout) > max_output,
            "stderr_truncated": len(completed.stderr) > max_output,
        }
    if name == "run_shell":
        timeout = int(args.get("timeout") or OPTIONS.get("command_timeout_seconds") or 300)
        max_output = int(args.get("max_output_bytes") or 20000)
        audit_event("run_shell", {"command": args["command"], "shell": args.get("shell"), "cwd": args.get("cwd")})
        completed = subprocess.run(
            args["command"],
            cwd=args.get("cwd") or None,
            shell=True,
            executable=args.get("shell") or None,
            text=True,
            capture_output=True,
            timeout=timeout,
        )
        return {
            "command": args["command"],
            "shell": args.get("shell"),
            "cwd": args.get("cwd"),
            "returncode": completed.returncode,
            "stdout": completed.stdout[:max_output],
            "stderr": completed.stderr[:max_output],
            "stdout_truncated": len(completed.stdout) > max_output,
            "stderr_truncated": len(completed.stderr) > max_output,
        }
    if name == "get_environment":
        return get_environment(bool(args.get("include_values")))
    if name == "get_target_identity":
        return get_target_identity()
    if name == "get_version":
        return get_version()
    if name == "search_tools":
        return search_tools(args["query"], int(args.get("limit") or 10))
    if name == "batch_call_tools":
        return batch_call_tools(args)
    if name == "stat_path":
        path = Path(args["path"])
        return path_info(path) if path.exists() or path.is_symlink() else {"path": str(path), "exists": False}
    if name == "list_dir":
        path = Path(args["path"])
        limit = int(args.get("limit") or 500)
        return [path_info(child) for child in list(path.iterdir())[:limit]]
    if name == "read_file":
        content, truncated = read_limited(Path(args["path"]), int(args.get("max_bytes") or MAX_READ_BYTES))
        return {"path": args["path"], "content": content, "truncated": truncated}
    if name == "read_file_window":
        return read_file_window(Path(args["path"]), int(args.get("offset") or 0), int(args.get("length") or 100000))
    if name == "read_file_lines":
        return read_file_lines(Path(args["path"]), int(args.get("start_line") or 1), int(args.get("line_count") or 200))
    if name == "read_file_base64":
        data, truncated = read_bytes_limited(Path(args["path"]), int(args.get("max_bytes") or MAX_READ_BYTES))
        return {"path": args["path"], "content_base64": base64.b64encode(data).decode(), "truncated": truncated}
    if name == "write_file":
        path = Path(args["path"])
        require_expected_hash(path, args.get("expected_hash"))
        if bool(args.get("dry_run")):
            return {"path": str(path), "dry_run": True, "would_write_bytes": len(args["content"].encode()), "current_hash": path_hash(path)}
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(args["content"])
        if args.get("mode"):
            path.chmod(int(str(args["mode"]), 8))
        audit_event("write_file", {"path": str(path), "bytes": len(args["content"].encode())})
        return path_info(path)
    if name == "write_file_base64":
        path = Path(args["path"])
        require_expected_hash(path, args.get("expected_hash"))
        data = base64.b64decode(args["content_base64"])
        if bool(args.get("dry_run")):
            return {"path": str(path), "dry_run": True, "would_write_bytes": len(data), "current_hash": path_hash(path)}
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        if args.get("mode"):
            path.chmod(int(str(args["mode"]), 8))
        audit_event("write_file_base64", {"path": str(path), "bytes": len(data)})
        return path_info(path)
    if name == "delete_path":
        path = Path(args["path"])
        require_force_for_path(path, args, "delete_path")
        if bool(args.get("dry_run")):
            return {"path": str(path), "dry_run": True, "exists": path.exists(), "recursive": bool(args.get("recursive"))}
        if path.is_dir() and not path.is_symlink():
            if not args.get("recursive"):
                path.rmdir()
            else:
                shutil.rmtree(path)
        else:
            path.unlink()
        audit_event("delete_path", {"path": str(path), "recursive": bool(args.get("recursive"))})
        return {"path": str(path), "deleted": True}
    if name == "search_files":
        return search_files(args)
    if name == "glob_paths":
        return glob_paths(args["pattern"], int(args.get("limit") or 500))
    if name == "hash_file":
        return hash_file(Path(args["path"]), args.get("algorithm") or "sha256")
    if name == "ha_api":
        if str(args.get("method", "GET")).upper() not in ("GET", "HEAD", "OPTIONS"):
            audit_event("ha_api", {"method": args.get("method", "GET"), "endpoint": args["endpoint"]})
        return ha_request(args.get("method", "GET"), args["endpoint"], args.get("data"))
    if name == "ha_ws_call":
        return ha_ws_call(args["message"], int(args.get("timeout") or 30))
    if name == "supervisor_api":
        if str(args.get("method", "GET")).upper() not in ("GET", "HEAD", "OPTIONS"):
            audit_event("supervisor_api", {"method": args.get("method", "GET"), "endpoint": args["endpoint"]})
        return supervisor_request(args.get("method", "GET"), args["endpoint"], args.get("data"))
    if name == "http_request":
        return http_request(args)
    if name == "check_config":
        return run_config_check()
    if name == "ha_cli":
        return ha_cli(args)
    if name == "core_info":
        return supervisor_request("GET", "/core/info")
    if name == "host_info":
        return supervisor_request("GET", "/host/info")
    if name == "supervisor_info":
        return supervisor_request("GET", "/supervisor/info")
    if name == "store_info":
        return supervisor_request("GET", "/store")
    if name == "app_info":
        return supervisor_request("GET", f"/addons/{args['slug']}/info")
    if name == "app_logs":
        return supervisor_request("GET", f"/addons/{args['slug']}/logs")
    if name == "app_control":
        audit_event("app_control", {"slug": args["slug"], "action": args["action"]})
        return supervisor_request("POST", f"/addons/{args['slug']}/{args['action']}")
    if name == "restart_core":
        if not bool(args.get("force")):
            raise ValueError("restart_core requires force=true")
        audit_event("restart_core", {})
        return supervisor_request("POST", "/core/restart")
    if name == "stop_core":
        if not bool(args.get("force")):
            raise ValueError("stop_core requires force=true")
        audit_event("stop_core", {})
        return supervisor_request("POST", "/core/stop")
    if name == "start_core":
        audit_event("start_core", {})
        return supervisor_request("POST", "/core/start")
    if name == "reload_core_config":
        audit_event("reload_core_config", {})
        return ha_request("POST", "/services/homeassistant/reload_core_config")
    if name == "check_reload_readiness":
        return check_reload_readiness()
    if name == "check_config_and_reload":
        return check_config_and_reload(args)
    if name == "reload_domain_config":
        audit_event("reload_domain_config", {"domain": args["domain"]})
        return ha_request("POST", f"/services/{args['domain']}/reload", args.get("data") or {})
    if name == "call_service":
        audit_event("call_service", {"domain": args["domain"], "service": args["service"], "data": args.get("data") or {}})
        return ha_request("POST", f"/services/{args['domain']}/{args['service']}", args.get("data") or {})
    if name == "get_states":
        entity_id = args.get("entity_id")
        return ha_request("GET", f"/states/{entity_id}" if entity_id else "/states")
    if name == "get_entity":
        return get_entity(args)
    if name == "entity_action":
        return entity_action(args)
    if name == "list_entities":
        return list_entities(args)
    if name == "search_entities":
        return search_entities(args["query"], int(args.get("limit") or 20))
    if name == "get_entities_by_area":
        return get_entities_by_area(args["area"], int(args.get("limit") or 500))
    if name == "domain_summary":
        return domain_summary(args["domain"], int(args.get("example_limit") or 3))
    if name == "system_overview":
        return system_overview()
    if name == "diagnostic_bundle":
        return diagnostic_bundle(args)
    if name == "list_automations":
        return list_automations()
    if name == "list_automation_configs":
        return list_domain_configs("automation", args)
    if name == "get_automation_config":
        return get_domain_config("automation", args)
    if name == "list_script_configs":
        return list_domain_configs("script", args)
    if name == "get_script_config":
        return get_domain_config("script", args)
    if name == "list_scene_configs":
        return list_domain_configs("scene", args)
    if name == "get_scene_config":
        return get_domain_config("scene", args)
    if name == "get_events":
        return ha_request("GET", "/events")
    if name == "get_services":
        return ha_request("GET", "/services")
    if name == "get_history":
        endpoint = "/history/period"
        if args.get("timestamp"):
            endpoint += f"/{urllib.parse.quote(str(args['timestamp']), safe=':TZ+-')}"
        endpoint = maybe_query(
            endpoint,
            {
                "filter_entity_id": args.get("filter_entity_id"),
                "minimal_response": str(bool(args.get("minimal_response"))).lower() if "minimal_response" in args else None,
                "no_attributes": str(bool(args.get("no_attributes"))).lower() if "no_attributes" in args else None,
                "significant_changes_only": str(bool(args.get("significant_changes_only"))).lower()
                if "significant_changes_only" in args
                else None,
            },
        )
        return ha_request("GET", endpoint)
    if name == "get_history_range":
        return get_history_range(args)
    if name == "get_statistics":
        return get_statistics(args)
    if name == "get_statistics_range":
        return get_statistics_range(args)
    if name == "get_error_log":
        return get_error_log(args)
    if name == "render_template":
        return ha_request("POST", "/template", {"template": args["template"]})
    if name == "fire_event":
        audit_event("fire_event", {"event_type": args["event_type"], "event_data": args.get("event_data") or {}})
        return ha_request("POST", f"/events/{args['event_type']}", args.get("event_data") or {})
    if name == "backup_path":
        return backup_path(Path(args["path"]), args.get("label"))
    if name == "list_config_files":
        return list_config_files(args)
    if name == "read_config_file":
        content, truncated = read_limited(config_path(args["path"]), int(args.get("max_bytes") or MAX_READ_BYTES))
        return {"path": str(config_path(args["path"])), "relative_path": args["path"], "content": content, "truncated": truncated}
    if name == "read_config_lines":
        return read_file_lines(config_path(args["path"]), int(args.get("start_line") or 1), int(args.get("line_count") or 200)) | {"relative_path": args["path"]}
    if name == "write_config_file":
        return write_config_file(args)
    if name == "search_config":
        search_args = dict(args)
        search_args["path"] = str(config_path(search_args.get("path") or "."))
        return search_files(search_args)
    if name == "patch_config_text":
        return patch_config_text(args)
    if name == "ensure_config_block":
        return ensure_config_block(args)
    if name == "list_packages":
        return list_packages(bool(args.get("recursive")))
    if name == "read_package":
        package_args = dict(args)
        package_args["path"] = str(Path("packages") / package_args["path"])
        content, truncated = read_limited(config_path(package_args["path"]), int(args.get("max_bytes") or MAX_READ_BYTES))
        return {"path": str(config_path(package_args["path"])), "relative_path": package_args["path"], "content": content, "truncated": truncated}
    if name == "write_package":
        package_args = dict(args)
        package_args["path"] = str(Path("packages") / package_args["path"])
        return write_config_file(package_args)
    if name == "patch_package_text":
        package_args = dict(args)
        package_args["path"] = str(Path("packages") / package_args["path"])
        return patch_config_text(package_args)
    if name == "list_secrets":
        return list_secrets()
    if name == "get_secret":
        return get_secret(args["name"])
    if name == "set_secret":
        return set_secret(args)
    if name == "delete_secret":
        return delete_secret(args)
    if name == "tail_log":
        return tail_log(args)
    if name == "list_storage_keys":
        return list_storage_keys(bool(args.get("include_backups")))
    if name == "list_storage_keys_filtered":
        return list_storage_keys_filtered(args)
    if name == "read_storage_key":
        return read_storage_key(args["key"], int(args.get("max_bytes") or MAX_READ_BYTES))
    if name == "read_storage_key_window":
        return read_file_window(storage_path(args["key"]), int(args.get("offset") or 0), int(args.get("length") or 100000))
    if name == "search_storage_key":
        return search_storage_key(args["key"], args["query"], int(args.get("limit") or 50))
    if name == "search_storage_json":
        return search_storage_json(args)
    if name == "read_storage_json_path":
        return read_storage_json_path(args["key"], args["path"])
    if name == "read_storage_json_paths":
        return read_storage_json_paths(args["key"], args["paths"])
    if name == "patch_storage_json_path":
        return patch_storage_json_path(args)
    if name == "search_entity_registry":
        return search_entity_registry(args)
    if name == "get_entity_registry_entry":
        return get_entity_registry_entry(args)
    if name == "search_device_registry":
        return search_device_registry(args)
    if name == "search_config_entries":
        return search_config_entries(args)
    if name == "search_area_registry":
        return search_named_registry("core.area_registry", "areas", args)
    if name == "search_floor_registry":
        return search_named_registry("core.floor_registry", "floors", args)
    if name == "search_label_registry":
        return search_named_registry("core.label_registry", "labels", args)
    if name == "patch_entity_registry_entry":
        return patch_registry_entry("core.entity_registry", "entities", args, ["entity_id", "unique_id", "id"])
    if name == "patch_device_registry_entry":
        return patch_registry_entry("core.device_registry", "devices", args, ["id", "name", "name_by_user"])
    if name == "sqlite_query":
        return sqlite_query(args)
    if name == "recorder_purge":
        return recorder_purge(args)
    if name == "recorder_purge_entities":
        return recorder_purge_entities(args)
    if name == "recorder_get_db_info":
        return recorder_get_db_info()
    if name == "list_backups":
        return supervisor_request("GET", "/backups")
    if name == "create_backup":
        return create_backup(args)
    if name == "get_backup_info":
        return supervisor_request("GET", f"/backups/{args['slug']}/info")
    if name == "delete_backup":
        return delete_backup(args)
    if name == "restore_backup":
        return restore_backup(args)
    if name == "read_lovelace_dashboards":
        return read_lovelace_dashboards(bool(args.get("include_content")), int(args.get("max_bytes") or MAX_READ_BYTES))
    if name == "live_lovelace_get_config":
        return live_lovelace_get_config(args)
    if name == "live_lovelace_get_outline":
        return live_lovelace_get_outline(args)
    if name == "live_lovelace_find_cards":
        return live_lovelace_find_cards(args)
    if name == "live_lovelace_get_card":
        return live_lovelace_get_card(args)
    if name == "live_lovelace_patch_card":
        return live_lovelace_patch_card(args)
    if name == "live_lovelace_save_config":
        return live_lovelace_save_config(args)
    if name == "live_lovelace_resources":
        return ha_ws_call({"type": "lovelace/resources"})
    if name == "list_lovelace_dashboards":
        return list_lovelace_dashboards(bool(args.get("include_config")), int(args.get("max_bytes") or MAX_READ_BYTES))
    if name == "get_lovelace_dashboard_outline":
        return get_lovelace_dashboard_outline(args)
    if name == "get_lovelace_dashboard":
        return get_lovelace_dashboard(args, int(args.get("max_bytes") or MAX_READ_BYTES))
    if name == "get_lovelace_view":
        return get_lovelace_view(args)
    if name == "get_lovelace_card":
        return get_lovelace_card(args)
    if name == "find_lovelace_cards":
        return find_lovelace_cards(args)
    if name == "patch_lovelace_card":
        return patch_lovelace_card(args)
    if name == "patch_lovelace_json_path":
        return patch_lovelace_json_path(args)
    if name == "insert_lovelace_card":
        return insert_lovelace_card(args)
    if name == "delete_lovelace_card":
        return delete_lovelace_card(args)
    if name == "move_lovelace_card":
        return move_lovelace_card(args)
    if name == "save_lovelace_dashboard":
        return save_lovelace_dashboard(args)
    if name == "delete_lovelace_dashboard":
        return delete_lovelace_dashboard(args)
    if name == "write_storage_key":
        return write_storage_key(args["key"], args)
    if name == "delete_storage_key":
        path = storage_path(args["key"])
        if not bool(args.get("force")):
            raise ValueError("delete_storage_key requires force=true")
        if bool(args.get("dry_run")):
            return {"key": args["key"], "path": str(path), "dry_run": True, "exists": path.exists()}
        path.unlink()
        audit_event("delete_storage_key", {"key": args["key"], "path": str(path)})
        return {"key": args["key"], "path": str(path), "deleted": True}
    if name == "backup_storage_key":
        return backup_path(storage_path(args["key"]), args.get("label") or args["key"])
    raise ValueError(f"Unknown tool: {name}")


def get_environment(include_values: bool) -> dict[str, Any]:
    def redact(name: str, value: str) -> str:
        if include_values and not any(token in name.upper() for token in ("TOKEN", "SECRET", "PASSWORD", "KEY")):
            return value
        return f"<redacted:{len(value)}>"

    rows: dict[str, Any] = {"process": {}, "s6": {}}
    for key, value in sorted(os.environ.items()):
        rows["process"][key] = redact(key, value)
    if S6_ENV_DIR.exists():
        for path in sorted(S6_ENV_DIR.iterdir()):
            if path.is_file():
                value = path.read_text(errors="replace").strip()
                rows["s6"][path.name] = redact(path.name, value)
    return rows


def get_target_identity() -> dict[str, Any]:
    core = supervisor_request("GET", "/core/info")
    supervisor = supervisor_request("GET", "/supervisor/info")
    host = supervisor_request("GET", "/host/info")
    return {
        "app": {"name": "ha-admin-mcp", "version": APP_VERSION, "endpoint_path": MCP_PATH},
        "core": core.get("data", core) if isinstance(core, dict) else core,
        "supervisor": supervisor.get("data", supervisor) if isinstance(supervisor, dict) else supervisor,
        "host": host.get("data", host) if isinstance(host, dict) else host,
        "warning": "This MCP app has full-access administrative control over this Home Assistant instance.",
    }


def get_version() -> str:
    info = supervisor_request("GET", "/core/info")
    if isinstance(info, dict) and isinstance(info.get("data"), dict):
        info = info["data"]
    return str(info.get("version") or info.get("homeassistant") or info)


def batch_call_tools(args: dict[str, Any]) -> dict[str, Any]:
    calls = args.get("calls") or []
    if not isinstance(calls, list):
        raise ValueError("calls must be a list")
    stop_on_error = bool(args.get("stop_on_error", True))
    results = []
    for index, call in enumerate(calls):
        if not isinstance(call, dict):
            row = {"index": index, "error": "call must be an object"}
        else:
            tool_name = str(call.get("name") or "")
            if not tool_name:
                row = {"index": index, "error": "name is required"}
            elif tool_name == "batch_call_tools":
                row = {"index": index, "name": tool_name, "error": "batch_call_tools cannot call itself"}
            else:
                try:
                    row = {"index": index, "name": tool_name, "result": call_tool(tool_name, call.get("arguments") or {})}
                except Exception as err:
                    row = {"index": index, "name": tool_name, "error": str(err)}
        results.append(row)
        if stop_on_error and row.get("error"):
            break
    return {"count": len(results), "results": results}


def search_tools(query: str, limit: int) -> dict[str, Any]:
    needle = query.lower()
    rows = []
    for tool in TOOLS:
        haystack = json.dumps(tool, default=str).lower()
        if needle in haystack:
            rows.append(
                {
                    "name": tool["name"],
                    "description": tool.get("description", ""),
                    "required": tool.get("inputSchema", {}).get("required", []),
                    "properties": sorted((tool.get("inputSchema", {}).get("properties") or {}).keys()),
                }
            )
            if len(rows) >= limit:
                break
    return {"query": query, "count": len(rows), "matches": rows}


def project_field(value: Any, field: str) -> Any:
    if field.startswith("attr."):
        return (value.get("attributes") or {}).get(field.removeprefix("attr."))
    current = value
    for part in field.split("."):
        if not isinstance(current, dict):
            return None
        current = current.get(part)
    return current


def project_entity_state(state: dict[str, Any], fields: list[str] | None, detailed: bool = False) -> dict[str, Any]:
    if detailed:
        return state
    if fields:
        return {field: project_field(state, field) for field in fields}
    attributes = state.get("attributes") or {}
    return {
        "entity_id": state.get("entity_id"),
        "state": state.get("state"),
        "friendly_name": attributes.get("friendly_name"),
        "last_changed": state.get("last_changed"),
    }


def registry_maps() -> dict[str, Any]:
    entities = load_storage_json("core.entity_registry").get("data", {}).get("entities", [])
    devices = load_storage_json("core.device_registry").get("data", {}).get("devices", [])
    areas = load_storage_json("core.area_registry").get("data", {}).get("areas", [])
    area_by_id = {area.get("id"): area for area in areas}
    device_by_id = {device.get("id"): device for device in devices}
    entity_by_id = {entity.get("entity_id"): entity for entity in entities}
    return {"area_by_id": area_by_id, "device_by_id": device_by_id, "entity_by_id": entity_by_id}


def entity_area_name(entity_id: str, maps: dict[str, Any]) -> str | None:
    entry = maps["entity_by_id"].get(entity_id) or {}
    area_id = entry.get("area_id")
    if not area_id and entry.get("device_id"):
        area_id = (maps["device_by_id"].get(entry["device_id"]) or {}).get("area_id")
    area = maps["area_by_id"].get(area_id) or {}
    return area.get("name") or area_id


def get_entity(args: dict[str, Any]) -> dict[str, Any]:
    state = ha_request("GET", f"/states/{args['entity_id']}")
    return project_entity_state(state, args.get("fields"), bool(args.get("detailed")))


def entity_action(args: dict[str, Any]) -> Any:
    entity_id = args["entity_id"]
    action = args["action"]
    service = action if action == "toggle" else f"turn_{action}"
    domain = entity_id.split(".", 1)[0]
    data = {"entity_id": entity_id} | (args.get("params") or {})
    return ha_request("POST", f"/services/{domain}/{service}", data)


def list_entities(args: dict[str, Any]) -> dict[str, Any]:
    states = ha_request("GET", "/states")
    maps = registry_maps()
    domain = args.get("domain")
    wanted_area = str(args.get("area") or "").lower()
    wanted_state = args.get("state")
    query = str(args.get("query") or "").lower()
    limit = int(args.get("limit") or 500)
    offset = int(args.get("offset") or 0)
    rows = []
    for state in states:
        entity_id = state.get("entity_id", "")
        if domain and entity_id.split(".", 1)[0] != domain:
            continue
        if wanted_state is not None and str(state.get("state")) != str(wanted_state):
            continue
        area = entity_area_name(entity_id, maps)
        if wanted_area and wanted_area not in str(area or "").lower():
            continue
        if query and query not in json.dumps(state, default=str).lower() and query not in json.dumps(maps["entity_by_id"].get(entity_id, {}), default=str).lower():
            continue
        row = project_entity_state(state, args.get("fields"), bool(args.get("detailed")))
        if area:
            row["area"] = area
        rows.append(row)
    total = len(rows)
    rows = rows[offset : offset + limit]
    return {"count": len(rows), "total": total, "offset": offset, "limit": limit, "entities": rows}


def search_entities(query: str, limit: int) -> dict[str, Any]:
    return list_entities({"query": query, "limit": limit, "detailed": False})


def get_entities_by_area(area: str, limit: int) -> dict[str, Any]:
    return list_entities({"area": area, "limit": limit, "detailed": False})


def domain_summary(domain: str, example_limit: int) -> dict[str, Any]:
    states = [state for state in ha_request("GET", "/states") if str(state.get("entity_id", "")).split(".", 1)[0] == domain]
    state_counts: dict[str, int] = {}
    attr_counts: dict[str, int] = {}
    examples = []
    for state in states:
        state_counts[str(state.get("state"))] = state_counts.get(str(state.get("state")), 0) + 1
        for attr in (state.get("attributes") or {}):
            attr_counts[attr] = attr_counts.get(attr, 0) + 1
        if len(examples) < example_limit:
            examples.append(project_entity_state(state, None))
    return {"domain": domain, "count": len(states), "states": state_counts, "common_attributes": attr_counts, "examples": examples}


def system_overview() -> dict[str, Any]:
    states = ha_request("GET", "/states")
    maps = registry_maps()
    domains: dict[str, int] = {}
    areas: dict[str, int] = {}
    for state in states:
        entity_id = state.get("entity_id", "")
        domain = entity_id.split(".", 1)[0]
        domains[domain] = domains.get(domain, 0) + 1
        area = entity_area_name(entity_id, maps)
        if area:
            areas[area] = areas.get(area, 0) + 1
    return {
        "version": get_version(),
        "total_entities": len(states),
        "domains": dict(sorted(domains.items())),
        "areas": dict(sorted(areas.items())),
        "core": supervisor_request("GET", "/core/info"),
    }


def diagnostic_bundle(args: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {
        "target": get_target_identity(),
        "overview": system_overview(),
        "reload_readiness": check_reload_readiness(),
        "errors": get_error_log({"level": "ERROR", "lines": int(args.get("log_lines") or 80)}),
    }
    try:
        result["updates"] = ha_request("GET", "/states/update")
    except Exception as err:
        result["updates_error"] = str(err)
    if args.get("entity_id"):
        result["entity"] = get_entity({"entity_id": args["entity_id"], "detailed": True})
        try:
            result["entity_registry"] = get_entity_registry_entry({"entity_id": args["entity_id"]})
        except Exception as err:
            result["entity_registry_error"] = str(err)
    dashboard_args: dict[str, Any] = {}
    if args.get("dashboard_id"):
        dashboard_args["id"] = args["dashboard_id"]
    if args.get("dashboard_url_path"):
        dashboard_args["url_path"] = args["dashboard_url_path"]
    if dashboard_args:
        result["dashboard_outline"] = get_lovelace_dashboard_outline(dashboard_args)
    return result


def list_automations() -> dict[str, Any]:
    return list_entities({"domain": "automation", "detailed": True, "limit": 10000})


def list_domain_configs(domain: str, args: dict[str, Any]) -> dict[str, Any]:
    query = str(args.get("query") or "").lower()
    limit = int(args.get("limit") or 500)
    states = ha_request("GET", "/states")
    rows = []
    for state in states:
        entity_id = state.get("entity_id", "")
        if not entity_id.startswith(f"{domain}."):
            continue
        attrs = state.get("attributes") or {}
        row = {
            "entity_id": entity_id,
            "id": attrs.get("id") or entity_id.split(".", 1)[1],
            "friendly_name": attrs.get("friendly_name"),
            "state": state.get("state"),
            "last_changed": state.get("last_changed"),
        }
        if query and query not in json.dumps(row, default=str).lower():
            continue
        rows.append(row)
        if len(rows) >= limit:
            break
    return {"domain": domain, "count": len(rows), "items": rows}


def config_reference_files(domain: str) -> list[str]:
    base = {
        "automation": ["automations.yaml"],
        "script": ["scripts.yaml"],
        "scene": ["scenes.yaml"],
    }.get(domain, [f"{domain}s.yaml"])
    files = base[:]
    packages = config_path("packages")
    if packages.exists():
        files.extend(str(path.relative_to(CONFIG_ROOT)) for path in packages.rglob("*.yaml"))
        files.extend(str(path.relative_to(CONFIG_ROOT)) for path in packages.rglob("*.yml"))
    return files


def get_domain_config(domain: str, args: dict[str, Any]) -> dict[str, Any]:
    identifier = args.get("id") or args.get("entity_id") or args.get("query")
    if not identifier:
        raise ValueError("Pass entity_id, id, or query")
    identifier = str(identifier)
    entity_id = identifier if identifier.startswith(f"{domain}.") else f"{domain}.{identifier}" if "." not in identifier else identifier
    compact = list_domain_configs(domain, {"query": identifier, "limit": 20})
    state = None
    try:
        state = ha_request("GET", f"/states/{entity_id}")
    except Exception:
        pass
    needles = [identifier, entity_id, entity_id.split(".", 1)[-1]]
    if state and isinstance(state, dict):
        attrs = state.get("attributes") or {}
        for key in ("id", "friendly_name"):
            if attrs.get(key):
                needles.append(str(attrs[key]))
    contexts = []
    context_lines = int(args.get("context_lines") or 20)
    for rel_path in config_reference_files(domain):
        path = config_path(rel_path)
        if not path.exists() or not path.is_file():
            continue
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for number, line in enumerate(lines, 1):
            if any(needle and needle.lower() in line.lower() for needle in needles):
                start = max(1, number - context_lines // 2)
                contexts.append({"relative_path": rel_path, "match_line": number, "context": read_file_lines(path, start, context_lines)})
                break
    return {"domain": domain, "identifier": identifier, "entity_id": entity_id, "state": state, "matches": compact["items"], "source_contexts": contexts}


def first_present(args: dict[str, Any], *names: str) -> Any:
    for name in names:
        value = args.get(name)
        if value not in (None, ""):
            return value
    return None


def compat_identifier(args: dict[str, Any]) -> str | None:
    return first_present(args, "entity_id", "identifier", "id", "name", "slug")


def call_upstream_compat_tool(name: str, args: dict[str, Any]) -> Any:
    identifier = compat_identifier(args)
    if name in ("ha_get_state", "ha_get_entity"):
        if not identifier:
            raise ValueError("entity_id or identifier is required")
        return get_entity({"entity_id": identifier, "fields": args.get("fields"), "detailed": bool(args.get("detailed", True))})
    if name == "ha_search":
        query = str(args.get("query") or "")
        return {"entities": search_entities(query, int(args.get("limit") or 20)), "tools": search_tools(query, 10)}
    if name == "ha_get_overview":
        return system_overview()
    if name == "ha_get_system_health":
        return {
            "overview": system_overview(),
            "reload_readiness": check_reload_readiness(),
            "logs": get_error_log({"level": "ERROR", "lines": 50}),
        }
    if name == "ha_restart":
        if not bool(args.get("force")):
            raise ValueError("ha_restart requires force=true")
        result = supervisor_request("POST", "/core/restart")
        audit_event("ha_restart", {"result": result})
        return result
    if name == "ha_reload_core":
        result = ha_request("POST", "/services/homeassistant/reload_core_config")
        audit_event("ha_reload_core", {"result": result})
        return result
    if name == "ha_eval_template":
        template = args.get("template") or args.get("content")
        if not template:
            raise ValueError("template is required")
        return ha_request("POST", "/template", {"template": template})
    if name == "ha_call_service":
        domain = args.get("domain")
        service = args.get("service") or args.get("action")
        if not domain or not service:
            raise ValueError("domain and service are required")
        return ha_request("POST", f"/services/{domain}/{service}", args.get("data") or {})
    if name == "ha_call_event":
        event_type = args.get("event_type") or args.get("name") or args.get("event")
        if not event_type:
            raise ValueError("event_type/name is required")
        return ha_request("POST", f"/events/{event_type}", args.get("data") or {})
    if name == "ha_bulk_control":
        operations = args.get("operations") or []
        if not isinstance(operations, list):
            raise ValueError("operations must be a list")
        return {"results": [call_upstream_compat_tool("ha_call_service", operation) for operation in operations]}
    if name == "ha_list_services":
        return ha_request("GET", "/services")
    if name == "ha_get_logs":
        return get_error_log(args)
    if name == "ha_get_history":
        if args.get("start_time"):
            return get_history_range(args)
        if not identifier:
            raise ValueError("entity_id or identifier is required")
        hours = int(args.get("hours") or 24)
        end = datetime.now(timezone.utc)
        start = end - timedelta(hours=hours)
        return flatten_history(identifier, ha_request("GET", history_endpoint(start, end, identifier)))
    if name == "ha_get_automation_traces":
        entity_id = identifier
        if not entity_id:
            raise ValueError("entity_id or identifier is required")
        automation_id = entity_id.removeprefix("automation.")
        return ha_request("GET", f"/config/automation/trace/{automation_id}")
    if name == "ha_get_operation_status":
        return {"core": supervisor_request("GET", "/core/info"), "supervisor": supervisor_request("GET", "/supervisor/info")}
    if name == "ha_get_addon":
        slug = args.get("slug") or identifier
        if not slug:
            raise ValueError("slug is required")
        return supervisor_request("GET", f"/addons/{slug}/info")
    if name == "ha_manage_addon":
        slug = args.get("slug") or identifier
        action = args.get("action")
        if not slug:
            raise ValueError("slug is required")
        if action in {"start", "stop", "restart", "rebuild", "update", "install", "uninstall"}:
            return supervisor_request("POST", f"/addons/{slug}/{action}")
        if action == "get" or not action:
            return supervisor_request("GET", f"/addons/{slug}/info")
        return supervisor_request("POST", f"/addons/{slug}/{action}", args.get("data"))
    if name in ("ha_list_files", "ha_read_file", "ha_write_file", "ha_delete_file"):
        path = args.get("path") or "."
        if name == "ha_list_files":
            return list_config_files({"path": path, "recursive": bool(args.get("recursive")), "limit": int(args.get("limit") or 500)})
        if name == "ha_read_file":
            content, truncated = read_limited(config_path(path), int(args.get("max_bytes") or MAX_READ_BYTES))
            return {"path": path, "content": content, "truncated": truncated}
        if name == "ha_write_file":
            return write_config_file({
                "path": path,
                "content": args.get("content") or "",
                "backup": bool(args.get("backup", True)),
                "check_config": bool(args.get("check_config", False)),
                "dry_run": bool(args.get("dry_run")),
                "expected_hash": args.get("expected_hash"),
            })
        target = config_path(path)
        require_force_for_path(target, args, "ha_delete_file")
        if bool(args.get("dry_run")):
            return {"path": str(target), "deleted": False, "dry_run": True, "exists": target.exists()}
        if target.is_dir():
            shutil.rmtree(target)
        else:
            target.unlink()
        audit_event("ha_delete_file", {"path": str(target)})
        return {"path": str(target), "deleted": True}
    if name == "ha_config_set_yaml":
        path = args.get("path") or "configuration.yaml"
        return write_config_file({
            "path": path,
            "content": args.get("content") or json.dumps(args.get("config") or {}, indent=2),
            "backup": bool(args.get("backup", True)),
            "check_config": bool(args.get("check_config", True)),
            "dry_run": bool(args.get("dry_run")),
            "expected_hash": args.get("expected_hash"),
        })
    if name in ("ha_config_get_dashboard", "ha_config_set_dashboard", "ha_config_delete_dashboard"):
        dash_args = {
            "id": args.get("dashboard_id") or args.get("id") or args.get("identifier"),
            "url_path": args.get("url_path"),
            "key": args.get("key"),
            "config": args.get("config"),
            "data": args.get("data"),
            "content": args.get("content"),
            "title": args.get("title"),
            "create": bool(args.get("create", True)),
            "backup": bool(args.get("backup", True)),
            "dry_run": bool(args.get("dry_run")),
            "force": bool(args.get("force")),
            "expected_hash": args.get("expected_hash"),
        }
        if name == "ha_config_get_dashboard":
            return get_lovelace_dashboard(dash_args, int(args.get("max_bytes") or MAX_READ_BYTES))
        if name == "ha_config_set_dashboard":
            return save_lovelace_dashboard(dash_args)
        return delete_lovelace_dashboard(dash_args)
    if name == "ha_config_list_dashboard_resources":
        return read_storage_key("lovelace_resources", MAX_READ_BYTES)
    if name in ("ha_config_set_dashboard_resource", "ha_config_delete_dashboard_resource"):
        resources = load_storage_json("lovelace_resources")
        resources.setdefault("data", {}).setdefault("items", [])
        item_id = args.get("id") or args.get("url") or args.get("resource_id")
        if name == "ha_config_delete_dashboard_resource":
            if not bool(args.get("force")):
                raise ValueError("ha_config_delete_dashboard_resource requires force=true")
            if bool(args.get("dry_run")):
                matches = [item for item in resources["data"]["items"] if item.get("id") == item_id or item.get("url") == item_id]
                return {"resource": item_id, "matches": matches, "dry_run": True}
            resources["data"]["items"] = [item for item in resources["data"]["items"] if item.get("id") != item_id and item.get("url") != item_id]
        else:
            if bool(args.get("dry_run")):
                return {"resource": args.get("resource") or args.get("data") or {"id": item_id, "url": args.get("url"), "type": args.get("type")}, "dry_run": True}
            item = args.get("resource") or args.get("data") or {"id": item_id, "url": args.get("url"), "type": args.get("type")}
            resources["data"]["items"] = [old for old in resources["data"]["items"] if old.get("id") != item.get("id") and old.get("url") != item.get("url")]
            resources["data"]["items"].append(item)
        return dump_storage_json("lovelace_resources", resources)
    if name == "ha_get_device":
        if identifier:
            return search_device_registry({"id": identifier, "query": identifier, "limit": 20})
        return search_device_registry({"query": args.get("query") or "", "limit": int(args.get("limit") or 20)})
    if name in ("ha_set_device", "ha_remove_device"):
        return {"note": "Use search_device_registry plus patch_storage_json_path on core.device_registry for exact device registry edits.", "args": args}
    if name in ("ha_get_integration", "ha_set_integration_enabled"):
        domain = args.get("domain") or identifier
        if name == "ha_get_integration":
            return search_config_entries({"domain": domain, "query": args.get("query"), "limit": int(args.get("limit") or 20)})
        return {"note": "Integration enable/disable is available through raw storage/API tools; refusing to guess config-entry mutation shape.", "matching_entries": search_config_entries({"domain": domain, "limit": 20})}
    if name in ("ha_list_floors_areas", "ha_set_area_or_floor", "ha_remove_area_or_floor"):
        if name == "ha_list_floors_areas":
            return {
                "areas": search_named_registry("core.area_registry", "areas", {"limit": 10000}),
                "floors": search_named_registry("core.floor_registry", "floors", {"limit": 10000}),
            }
        registry_key = "core.floor_registry" if args.get("kind") == "floor" else "core.area_registry"
        list_name = "floors" if args.get("kind") == "floor" else "areas"
        return patch_named_registry(registry_key, list_name, args, remove=name.startswith("ha_remove"))
    if name in ("ha_config_get_label", "ha_config_set_label", "ha_config_remove_label", "ha_config_get_category", "ha_config_set_category", "ha_config_remove_category"):
        is_label = "label" in name
        registry_key = "core.label_registry" if is_label else "core.category_registry"
        list_name = "labels" if is_label else "categories"
        if "_get_" in name:
            return search_named_registry(registry_key, list_name, {"id": identifier, "name": args.get("name"), "query": args.get("query"), "limit": int(args.get("limit") or 20)})
        return patch_named_registry(registry_key, list_name, args, remove="_remove_" in name)
    if name in ("ha_config_get_automation", "ha_config_get_script", "ha_config_get_scene"):
        domain = {"ha_config_get_automation": "automation", "ha_config_get_script": "script", "ha_config_get_scene": "scene"}[name]
        return ha_request("GET", f"/config/{domain}/config/{identifier}") if identifier else list_entities({"domain": domain, "detailed": True, "limit": 10000})
    if name in ("ha_config_set_automation", "ha_config_set_script", "ha_config_set_scene"):
        domain = "automation" if "automation" in name else "script" if "script" in name else "scene"
        return ha_request("POST", f"/config/{domain}/config/{identifier or args.get('id')}", args.get("config") or args.get("data") or {})
    if name in ("ha_config_remove_automation", "ha_config_remove_script", "ha_config_remove_scene"):
        domain = "automation" if "automation" in name else "script" if "script" in name else "scene"
        return ha_request("DELETE", f"/config/{domain}/config/{identifier}")
    if name == "ha_manage_backup":
        action = args.get("action") or "list"
        if action == "list":
            return supervisor_request("GET", "/backups")
        if action in {"create", "new", "full"}:
            return supervisor_request("POST", "/backups/new/full", args.get("data") or {})
        slug = args.get("slug") or identifier
        if action == "info" and slug:
            return supervisor_request("GET", f"/backups/{slug}/info")
        return supervisor_request("POST", f"/backups/{slug}/{action}", args.get("data") or {})
    if name == "ha_get_updates":
        return {"core": supervisor_request("GET", "/core/info"), "store": supervisor_request("GET", "/store")}
    if name in ("ha_get_hacs_info", "ha_manage_hacs"):
        return {"note": "HACS can be controlled through ha_api/supervisor_api/http_request; no dedicated HACS REST contract is assumed.", "hacs_entries": search_config_entries({"domain": "hacs", "limit": 20})}
    if name in ("ha_get_zone", "ha_remove_zone", "ha_set_zone"):
        return ha_request("GET", "/states/zone") if name == "ha_get_zone" and not identifier else {"note": "Use storage/API primitives for zone mutation.", "args": args}
    if name in ("ha_get_todo", "ha_remove_todo_item", "ha_set_todo_item"):
        if name == "ha_get_todo":
            return ha_request("GET", f"/states/{identifier}") if identifier else list_entities({"domain": "todo", "detailed": True, "limit": 10000})
        return ha_request("POST", f"/services/todo/{'remove_item' if 'remove' in name else 'add_item'}", args.get("data") or {})
    if name == "ha_get_camera_image":
        entity_id = identifier
        if not entity_id:
            raise ValueError("entity_id is required")
        return ha_request("GET", f"/camera_proxy/{entity_id}")
    if name == "ha_manage_theme":
        return {"themes": search_files({"path": str(CONFIG_ROOT), "filename": "*.yaml", "query": args.get("query") or "frontend:", "recursive": True, "limit": int(args.get("limit") or 50)})}
    if name == "ha_report_issue":
        return {"title": args.get("title"), "body": args.get("body") or args.get("content"), "system_overview": system_overview()}
    if name in ("ha_install_mcp_tools", "ha_manage_pipeline", "ha_manage_energy_prefs", "ha_config_list_groups", "ha_config_set_group", "ha_config_remove_group", "ha_config_list_helpers", "ha_config_set_helper", "ha_remove_helpers_integrations", "ha_get_blueprint", "ha_import_blueprint", "ha_config_get_calendar_events", "ha_config_set_calendar_event", "ha_config_remove_calendar_event", "ha_get_dashboard_screenshot", "ha_manage_custom_tool", "ha_get_entity_exposure", "ha_set_entity", "ha_remove_entity"):
        return {
            "note": "Compatibility shim present. Use this app's full-access primitives for exact execution when this high-level upstream workflow needs HA-specific payload details.",
            "recommended_tools": ["ha_api", "supervisor_api", "http_request", "read_storage_json_path", "patch_storage_json_path", "run_command"],
            "args": args,
        }
    raise ValueError(f"Unhandled upstream compatibility tool: {name}")


def patch_named_registry(registry_key: str, list_name: str, args: dict[str, Any], remove: bool = False) -> dict[str, Any]:
    data = load_storage_json(registry_key)
    items = data.setdefault("data", {}).setdefault(list_name, [])
    identifier = args.get("id") or args.get("identifier") or args.get("name")
    if remove:
        before = len(items)
        data["data"][list_name] = [item for item in items if item.get("id") != identifier and item.get("name") != identifier]
        info = dump_storage_json(registry_key, data)
        return {"removed": before - len(data["data"][list_name]), "storage": info}
    item = args.get("data") or args.get("config") or {}
    if not item:
        item = {"id": args.get("id") or make_dashboard_id(str(args.get("name") or "")), "name": args.get("name")}
    items[:] = [old for old in items if old.get("id") != item.get("id")]
    items.append(item)
    return dump_storage_json(registry_key, data)


def glob_paths(pattern: str, limit: int) -> list[dict[str, Any]]:
    rows = []
    for match in glob.iglob(pattern, recursive=True):
        if len(rows) >= limit:
            break
        path = Path(match)
        rows.append(path_info(path) if path.exists() or path.is_symlink() else {"path": str(path), "exists": False})
    return rows


def hash_file(path: Path, algorithm: str) -> dict[str, Any]:
    digest = hashlib.new(algorithm)
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return {"path": str(path), "algorithm": algorithm, "hexdigest": digest.hexdigest(), "size": path.stat().st_size}


def read_file_window(path: Path, offset: int, length: int) -> dict[str, Any]:
    size = path.stat().st_size
    offset = max(0, min(offset, size))
    with path.open("rb") as handle:
        handle.seek(offset)
        data = handle.read(length)
    return {
        "path": str(path),
        "offset": offset,
        "length": len(data),
        "size": size,
        "next_offset": offset + len(data),
        "has_more": offset + len(data) < size,
        "content": data.decode("utf-8", errors="replace"),
    }


def read_file_lines(path: Path, start_line: int, line_count: int) -> dict[str, Any]:
    rows = []
    end_line = start_line + line_count - 1
    total = 0
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for number, line in enumerate(handle, 1):
            total = number
            if number < start_line:
                continue
            if number > end_line:
                break
            rows.append({"line": number, "text": line.rstrip("\n\r")})
    return {"path": str(path), "start_line": start_line, "line_count": len(rows), "total_lines_seen": total, "has_more": total > end_line, "lines": rows}


def search_files(args: dict[str, Any]) -> list[dict[str, Any]]:
    root = Path(args["path"])
    query = str(args.get("query") or "").lower()
    filename = args.get("filename")
    recursive = bool(args.get("recursive", True))
    limit = int(args.get("limit") or 100)
    max_file_bytes = int(args.get("max_file_bytes") or 2_000_000)
    iterator = root.rglob("*") if recursive else root.iterdir()
    matches: list[dict[str, Any]] = []
    for path in iterator:
        if len(matches) >= limit:
            break
        try:
            if filename and fnmatch.fnmatch(path.name, filename):
                matches.append({"path": str(path), "match": "filename"})
                continue
            if not query or not path.is_file() or path.stat().st_size > max_file_bytes:
                continue
            if path.suffix.lower() not in TEXT_EXTENSIONS:
                continue
            for line_number, line in enumerate(path.read_text(errors="replace").splitlines(), 1):
                if query in line.lower():
                    matches.append({"path": str(path), "line": line_number, "text": line[:500]})
                    break
        except OSError as err:
            matches.append({"path": str(path), "error": str(err)})
    return matches


def backup_path(path: Path, label: str | None) -> dict[str, Any]:
    DEFAULT_BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    safe_label = "".join(ch if ch.isalnum() or ch in "-_" else "_" for ch in (label or path.name or "path"))
    destination = DEFAULT_BACKUP_DIR / f"{safe_label}-{stamp}"
    if path.is_dir():
        shutil.copytree(path, destination, symlinks=True)
    else:
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, destination)
    return {"source": str(path), "backup": str(destination)}


def config_path(path: str) -> Path:
    if not path or path == ".":
        return CONFIG_ROOT.resolve()
    candidate = Path(path)
    if candidate.is_absolute():
        raise ValueError("Config file paths must be relative to /config")
    root = CONFIG_ROOT.resolve()
    target = (CONFIG_ROOT / candidate).resolve()
    if target != root and root not in target.parents:
        raise ValueError("Config path escapes /config")
    return target


def list_config_files(args: dict[str, Any]) -> dict[str, Any]:
    root = config_path(args.get("path") or ".")
    pattern = args.get("pattern") or "*"
    recursive = bool(args.get("recursive", False))
    limit = int(args.get("limit") or 500)
    iterator = root.rglob(pattern) if recursive else root.glob(pattern)
    rows = []
    for path in iterator:
        if len(rows) >= limit:
            break
        try:
            rows.append(path_info(path) | {"relative_path": str(path.relative_to(CONFIG_ROOT))})
        except OSError as err:
            rows.append({"path": str(path), "error": str(err)})
    return {"root": str(root), "count": len(rows), "files": rows}


def write_config_file(args: dict[str, Any]) -> dict[str, Any]:
    path = config_path(args["path"])
    require_expected_hash(path, args.get("expected_hash"))
    if bool(args.get("dry_run")):
        return {
            "path": str(path),
            "relative_path": args["path"],
            "dry_run": True,
            "would_write_bytes": len(args["content"].encode()),
            "current_hash": path_hash(path),
            "would_backup": bool(path.exists() and args.get("backup", True)),
            "would_check_config": bool(args.get("check_config", False)),
        }
    backup = None
    if path.exists() and bool(args.get("backup", True)):
        backup = backup_path(path, args["path"])
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(args["content"])
    if args.get("mode"):
        path.chmod(int(str(args["mode"]), 8))
    result: dict[str, Any] = path_info(path) | {"relative_path": args["path"], "backup": backup}
    if bool(args.get("check_config", False)):
        result["check_config"] = supervisor_request("POST", "/core/check")
    audit_event("write_config_file", {"path": str(path), "backup": backup, "check_config": bool(args.get("check_config", False))})
    return result


def patch_config_text(args: dict[str, Any]) -> dict[str, Any]:
    path = config_path(args["path"])
    require_expected_hash(path, args.get("expected_hash"))
    before_text = path.read_text(encoding="utf-8", errors="replace")
    search = str(args["search"])
    replace = str(args["replace"])
    count = int(args.get("count") if args.get("count") is not None else 0)
    if bool(args.get("regex")):
        after_text, changed = re.subn(search, replace, before_text, count=count)
    else:
        changed = before_text.count(search) if count == 0 else min(before_text.count(search), count)
        after_text = before_text.replace(search, replace) if count == 0 else before_text.replace(search, replace, count)
    expected = args.get("expected_count")
    if expected is not None and changed != int(expected):
        raise ValueError(f"expected_count mismatch for {path}: expected {expected}, actual {changed}")
    before_hash = path_hash(path)
    result = {
        "path": str(path),
        "relative_path": args["path"],
        "changed_count": changed,
        "before_hash": before_hash,
        "after_hash": hashlib.sha256(after_text.encode()).hexdigest(),
        "dry_run": bool(args.get("dry_run")),
        "would_backup": bool(path.exists() and args.get("backup", True)),
        "would_check_config": bool(args.get("check_config", False)),
    }
    if bool(args.get("dry_run")):
        return result
    backup = backup_path(path, args.get("label") or args["path"]) if bool(args.get("backup", True)) else None
    path.write_text(after_text, encoding="utf-8")
    result["backup"] = backup
    if bool(args.get("check_config", False)):
        result["check_config"] = supervisor_request("POST", "/core/check")
    audit_event("patch_config_text", {"path": str(path), "changed_count": changed, "backup": backup, "check_config": bool(args.get("check_config", False))})
    return result


def ensure_config_block(args: dict[str, Any]) -> dict[str, Any]:
    path = config_path(args["path"])
    require_expected_hash(path, args.get("expected_hash"))
    name = str(args["name"])
    start = f"# BEGIN HA-ADMIN-MCP {name}"
    end = f"# END HA-ADMIN-MCP {name}"
    text = path.read_text(encoding="utf-8", errors="replace") if path.exists() else ""
    pattern = re.compile(rf"(?ms)^# BEGIN HA-ADMIN-MCP {re.escape(name)}\n.*?^# END HA-ADMIN-MCP {re.escape(name)}\n?")
    block = "" if bool(args.get("remove")) else f"{start}\n{str(args.get('content') or '').rstrip()}\n{end}\n"
    matches = list(pattern.finditer(text))
    if matches:
        after = pattern.sub(block, text, count=1)
        action = "removed" if args.get("remove") else "replaced"
    elif args.get("remove"):
        after = text
        action = "missing"
    else:
        separator = "" if not text or text.endswith("\n") else "\n"
        after = text + separator + block
        action = "added"
    result = {
        "path": str(path),
        "relative_path": args["path"],
        "name": name,
        "action": action,
        "dry_run": bool(args.get("dry_run")),
        "before_hash": path_hash(path),
        "after_hash": hashlib.sha256(after.encode()).hexdigest(),
    }
    if bool(args.get("dry_run")):
        return result
    backup = backup_path(path, args.get("label") or args["path"]) if path.exists() and bool(args.get("backup", True)) else None
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(after, encoding="utf-8")
    result["backup"] = backup
    if bool(args.get("check_config", False)):
        result["check_config"] = run_config_check()
    audit_event("ensure_config_block", {"path": str(path), "name": name, "action": action, "backup": backup})
    return result


def package_path(path: str) -> Path:
    candidate = Path(path)
    if candidate.is_absolute():
        raise ValueError("Package paths must be relative to /config/packages")
    root = config_path("packages")
    target = (root / candidate).resolve()
    if target != root and root not in target.parents:
        raise ValueError("Package path escapes /config/packages")
    return target


def list_packages(recursive: bool) -> dict[str, Any]:
    root = config_path("packages")
    if not root.exists():
        return {"root": str(root), "count": 0, "packages": []}
    iterator = root.rglob("*") if recursive else root.glob("*")
    rows = []
    for path in iterator:
        if path.is_file() and path.suffix.lower() in (".yaml", ".yml"):
            rows.append(path_info(path) | {"package_path": str(path.relative_to(root))})
    return {"root": str(root), "count": len(rows), "packages": rows}


def secret_path() -> Path:
    return config_path("secrets.yaml")


def parse_secret_lines() -> tuple[Path, list[str]]:
    path = secret_path()
    if not path.exists():
        return path, []
    return path, path.read_text(encoding="utf-8", errors="replace").splitlines()


def secret_line_pattern(name: str) -> re.Pattern[str]:
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", name):
        raise ValueError("Secret names may contain only letters, numbers, dot, underscore, and dash")
    return re.compile(rf"^({re.escape(name)}\s*:\s*)(.*)$")


def list_secrets() -> dict[str, Any]:
    path, lines = parse_secret_lines()
    names = []
    for line in lines:
        match = re.match(r"^([A-Za-z0-9_.-]+)\s*:", line)
        if match:
            names.append(match.group(1))
    return {"path": str(path), "count": len(names), "secrets": sorted(names)}


def get_secret(name: str) -> dict[str, Any]:
    path, lines = parse_secret_lines()
    pattern = secret_line_pattern(name)
    for line in lines:
        match = pattern.match(line)
        if match:
            return {"path": str(path), "name": name, "value": match.group(2).strip()}
    raise ValueError(f"Secret not found: {name}")


def set_secret(args: dict[str, Any]) -> dict[str, Any]:
    path, lines = parse_secret_lines()
    require_expected_hash(path, args.get("expected_hash"))
    name = str(args["name"])
    value = str(args["value"])
    pattern = secret_line_pattern(name)
    changed = False
    after_lines = []
    for line in lines:
        if pattern.match(line):
            after_lines.append(f"{name}: {value}")
            changed = True
        else:
            after_lines.append(line)
    if not changed:
        after_lines.append(f"{name}: {value}")
    after = "\n".join(after_lines).rstrip() + "\n"
    result = {"path": str(path), "name": name, "action": "updated" if changed else "created", "dry_run": bool(args.get("dry_run")), "current_hash": path_hash(path)}
    if bool(args.get("dry_run")):
        return result
    backup = backup_path(path, "secrets.yaml") if path.exists() and bool(args.get("backup", True)) else None
    path.write_text(after, encoding="utf-8")
    audit_event("set_secret", {"name": name, "backup": backup})
    return result | {"backup": backup}


def delete_secret(args: dict[str, Any]) -> dict[str, Any]:
    if not bool(args.get("force")):
        raise ValueError("delete_secret requires force=true")
    path, lines = parse_secret_lines()
    require_expected_hash(path, args.get("expected_hash"))
    name = str(args["name"])
    pattern = secret_line_pattern(name)
    after_lines = [line for line in lines if not pattern.match(line)]
    removed = len(after_lines) != len(lines)
    result = {"path": str(path), "name": name, "removed": removed, "dry_run": bool(args.get("dry_run")), "current_hash": path_hash(path)}
    if bool(args.get("dry_run")):
        return result
    backup = backup_path(path, "secrets.yaml") if path.exists() and bool(args.get("backup", True)) else None
    path.write_text(("\n".join(after_lines).rstrip() + "\n") if after_lines else "", encoding="utf-8")
    audit_event("delete_secret", {"name": name, "removed": removed, "backup": backup})
    return result | {"backup": backup}


def tail_log(args: dict[str, Any]) -> dict[str, Any]:
    explicit_path = bool(args.get("path"))
    raw_path = args.get("path") or "/config/home-assistant.log"
    path = Path(raw_path)
    if not path.is_absolute():
        path = config_path(raw_path)
    if not path.exists() and not explicit_path:
        candidates = [candidate for candidate in CONFIG_ROOT.glob("*.log*") if candidate.is_file()]
        if not candidates:
            return {"path": str(path), "exists": False, "lines": [], "line_count": 0, "candidates": []}
        path = max(candidates, key=lambda candidate: candidate.stat().st_mtime)
    lines = int(args.get("lines") or 200)
    max_bytes = int(args.get("max_bytes") or 2_000_000)
    size = path.stat().st_size
    with path.open("rb") as handle:
        if size > max_bytes:
            handle.seek(size - max_bytes)
            truncated = True
        else:
            truncated = False
        data = handle.read(max_bytes)
    text = data.decode("utf-8", errors="replace")
    tail = text.splitlines()[-lines:]
    return {"path": str(path), "lines": tail, "line_count": len(tail), "truncated_from_start": truncated}


def check_reload_readiness() -> dict[str, Any]:
    check = run_config_check()
    services = ha_request("GET", "/services")
    reloads = []
    for domain in services:
        domain_name = domain.get("domain")
        for service in domain.get("services", {}):
            if service.startswith("reload"):
                reloads.append({"domain": domain_name, "service": service})
    return {"check_config": check, "reload_services": reloads}


def run_config_check(retries: int = 3, delay: float = 2.0) -> Any:
    last_error: Exception | None = None
    for attempt in range(retries + 1):
        try:
            return supervisor_request("POST", "/core/check")
        except RuntimeError as err:
            last_error = err
            if "Another job is running" not in str(err) or attempt >= retries:
                raise
            time.sleep(delay)
    raise last_error or RuntimeError("config check failed")


def emulate_ha_cli(argv: list[str]) -> Any:
    if not argv:
        return {"supported": ["core", "supervisor", "host", "addons", "apps", "store"], "note": "ha binary is not installed in this app image; common commands are emulated through Supervisor/API calls."}
    group = argv[0]
    rest = argv[1:]
    if group == "core":
        action = rest[0] if rest else "info"
        if action == "info":
            return supervisor_request("GET", "/core/info")
        if action == "check":
            return run_config_check()
        if action in {"restart", "stop", "start"}:
            return supervisor_request("POST", f"/core/{action}")
    if group == "supervisor":
        action = rest[0] if rest else "info"
        if action == "info":
            return supervisor_request("GET", "/supervisor/info")
    if group == "host":
        action = rest[0] if rest else "info"
        if action == "info":
            return supervisor_request("GET", "/host/info")
    if group == "store":
        action = rest[0] if rest else "info"
        if action == "reload":
            return supervisor_request("POST", "/store/reload")
        if action == "info":
            return supervisor_request("GET", "/store")
    if group in {"addons", "apps"}:
        if not rest:
            return supervisor_request("GET", "/addons")
        action = rest[0]
        if action in {"info", "logs", "start", "stop", "restart", "rebuild", "update", "install", "uninstall"} and len(rest) >= 2:
            slug = rest[1]
            method = "GET" if action in {"info", "logs"} else "POST"
            return supervisor_request(method, f"/addons/{slug}/{action}")
    raise ValueError(f"Unsupported emulated ha command: {' '.join(argv)}")


def ha_cli(args: dict[str, Any]) -> dict[str, Any]:
    argv = ["ha"] + [str(value) for value in (args.get("args") or [])]
    timeout = int(args.get("timeout") or OPTIONS.get("command_timeout_seconds") or 300)
    max_output = int(args.get("max_output_bytes") or 20000)
    audit_event("ha_cli", {"args": argv})
    if shutil.which("ha") is None:
        return {"args": argv, "emulated": True, "result": emulate_ha_cli(argv[1:])}
    completed = subprocess.run(argv, text=True, capture_output=True, timeout=timeout)
    return {
        "args": argv,
        "emulated": False,
        "returncode": completed.returncode,
        "stdout": completed.stdout[:max_output],
        "stderr": completed.stderr[:max_output],
        "stdout_truncated": len(completed.stdout) > max_output,
        "stderr_truncated": len(completed.stderr) > max_output,
    }


def check_config_and_reload(args: dict[str, Any]) -> dict[str, Any]:
    check = run_config_check()
    result: dict[str, Any] = {"check_config": check, "dry_run": bool(args.get("dry_run")), "reloads": []}
    check_payload = check.get("data", check) if isinstance(check, dict) else check
    if isinstance(check_payload, dict) and check_payload.get("result") not in (None, "valid"):
        result["skipped"] = "config check did not report valid"
        return result
    domains = [str(domain) for domain in (args.get("domains") or [])]
    services = args.get("services") or []
    if bool(args.get("reload_core")):
        services.append({"domain": "homeassistant", "service": "reload_core_config", "data": {}})
    for domain in domains:
        services.append({"domain": domain, "service": "reload", "data": {}})
    for service in services:
        domain = service.get("domain")
        service_name = service.get("service") or "reload"
        data = service.get("data") or {}
        row = {"domain": domain, "service": service_name, "data": data}
        if not args.get("dry_run"):
            row["result"] = ha_request("POST", f"/services/{domain}/{service_name}", data)
        result["reloads"].append(row)
    if result["reloads"] and not args.get("dry_run"):
        audit_event("check_config_and_reload", {"reloads": result["reloads"]})
    return result


def storage_path(key: str) -> Path:
    if "/" in key or "\\" in key:
        raise ValueError("Invalid storage key")
    return Path("/config/.storage") / key


def list_storage_keys(include_backups: bool) -> list[dict[str, Any]]:
    storage = Path("/config/.storage")
    rows = []
    for path in sorted(storage.iterdir()):
        if not include_backups and (".bak" in path.name or "backup" in path.name):
            continue
        rows.append(path_info(path) | {"key": path.name})
    return rows


def list_storage_keys_filtered(args: dict[str, Any]) -> dict[str, Any]:
    pattern = args.get("pattern") or "*"
    query = str(args.get("query") or "").lower()
    min_size = args.get("min_size")
    max_size = args.get("max_size")
    include_backups = bool(args.get("include_backups", False))
    limit = int(args.get("limit") or 500)
    rows = []
    for path in sorted(Path("/config/.storage").iterdir()):
        if len(rows) >= limit:
            break
        if not include_backups and (".bak" in path.name or "backup" in path.name):
            continue
        if not fnmatch.fnmatch(path.name, pattern):
            continue
        stat = path.stat()
        if min_size is not None and stat.st_size < int(min_size):
            continue
        if max_size is not None and stat.st_size > int(max_size):
            continue
        if query:
            content, _ = read_limited(path, min(stat.st_size, 5_000_000))
            if query not in path.name.lower() and query not in content.lower():
                continue
        rows.append(path_info(path) | {"key": path.name})
    return {"count": len(rows), "keys": rows}


def read_storage_key(key: str, max_bytes: int) -> dict[str, Any]:
    path = storage_path(key)
    content, truncated = read_limited(path, max_bytes)
    try:
        parsed: Any = json.loads(content)
    except json.JSONDecodeError:
        parsed = content
    return {"key": key, "path": str(path), "truncated": truncated, "data": parsed}


def write_storage_key(key: str, args: dict[str, Any]) -> dict[str, Any]:
    path = storage_path(key)
    require_expected_hash(path, args.get("expected_hash"))
    if bool(args.get("dry_run")):
        content = str(args["content"]) if "content" in args and args["content"] is not None else json.dumps(args.get("data"), indent=2, default=str)
        return {"key": key, "path": str(path), "dry_run": True, "would_write_bytes": len(content.encode()), "current_hash": path_hash(path), "would_backup": bool(path.exists() and args.get("backup", True))}
    backup = backup_path(path, args.get("label") or key) if path.exists() and bool(args.get("backup", True)) else None
    path.parent.mkdir(parents=True, exist_ok=True)
    if "content" in args and args["content"] is not None:
        path.write_text(str(args["content"]))
    else:
        path.write_text(json.dumps(args.get("data"), indent=2, default=str))
    if args.get("mode"):
        path.chmod(int(str(args["mode"]), 8))
    audit_event("write_storage_key", {"key": key, "path": str(path), "backup": backup})
    return path_info(path) | {"key": key, "backup": backup}


def search_storage_key(key: str, query: str, limit: int) -> list[dict[str, Any]]:
    path = storage_path(key)
    content, _ = read_limited(path, 100_000_000)
    matches = []
    needle = query.lower()
    for line_number, line in enumerate(content.splitlines(), 1):
        if needle in line.lower():
            matches.append({"line": line_number, "text": line[:1000]})
            if len(matches) >= limit:
                break
    return matches


def compact_value(value: Any, max_chars: int = 500) -> Any:
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    text = json.dumps(value, default=str)
    if len(text) <= max_chars:
        return value
    return text[:max_chars] + "...<truncated>"


def json_matches(value: Any, needle: str, field: str | None, path: str = "$") -> list[dict[str, Any]]:
    matches: list[dict[str, Any]] = []
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{path}.{key}"
            key_match = needle in str(key).lower()
            value_match = needle in str(child).lower()
            field_match = field is None or key == field
            if field_match and (key_match or value_match):
                matches.append({"path": child_path, "key": key, "value": compact_value(child)})
            matches.extend(json_matches(child, needle, field, child_path))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            child_path = f"{path}[{index}]"
            if field is None and needle in str(child).lower():
                matches.append({"path": child_path, "value": compact_value(child)})
            matches.extend(json_matches(child, needle, field, child_path))
    return matches


def search_storage_json(args: dict[str, Any]) -> dict[str, Any]:
    key = args["key"]
    limit = int(args.get("limit") or 100)
    max_bytes = int(args.get("max_bytes") or MAX_READ_BYTES)
    content, truncated = read_limited(storage_path(key), max_bytes)
    data = json.loads(content)
    matches = json_matches(data, str(args["query"]).lower(), args.get("field"))
    return {"key": key, "truncated": truncated, "count": min(len(matches), limit), "matches": matches[:limit]}


def read_storage_json_path(key: str, path: str) -> dict[str, Any]:
    data = load_storage_json(key)
    return {"key": key, "path": path, "value": value_at_path(data, path)}


def read_storage_json_paths(key: str, paths: list[Any]) -> dict[str, Any]:
    data = load_storage_json(key)
    rows = []
    for path in paths:
        text_path = str(path)
        try:
            rows.append({"path": text_path, "value": value_at_path(data, text_path)})
        except Exception as err:
            rows.append({"path": text_path, "error": str(err)})
    return {"key": key, "count": len(rows), "values": rows}


def patch_storage_json_path(args: dict[str, Any]) -> dict[str, Any]:
    key = args["key"]
    storage_file = storage_path(key)
    require_expected_hash(storage_file, args.get("expected_hash"))
    data = load_storage_json(key)
    path = args["path"]
    target = value_at_path(data, path)
    before = json.loads(json.dumps(target, default=str))
    if args.get("replace") is not None:
        set_value_at_path(data, path, args["replace"])
        after = args["replace"]
    else:
        if not isinstance(target, dict):
            raise ValueError("Target path must be an object when using patch or remove_keys")
        for key_name in args.get("remove_keys") or []:
            target.pop(str(key_name), None)
        patch = args.get("patch") or {}
        if patch:
            if not isinstance(patch, dict):
                raise ValueError("patch must be an object")
            target.update(patch)
        after = json.loads(json.dumps(target, default=str))
    if bool(args.get("dry_run")):
        return {"key": key, "path": path, "dry_run": True, "before": before, "after": after, "current_hash": path_hash(storage_file)}
    backup = backup_path(storage_path(key), args.get("label") or key) if bool(args.get("backup", True)) and storage_path(key).exists() else None
    info = dump_storage_json(key, data)
    audit_event("patch_storage_json_path", {"key": key, "path": path, "backup": backup})
    return {"key": key, "path": path, "before": before, "after": after, "backup": backup, "storage": info}


def contains_text(value: Any, query: str) -> bool:
    return query.lower() in json.dumps(value, default=str).lower()


def field_equals(row: dict[str, Any], field: str, value: Any) -> bool:
    if value is None:
        return True
    return str(row.get(field) or "") == str(value)


def registry_search(key: str, list_name: str, args: dict[str, Any], fields: list[str]) -> dict[str, Any]:
    data = load_storage_json(key)
    rows = data.get("data", {}).get(list_name, [])
    query = str(args.get("query") or "").lower()
    limit = int(args.get("limit") or 100)
    matches = []
    for row in rows:
        if len(matches) >= limit:
            break
        if any(not field_equals(row, field, args.get(field)) for field in fields):
            continue
        if query and not contains_text(row, query):
            continue
        matches.append(row)
    return {"key": key, "count": len(matches), "matches": matches}


def text_field_contains(row: dict[str, Any], fields: list[str], value: str | None) -> bool:
    if value is None:
        return True
    needle = value.lower()
    return any(needle in str(row.get(field) or "").lower() for field in fields)


def search_entity_registry(args: dict[str, Any]) -> dict[str, Any]:
    data = load_storage_json("core.entity_registry")
    rows = data.get("data", {}).get("entities", [])
    query = str(args.get("query") or "").lower()
    domain = args.get("domain")
    limit = int(args.get("limit") or 100)
    matches = []
    for row in rows:
        if len(matches) >= limit:
            break
        if domain and str(row.get("entity_id", "")).split(".", 1)[0] != domain:
            continue
        if any(not field_equals(row, field, args.get(field)) for field in ["entity_id", "platform", "device_id", "area_id", "disabled_by", "hidden_by"]):
            continue
        if query and not contains_text(row, query):
            continue
        matches.append(row)
    return {"key": "core.entity_registry", "count": len(matches), "matches": matches}


def get_entity_registry_entry(args: dict[str, Any]) -> dict[str, Any]:
    data = load_storage_json("core.entity_registry")
    rows = data.get("data", {}).get("entities", [])
    for row in rows:
        if args.get("entity_id") and row.get("entity_id") == args["entity_id"]:
            return row
        if args.get("unique_id") and row.get("unique_id") == args["unique_id"]:
            return row
        if args.get("id") and row.get("id") == args["id"]:
            return row
    raise ValueError("Entity registry entry not found")


def patch_registry_entry(registry_key: str, list_name: str, args: dict[str, Any], selectors: list[str]) -> dict[str, Any]:
    path = storage_path(registry_key)
    require_expected_hash(path, args.get("expected_hash"))
    data = load_storage_json(registry_key)
    rows = data.get("data", {}).get(list_name, [])
    matches = []
    for index, row in enumerate(rows):
        for selector in selectors:
            wanted = args.get(selector)
            if wanted is not None and str(row.get(selector) or "") == str(wanted):
                matches.append((index, row))
                break
    if len(matches) != 1:
        raise ValueError(f"Expected exactly one {registry_key} match, found {len(matches)}")
    index, row = matches[0]
    before = json.loads(json.dumps(row, default=str))
    for key_name in args.get("remove_keys") or []:
        row.pop(str(key_name), None)
    patch = args.get("patch") or {}
    if patch:
        if not isinstance(patch, dict):
            raise ValueError("patch must be an object")
        row.update(patch)
    after = json.loads(json.dumps(row, default=str))
    if bool(args.get("dry_run")):
        return {"key": registry_key, "list": list_name, "index": index, "dry_run": True, "before": before, "after": after, "current_hash": path_hash(path)}
    backup = backup_path(path, args.get("label") or registry_key) if bool(args.get("backup", True)) else None
    info = dump_storage_json(registry_key, data)
    audit_event("patch_registry_entry", {"key": registry_key, "index": index, "backup": backup})
    return {"key": registry_key, "list": list_name, "index": index, "before": before, "after": after, "backup": backup, "storage": info}


def search_device_registry(args: dict[str, Any]) -> dict[str, Any]:
    data = load_storage_json("core.device_registry")
    rows = data.get("data", {}).get("devices", [])
    query = str(args.get("query") or "").lower()
    limit = int(args.get("limit") or 100)
    matches = []
    for row in rows:
        if len(matches) >= limit:
            break
        if any(not field_equals(row, field, args.get(field)) for field in ["id", "manufacturer", "model", "area_id"]):
            continue
        if not text_field_contains(row, ["name_by_user", "name", "model", "manufacturer"], args.get("name")):
            continue
        if query and not contains_text(row, query):
            continue
        matches.append(row)
    return {"key": "core.device_registry", "count": len(matches), "matches": matches}


def search_config_entries(args: dict[str, Any]) -> dict[str, Any]:
    data = load_storage_json("core.config_entries")
    rows = data.get("data", {}).get("entries", [])
    query = str(args.get("query") or "").lower()
    limit = int(args.get("limit") or 100)
    matches = []
    for row in rows:
        if len(matches) >= limit:
            break
        if any(not field_equals(row, field, args.get(field)) for field in ["entry_id", "domain", "source"]):
            continue
        if not text_field_contains(row, ["title"], args.get("title")):
            continue
        if query and not contains_text(row, query):
            continue
        matches.append(row)
    return {"key": "core.config_entries", "count": len(matches), "matches": matches}


def search_named_registry(key: str, list_name: str, args: dict[str, Any]) -> dict[str, Any]:
    data = load_storage_json(key)
    rows = data.get("data", {}).get(list_name, [])
    query = str(args.get("query") or "").lower()
    limit = int(args.get("limit") or 100)
    matches = []
    for row in rows:
        if len(matches) >= limit:
            break
        if args.get("id") and str(row.get("id") or "") != str(args["id"]):
            continue
        if args.get("name") and str(args["name"]).lower() not in str(row.get("name") or "").lower():
            continue
        if query and not contains_text(row, query):
            continue
        matches.append(row)
    return {"key": key, "count": len(matches), "matches": matches}


def sqlite_query(args: dict[str, Any]) -> dict[str, Any]:
    path = Path(args.get("path") or "/config/home-assistant_v2.db")
    query = str(args["query"]).strip()
    if not query:
        raise ValueError("query cannot be empty")
    allowed = ("select", "pragma", "with", "explain")
    if not query.lower().startswith(allowed):
        raise ValueError("Only read-only SQLite queries are allowed")
    limit = int(args.get("limit") or 100)
    timeout = int(args.get("timeout") or 30)
    uri = f"file:{urllib.parse.quote(str(path), safe='/:')}?mode=ro"
    start = time.time()
    with sqlite3.connect(uri, uri=True, timeout=timeout) as connection:
        connection.row_factory = sqlite3.Row
        cursor = connection.execute(query, args.get("parameters") or [])
        columns = [description[0] for description in cursor.description or []]
        rows = []
        for row in cursor:
            rows.append({column: row[column] for column in columns})
            if len(rows) >= limit:
                break
    return {"path": str(path), "columns": columns, "rows": rows, "count": len(rows), "limit": limit, "elapsed_seconds": round(time.time() - start, 3)}


def recorder_get_db_info() -> dict[str, Any]:
    path = Path("/config/home-assistant_v2.db")
    info: dict[str, Any] = {"path": str(path), "exists": path.exists()}
    if not path.exists():
        return info
    info.update(path_info(path))
    tables = sqlite_query({"path": str(path), "query": "select name from sqlite_master where type='table' order by name", "limit": 500})["rows"]
    table_names = [row["name"] for row in tables]
    counts: dict[str, Any] = {}
    for table in ("states", "states_meta", "events", "event_types", "statistics", "statistics_short_term", "statistics_meta"):
        if table in table_names:
            try:
                counts[table] = sqlite_query({"path": str(path), "query": f"select count(*) as count from {table}", "limit": 1})["rows"][0]["count"]
            except Exception as err:
                counts[table] = {"error": str(err)}
    info["tables"] = table_names
    info["counts"] = counts
    return info


def recorder_purge(args: dict[str, Any]) -> dict[str, Any]:
    data: dict[str, Any] = {}
    for key in ("keep_days", "repack", "apply_filter"):
        if args.get(key) is not None:
            data[key] = args[key]
    if bool(args.get("dry_run")):
        return {"service": "recorder.purge", "data": data, "dry_run": True}
    audit_event("recorder_purge", data)
    return ha_request("POST", "/services/recorder/purge", data)


def recorder_purge_entities(args: dict[str, Any]) -> dict[str, Any]:
    data: dict[str, Any] = {}
    for key in ("entity_id", "domains", "entity_globs", "keep_days"):
        if args.get(key) is not None:
            data[key] = args[key]
    if bool(args.get("dry_run")):
        return {"service": "recorder.purge_entities", "data": data, "dry_run": True}
    audit_event("recorder_purge_entities", data)
    return ha_request("POST", "/services/recorder/purge_entities", data)


def create_backup(args: dict[str, Any]) -> Any:
    data = {key: args[key] for key in ("name", "password", "folders", "addons", "homeassistant") if args.get(key) is not None}
    endpoint = "/backups/new/partial" if any(key in data for key in ("folders", "addons", "homeassistant")) else "/backups/new/full"
    audit_event("create_backup", {"endpoint": endpoint, "name": args.get("name")})
    return supervisor_request("POST", endpoint, data)


def delete_backup(args: dict[str, Any]) -> dict[str, Any]:
    if not bool(args.get("force")):
        raise ValueError("delete_backup requires force=true")
    if bool(args.get("dry_run")):
        return {"slug": args["slug"], "dry_run": True, "would_delete": True}
    result = supervisor_request("POST", f"/backups/{args['slug']}/remove")
    audit_event("delete_backup", {"slug": args["slug"], "result": result})
    return {"slug": args["slug"], "deleted": True, "result": result}


def restore_backup(args: dict[str, Any]) -> dict[str, Any]:
    if not bool(args.get("force")):
        raise ValueError("restore_backup requires force=true")
    data = {key: args[key] for key in ("password", "folders", "addons", "homeassistant") if args.get(key) is not None}
    endpoint = f"/backups/{args['slug']}/restore/partial" if bool(args.get("partial")) else f"/backups/{args['slug']}/restore/full"
    if bool(args.get("dry_run")):
        return {"slug": args["slug"], "endpoint": endpoint, "data": data, "dry_run": True}
    result = supervisor_request("POST", endpoint, data)
    audit_event("restore_backup", {"slug": args["slug"], "endpoint": endpoint, "result": result})
    return {"slug": args["slug"], "endpoint": endpoint, "restored": True, "result": result}


def parse_time(value: str | None) -> datetime:
    if not value:
        return datetime.now(timezone.utc)
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    parsed = datetime.fromisoformat(text)
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def history_endpoint(start: datetime, end: datetime, entity_id: str) -> str:
    endpoint = f"/history/period/{urllib.parse.quote(start.isoformat(), safe=':TZ+-')}"
    return maybe_query(endpoint, {"filter_entity_id": entity_id, "minimal_response": "true", "end_time": end.isoformat()})


def flatten_history(entity_id: str, history_data: Any) -> dict[str, Any]:
    states = []
    if isinstance(history_data, list):
        for bucket in history_data:
            if isinstance(bucket, list):
                states.extend(bucket)
    states.sort(key=lambda row: row.get("last_changed", ""))
    return {
        "entity_id": entity_id,
        "states": states,
        "count": len(states),
        "first_changed": states[0].get("last_changed") if states else None,
        "last_changed": states[-1].get("last_changed") if states else None,
    }


def get_history_range(args: dict[str, Any]) -> dict[str, Any]:
    start = parse_time(args["start_time"])
    end = parse_time(args.get("end_time"))
    if start >= end:
        raise ValueError("start_time must be before end_time")
    return flatten_history(args["entity_id"], ha_request("GET", history_endpoint(start, end, args["entity_id"])))


def sqlite_columns(path: Path, table: str) -> set[str]:
    result = sqlite_query({"path": str(path), "query": f"pragma table_info({table})", "limit": 100})
    return {row["name"] for row in result["rows"]}


def get_statistics_range(args: dict[str, Any]) -> dict[str, Any]:
    entity_id = args["entity_id"]
    start = parse_time(args["start_time"])
    end = parse_time(args.get("end_time"))
    if start >= end:
        raise ValueError("start_time must be before end_time")
    path = Path("/config/home-assistant_v2.db")
    stat_cols = sqlite_columns(path, "statistics")
    meta_id_col = "metadata_id"
    start_col = "start_ts" if "start_ts" in stat_cols else "start"
    use_ts = start_col.endswith("_ts")
    start_value: Any = start.timestamp() if use_ts else start.isoformat()
    end_value: Any = end.timestamp() if use_ts else end.isoformat()
    period = args.get("period") or "hour"
    if period not in {"5minute", "hour", "day", "week", "month"}:
        raise ValueError("period must be one of 5minute, hour, day, week, month")
    table = "statistics_short_term" if period == "5minute" else "statistics"
    columns = sqlite_columns(path, table)
    start_col = "start_ts" if "start_ts" in columns else "start"
    select_cols = [column for column in (start_col, "mean", "min", "max", "state", "sum") if column in columns]
    query = (
        f"select {', '.join('s.' + column for column in select_cols)} "
        f"from {table} s join statistics_meta m on s.{meta_id_col} = m.id "
        f"where m.statistic_id = ? and s.{start_col} >= ? and s.{start_col} <= ? "
        f"order by s.{start_col}"
    )
    result = sqlite_query({"path": str(path), "query": query, "parameters": [entity_id, start_value, end_value], "limit": int(args.get("limit") or 1000)})
    return {"entity_id": entity_id, "period": period, "start_time": start.isoformat(), "end_time": end.isoformat(), "statistics": result["rows"], "count": result["count"]}


def get_statistics(args: dict[str, Any]) -> dict[str, Any]:
    hours = int(args.get("hours") or 24)
    end = datetime.now(timezone.utc)
    start = end - timedelta(hours=hours)
    range_args = dict(args)
    range_args["start_time"] = start.isoformat()
    range_args["end_time"] = end.isoformat()
    return get_statistics_range(range_args)


def get_error_log(args: dict[str, Any]) -> dict[str, Any]:
    try:
        raw = supervisor_request("GET", "/core/logs")
        text = raw.get("content", raw) if isinstance(raw, dict) else raw
    except Exception:
        try:
            raw = ha_request("GET", "/error_log")
            text = raw.get("content", raw) if isinstance(raw, dict) else raw
        except Exception as err:
            return {"error": str(err), "log_text": "", "error_count": 0, "warning_count": 0, "integration_mentions": {}}
    clean = re.sub(r"\x1b\[[0-9;]*m", "", str(text))
    rows = clean.splitlines()
    if args.get("level"):
        needle = str(args["level"]).upper()
        rows = [row for row in rows if needle in row.upper()]
    if args.get("integration"):
        needle = str(args["integration"]).lower()
        bare = f"[{needle}]"
        namespaced = f"[homeassistant.components.{needle}]"
        rows = [row for row in rows if bare in row.lower() or namespaced in row.lower()]
    if args.get("search_term"):
        needle = str(args["search_term"]).lower()
        rows = [row for row in rows if needle in row.lower()]
    if args.get("lines"):
        rows = rows[-int(args["lines"]) :]
    filtered = "\n".join(rows)
    mentions: dict[str, int] = {}
    for match in re.finditer(r"\[([a-zA-Z0-9_\.]+)\]", filtered):
        name = match.group(1).lower()
        if name.startswith("homeassistant.components."):
            name = name.split(".")[-1]
        mentions[name] = mentions.get(name, 0) + 1
    return {
        "log_text": filtered,
        "error_count": filtered.count("ERROR"),
        "warning_count": filtered.count("WARNING"),
        "integration_mentions": mentions,
        "total_lines": len(rows),
        "filters_applied": {key: value for key, value in args.items() if value not in (None, "")},
    }


def read_lovelace_dashboards(include_content: bool, max_bytes: int) -> dict[str, Any]:
    dashboards = []
    for path in sorted(Path("/config/.storage").glob("lovelace*")):
        row = path_info(path) | {"key": path.name}
        if include_content and path.is_file():
            content, truncated = read_limited(path, max_bytes)
            row["content"] = content
            row["truncated"] = truncated
        dashboards.append(row)
    return {"count": len(dashboards), "dashboards": dashboards}


def lovelace_url_path(args: dict[str, Any]) -> str | None:
    if args.get("url_path") is not None:
        value = str(args["url_path"])
        return value if value not in ("", "lovelace", "default") else None
    if args.get("dashboard_id"):
        registry, item = resolve_lovelace_dashboard({"id": args["dashboard_id"]})
        if item:
            value = str(item.get("url_path") or "")
            return value if value not in ("", "lovelace", "default") else None
    return None


def live_lovelace_get_config(args: dict[str, Any]) -> dict[str, Any]:
    message: dict[str, Any] = {"type": "lovelace/config"}
    url_path = lovelace_url_path(args)
    if url_path is not None:
        message["url_path"] = url_path
    return ha_ws_call(message)


def live_lovelace_config(args: dict[str, Any]) -> dict[str, Any]:
    response = live_lovelace_get_config(args)
    if not response.get("success"):
        raise ValueError(f"live Lovelace config read failed: {response}")
    config = response.get("result")
    if not isinstance(config, dict):
        raise ValueError("live Lovelace config result is not an object")
    return config


def live_lovelace_get_outline(args: dict[str, Any]) -> dict[str, Any]:
    config = live_lovelace_config(args)
    views = config.get("views")
    if not isinstance(views, list):
        raise ValueError("live Lovelace config does not contain views")
    rows = []
    for view_index, view in enumerate(views):
        if not isinstance(view, dict):
            rows.append({"index": view_index, "view": view})
            continue
        cards = []
        for row in iter_lovelace_cards(view, f"$.views[{view_index}]"):
            card_row = {"path": row["path"], "type": row.get("type"), "title": row.get("title")}
            if bool(args.get("include_entities", True)):
                card_row["entities"] = row.get("entities", [])
            cards.append(card_row)
        rows.append({"index": view_index, "path": f"$.views[{view_index}]", "title": view.get("title"), "view_path": view.get("path"), "type": view.get("type"), "card_count": len(view.get("cards") or []) if isinstance(view.get("cards"), list) else 0, "cards": cards})
    return {"preferred_path": True, "title": config.get("title"), "view_count": len(rows), "views": rows}


def live_lovelace_find_cards(args: dict[str, Any]) -> dict[str, Any]:
    config = live_lovelace_config(args)
    matches = live_lovelace_find_card_rows(config, args)
    return {"preferred_path": True, "count": len(matches), "matches": matches}


def live_lovelace_find_card_rows(config: dict[str, Any], args: dict[str, Any]) -> list[dict[str, Any]]:
    views = config.get("views")
    if not isinstance(views, list):
        raise ValueError("live Lovelace config does not contain views")
    wanted_view_index = args.get("view_index")
    wanted_view_title = args.get("view_title")
    limit = int(args.get("limit") or 100)
    matches = []
    for view_index, view in enumerate(views):
        if wanted_view_index is not None and view_index != int(wanted_view_index):
            continue
        if wanted_view_title and (not isinstance(view, dict) or str(view.get("title") or "") != wanted_view_title):
            continue
        for row in iter_lovelace_cards(view, f"$.views[{view_index}]"):
            if card_matches(row, args):
                matches.append(row)
                if len(matches) >= limit:
                    return matches
    return matches


def live_lovelace_get_card(args: dict[str, Any]) -> dict[str, Any]:
    config = live_lovelace_config(args)
    matches = live_lovelace_find_card_rows(config, args)
    expected = int(args.get("expected_matches") or 1)
    if len(matches) != expected:
        return {"preferred_path": True, "count": len(matches), "error": f"Expected {expected} card match(es), found {len(matches)}", "matches": matches}
    if expected != 1:
        raise ValueError("live_lovelace_get_card requires expected_matches=1")
    path = matches[0]["path"]
    return {"preferred_path": True, "path": path, "card": value_at_path(config, path)}


def live_lovelace_patch_card(args: dict[str, Any]) -> dict[str, Any]:
    if not bool(args.get("dry_run")) and not bool(args.get("force")):
        raise ValueError("live_lovelace_patch_card requires force=true")
    if args.get("patch") is None and args.get("replace") is None and not args.get("remove_keys"):
        raise ValueError("Pass patch, replace, or remove_keys")
    config = live_lovelace_config(args)
    matches = live_lovelace_find_card_rows(config, args)
    expected = int(args.get("expected_matches") or 1)
    if len(matches) != expected:
        return {"preferred_path": True, "changed": False, "error": f"Expected {expected} match(es), found {len(matches)}", "matches": matches}
    if expected != 1:
        raise ValueError("live_lovelace_patch_card requires expected_matches=1")
    path = matches[0]["path"]
    card = value_at_path(config, path)
    if not isinstance(card, dict):
        raise ValueError("Matched path is not a card object")
    before = json.loads(json.dumps(card, default=str))
    if args.get("replace") is not None:
        replacement = args["replace"]
        if not isinstance(replacement, dict):
            raise ValueError("replace must be an object")
        set_value_at_path(config, path, replacement)
        after = replacement
    else:
        for key_name in args.get("remove_keys") or []:
            card.pop(str(key_name), None)
        patch = args.get("patch") or {}
        if patch:
            if not isinstance(patch, dict):
                raise ValueError("patch must be an object")
            card.update(patch)
        after = json.loads(json.dumps(card, default=str))
    if bool(args.get("dry_run")):
        return {"preferred_path": True, "changed": False, "dry_run": True, "path": path, "before": before, "after": after}
    save_args = {"url_path": args.get("url_path"), "dashboard_id": args.get("dashboard_id"), "config": config, "backup": bool(args.get("backup", True)), "force": True}
    saved = live_lovelace_save_config(save_args)
    return {"preferred_path": True, "changed": True, "path": path, "before": before, "after": after, "save": saved}


def live_lovelace_save_config(args: dict[str, Any]) -> dict[str, Any]:
    if not bool(args.get("force")):
        raise ValueError("live_lovelace_save_config requires force=true")
    message: dict[str, Any] = {"type": "lovelace/config/save", "config": args["config"]}
    url_path = lovelace_url_path(args)
    if url_path is not None:
        message["url_path"] = url_path
    if bool(args.get("dry_run")):
        return {"dry_run": True, "message": message, "preferred_path": True}
    backups: dict[str, Any] = {}
    if bool(args.get("backup", True)):
        try:
            registry, item = resolve_lovelace_dashboard({"url_path": args.get("url_path"), "id": args.get("dashboard_id")})
            if item:
                key = dashboard_item_key(item)
                path = storage_path(key)
                if path.exists():
                    backups["dashboard"] = backup_path(path, key)
        except Exception as err:
            backups["error"] = str(err)
    result = ha_ws_call(message)
    audit_event("live_lovelace_save_config", {"url_path": url_path, "backups": backups, "success": result.get("success")})
    return {"result": result, "backups": backups, "preferred_path": True}


def load_storage_json(key: str) -> dict[str, Any]:
    path = storage_path(key)
    if not path.exists():
        return {"version": 1, "minor_version": 1, "key": key, "data": {}}
    return json.loads(path.read_text(errors="replace"))


def dump_storage_json(key: str, data: dict[str, Any], mode: str | None = None) -> dict[str, Any]:
    path = storage_path(key)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, default=str))
    if mode:
        path.chmod(int(str(mode), 8))
    audit_event("dump_storage_json", {"key": key, "path": str(path)})
    return path_info(path) | {"key": key}


def lovelace_dashboard_id_from_key(key: str) -> str:
    if key == "lovelace":
        return "lovelace"
    if key.startswith("lovelace."):
        return key.removeprefix("lovelace.")
    raise ValueError("Dashboard storage key must be lovelace.<id>")


def lovelace_dashboard_key(dashboard_id: str) -> str:
    return f"lovelace.{dashboard_id}"


def make_dashboard_id(value: str) -> str:
    cleaned = "".join(ch.lower() if ch.isalnum() else "_" for ch in value.strip())
    cleaned = "_".join(part for part in cleaned.split("_") if part)
    if not cleaned:
        raise ValueError("Dashboard id/url_path cannot be empty")
    return cleaned


def load_lovelace_registry() -> dict[str, Any]:
    registry = load_storage_json("lovelace_dashboards")
    registry.setdefault("version", 1)
    registry.setdefault("minor_version", 1)
    registry["key"] = "lovelace_dashboards"
    registry.setdefault("data", {})
    registry["data"].setdefault("items", [])
    return registry


def dashboard_item_key(item: dict[str, Any]) -> str:
    return lovelace_dashboard_key(item["id"])


def resolve_lovelace_dashboard(args: dict[str, Any], allow_missing: bool = False) -> tuple[dict[str, Any], dict[str, Any] | None]:
    registry = load_lovelace_registry()
    items = registry["data"]["items"]
    wanted_id = args.get("id")
    wanted_url = args.get("url_path")
    wanted_key = args.get("key")
    if wanted_key and not wanted_id:
        wanted_id = lovelace_dashboard_id_from_key(wanted_key)
    item = None
    for candidate in items:
        if wanted_id and candidate.get("id") == wanted_id:
            item = candidate
            break
        if wanted_url and candidate.get("url_path") == wanted_url:
            item = candidate
            break
    if item or not allow_missing:
        return registry, item
    dashboard_id = wanted_id or make_dashboard_id(wanted_url or args.get("title") or "")
    url_path = wanted_url or dashboard_id.replace("_", "-")
    item = {
        "id": dashboard_id,
        "url_path": url_path,
        "title": args.get("title") or url_path.replace("-", " ").title(),
        "require_admin": bool(args.get("require_admin", False)),
        "show_in_sidebar": bool(args.get("show_in_sidebar", False)),
        "mode": "storage",
    }
    if args.get("icon"):
        item["icon"] = args["icon"]
    items.append(item)
    return registry, item


def list_lovelace_dashboards(include_config: bool, max_bytes: int) -> dict[str, Any]:
    registry = load_lovelace_registry()
    rows = []
    for item in registry["data"]["items"]:
        key = dashboard_item_key(item)
        path = storage_path(key)
        row: dict[str, Any] = {"item": item, "key": key, "storage": {"path": str(path), "exists": path.exists()}}
        if path.exists():
            row["storage"] = path_info(path)
            if include_config:
                content, truncated = read_limited(path, max_bytes)
                row["storage"]["content"] = content
                row["storage"]["truncated"] = truncated
        rows.append(row)
    return {"count": len(rows), "dashboards": rows}


def get_lovelace_dashboard(args: dict[str, Any], max_bytes: int) -> dict[str, Any]:
    registry, item = resolve_lovelace_dashboard(args)
    if item is None:
        raise ValueError("Dashboard not found")
    key = dashboard_item_key(item)
    path = storage_path(key)
    result: dict[str, Any] = {"item": item, "key": key, "path": str(path), "exists": path.exists()}
    if path.exists():
        content, truncated = read_limited(path, max_bytes)
        result["content"] = content
        result["truncated"] = truncated
        try:
            result["data"] = json.loads(content)
        except json.JSONDecodeError:
            pass
    return result


def dashboard_storage(args: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any], str, dict[str, Any]]:
    registry, item = resolve_lovelace_dashboard(args)
    if item is None:
        raise ValueError("Dashboard not found")
    key = dashboard_item_key(item)
    storage = load_storage_json(key)
    config = storage.get("data", {}).get("config")
    if not isinstance(config, dict):
        raise ValueError("Dashboard storage does not contain data.config")
    return item, storage, key, config


def dashboard_views(config: dict[str, Any]) -> list[Any]:
    views = config.get("views")
    if not isinstance(views, list):
        raise ValueError("Dashboard config does not contain a views list")
    return views


def view_summary(view: Any, index: int, include_cards: bool) -> dict[str, Any]:
    if not isinstance(view, dict):
        return {"index": index, "view": view}
    summary = dict(view) if include_cards else {key: value for key, value in view.items() if key != "cards"}
    cards = view.get("cards")
    if isinstance(cards, list):
        summary["card_count"] = len(cards)
        if not include_cards:
            summary["cards"] = [
                {
                    "path": f"$.data.config.views[{index}].cards[{card_index}]",
                    "type": card.get("type") if isinstance(card, dict) else None,
                    "title": (card.get("title") or card.get("name")) if isinstance(card, dict) else None,
                    "entities": sorted(card_entities(card)),
                }
                for card_index, card in enumerate(cards)
            ]
    return {"index": index, "view": summary}


def matching_views(config: dict[str, Any], args: dict[str, Any]) -> list[dict[str, Any]]:
    views = dashboard_views(config)
    matches = []
    query = str(args.get("query") or "").lower()
    for index, view in enumerate(views):
        if args.get("view_index") is not None and index != int(args["view_index"]):
            continue
        if args.get("view_title") and (not isinstance(view, dict) or str(view.get("title") or "") != args["view_title"]):
            continue
        if args.get("view_path") and (not isinstance(view, dict) or str(view.get("path") or "") != args["view_path"]):
            continue
        if query and not contains_text(view, query):
            continue
        matches.append(view_summary(view, index, bool(args.get("include_cards", True))))
    return matches


def get_lovelace_view(args: dict[str, Any]) -> dict[str, Any]:
    item, _storage, key, config = dashboard_storage(args)
    matches = matching_views(config, args)
    expected = int(args.get("expected_matches") or 1)
    if len(matches) != expected:
        return {"item": item, "key": key, "count": len(matches), "error": f"Expected {expected} view match(es), found {len(matches)}", "matches": matches}
    if expected != 1:
        raise ValueError("get_lovelace_view currently requires expected_matches=1")
    return {"item": item, "key": key, "count": 1, "match": matches[0]}


def path_parts(path: str) -> list[str | int]:
    if not path.startswith("$"):
        raise ValueError("Card path must start with $")
    parts: list[str | int] = []
    index = 1
    while index < len(path):
        if path[index] == ".":
            index += 1
            start = index
            while index < len(path) and path[index] not in ".[":
                index += 1
            if start == index:
                raise ValueError(f"Invalid path: {path}")
            parts.append(path[start:index])
        elif path[index] == "[":
            end = path.find("]", index)
            if end == -1:
                raise ValueError(f"Invalid path: {path}")
            parts.append(int(path[index + 1 : end]))
            index = end + 1
        else:
            raise ValueError(f"Invalid path: {path}")
    return parts


def value_at_path(root: Any, path: str) -> Any:
    value = root
    for part in path_parts(path):
        value = value[part]
    return value


def set_value_at_path(root: Any, path: str, value: Any) -> None:
    parts = path_parts(path)
    if not parts:
        raise ValueError("Cannot replace dashboard root")
    parent = root
    for part in parts[:-1]:
        parent = parent[part]
    parent[parts[-1]] = value


def card_entities(card: Any) -> set[str]:
    entities: set[str] = set()
    if isinstance(card, dict):
        for key, value in card.items():
            if key == "entity" and isinstance(value, str):
                entities.add(value)
            elif key == "entities" and isinstance(value, list):
                for item in value:
                    if isinstance(item, str):
                        entities.add(item)
                    elif isinstance(item, dict) and isinstance(item.get("entity"), str):
                        entities.add(item["entity"])
            elif isinstance(value, (dict, list)):
                entities.update(card_entities(value))
    elif isinstance(card, list):
        for item in card:
            entities.update(card_entities(item))
    return entities


def iter_lovelace_cards(value: Any, path: str = "$") -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if isinstance(value, dict):
        if "type" in value:
            rows.append(
                {
                    "path": path,
                    "type": value.get("type"),
                    "title": value.get("title") or value.get("name"),
                    "entities": sorted(card_entities(value)),
                    "card": value,
                }
            )
        for key, child in value.items():
            if isinstance(child, (dict, list)):
                rows.extend(iter_lovelace_cards(child, f"{path}.{key}"))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            if isinstance(child, (dict, list)):
                rows.extend(iter_lovelace_cards(child, f"{path}[{index}]"))
    return rows


def card_matches(row: dict[str, Any], args: dict[str, Any]) -> bool:
    if args.get("path") and row["path"] != args["path"]:
        return False
    if args.get("card_type") and row.get("type") != args["card_type"]:
        return False
    if args.get("entity") and args["entity"] not in row.get("entities", []):
        return False
    query = str(args.get("query") or "").lower()
    if query and not contains_text(row.get("card"), query):
        return False
    return True


def find_lovelace_cards(args: dict[str, Any]) -> dict[str, Any]:
    item, _storage, key, config = dashboard_storage(args)
    views = dashboard_views(config)
    wanted_view_index = args.get("view_index")
    wanted_view_title = args.get("view_title")
    limit = int(args.get("limit") or 100)
    matches = []
    for view_index, view in enumerate(views):
        if wanted_view_index is not None and view_index != int(wanted_view_index):
            continue
        if wanted_view_title and str(view.get("title") or "") != wanted_view_title:
            continue
        for row in iter_lovelace_cards(view, f"$.data.config.views[{view_index}]"):
            if card_matches(row, args):
                matches.append(row)
                if len(matches) >= limit:
                    return {"item": item, "key": key, "count": len(matches), "matches": matches}
    return {"item": item, "key": key, "count": len(matches), "matches": matches}


def get_lovelace_card(args: dict[str, Any]) -> dict[str, Any]:
    item, storage, key, _config = dashboard_storage(args)
    search = find_lovelace_cards(args)
    matches = search["matches"]
    expected = int(args.get("expected_matches") or 1)
    if len(matches) != expected:
        return {"item": item, "key": key, "count": len(matches), "error": f"Expected {expected} card match(es), found {len(matches)}", "matches": matches}
    if expected != 1:
        raise ValueError("get_lovelace_card currently requires expected_matches=1")
    target_path = matches[0]["path"]
    return {"item": item, "key": key, "path": target_path, "card": value_at_path(storage, target_path)}


def patch_lovelace_card(args: dict[str, Any]) -> dict[str, Any]:
    if args.get("patch") is None and args.get("replace") is None and not args.get("remove_keys"):
        raise ValueError("Pass patch, replace, or remove_keys")
    item, storage, key, config = dashboard_storage(args)
    storage_file = storage_path(key)
    require_expected_hash(storage_file, args.get("expected_hash"))
    search = find_lovelace_cards(args)
    matches = search["matches"]
    expected = int(args.get("expected_matches") or 1)
    if len(matches) != expected:
        return {"changed": False, "error": f"Expected {expected} match(es), found {len(matches)}", "matches": matches}
    if expected != 1:
        raise ValueError("patch_lovelace_card currently requires expected_matches=1")
    target_path = matches[0]["path"]
    card = value_at_path(storage, target_path)
    if not isinstance(card, dict):
        raise ValueError("Matched path is not a card object")
    before = json.loads(json.dumps(card, default=str))
    if args.get("replace") is not None:
        replacement = args["replace"]
        if not isinstance(replacement, dict):
            raise ValueError("replace must be an object")
        set_value_at_path(storage, target_path, replacement)
        after = replacement
    else:
        patch = args.get("patch") or {}
        if not isinstance(patch, dict):
            raise ValueError("patch must be an object")
        for key_name in args.get("remove_keys") or []:
            card.pop(str(key_name), None)
        card.update(patch)
        after = json.loads(json.dumps(card, default=str))
    if bool(args.get("dry_run")):
        return {"changed": False, "dry_run": True, "warning": LOVELACE_STORAGE_EDIT_WARNING, "item": item, "key": key, "path": target_path, "before": before, "after": after, "current_hash": path_hash(storage_file)}
    backups: dict[str, Any] = {}
    if bool(args.get("backup", True)):
        backups["dashboard"] = backup_path(storage_path(key), args.get("label") or key)
    info = dump_storage_json(key, storage)
    audit_event("patch_lovelace_card", {"key": key, "path": target_path, "backups": backups})
    return {"changed": True, "warning": LOVELACE_STORAGE_EDIT_WARNING, "item": item, "key": key, "path": target_path, "before": before, "after": after, "dashboard": info, "backups": backups}


def lovelace_save_mutation(args: dict[str, Any], key: str, storage: dict[str, Any], action: str, details: dict[str, Any]) -> dict[str, Any]:
    backups: dict[str, Any] = {}
    if bool(args.get("backup", True)):
        backups["dashboard"] = backup_path(storage_path(key), args.get("label") or key)
    info = dump_storage_json(key, storage)
    audit_event(action, {"key": key, "details": details, "backups": backups})
    return {"warning": LOVELACE_STORAGE_EDIT_WARNING, "dashboard": info, "backups": backups}


def get_lovelace_dashboard_outline(args: dict[str, Any]) -> dict[str, Any]:
    item, _storage, key, config = dashboard_storage(args)
    views = dashboard_views(config)
    rows = []
    for view_index, view in enumerate(views):
        if not isinstance(view, dict):
            rows.append({"index": view_index, "view": view})
            continue
        view_row: dict[str, Any] = {
            "index": view_index,
            "path": f"$.data.config.views[{view_index}]",
            "title": view.get("title"),
            "view_path": view.get("path"),
            "type": view.get("type"),
            "card_count": len(view.get("cards") or []) if isinstance(view.get("cards"), list) else 0,
        }
        if bool(args.get("include_badges")):
            view_row["badges"] = view.get("badges")
        cards = []
        for row in iter_lovelace_cards(view, f"$.data.config.views[{view_index}]"):
            card_row = {"path": row["path"], "type": row.get("type"), "title": row.get("title")}
            if bool(args.get("include_entities", True)):
                card_row["entities"] = row.get("entities", [])
            cards.append(card_row)
        view_row["cards"] = cards
        rows.append(view_row)
    return {"item": item, "key": key, "view_count": len(rows), "views": rows}


def resolve_view_index(config: dict[str, Any], args: dict[str, Any], prefix: str = "") -> int:
    views = dashboard_views(config)
    index_key = f"{prefix}view_index"
    title_key = f"{prefix}view_title"
    path_key = f"{prefix}view_path"
    if args.get(index_key) is not None:
        index = int(args[index_key])
        if index < 0 or index >= len(views):
            raise ValueError(f"{index_key} is out of range")
        return index
    matches = []
    for index, view in enumerate(views):
        if not isinstance(view, dict):
            continue
        if args.get(title_key) is not None and str(view.get("title") or "") == str(args[title_key]):
            matches.append(index)
        elif args.get(path_key) is not None and str(view.get("path") or "") == str(args[path_key]):
            matches.append(index)
    if len(matches) != 1:
        raise ValueError(f"Expected exactly one view match for prefix {prefix!r}, found {len(matches)}")
    return matches[0]


def remove_value_at_path(root: Any, path: str) -> Any:
    parts = path_parts(path)
    if not parts:
        raise ValueError("Cannot remove dashboard root")
    parent = root
    for part in parts[:-1]:
        parent = parent[part]
    last = parts[-1]
    if isinstance(parent, list) and isinstance(last, int):
        return parent.pop(last)
    if isinstance(parent, dict) and isinstance(last, str):
        return parent.pop(last)
    raise ValueError(f"Cannot remove {path}")


def patch_lovelace_json_path(args: dict[str, Any]) -> dict[str, Any]:
    item, storage, key, _config = dashboard_storage(args)
    storage_file = storage_path(key)
    require_expected_hash(storage_file, args.get("expected_hash"))
    path = args["path"]
    before = None if bool(args.get("remove")) else json.loads(json.dumps(value_at_path(storage, path), default=str))
    operation = None
    after: Any = None
    if bool(args.get("remove")):
        removed = remove_value_at_path(storage, path)
        operation = "remove"
        after = None
    elif args.get("replace") is not None:
        set_value_at_path(storage, path, args["replace"])
        operation = "replace"
        after = args["replace"]
    else:
        target = value_at_path(storage, path)
        if args.get("append") is not None:
            if not isinstance(target, list):
                raise ValueError("append target must be a list")
            target.append(args["append"])
            operation = "append"
            after = {"length": len(target), "appended": args["append"]}
        elif args.get("insert") is not None:
            if not isinstance(target, list):
                raise ValueError("insert target must be a list")
            index = int(args.get("index") if args.get("index") is not None else len(target))
            target.insert(index, args["insert"])
            operation = "insert"
            after = {"length": len(target), "index": index, "inserted": args["insert"]}
        elif args.get("patch") is not None or args.get("remove_keys"):
            if not isinstance(target, dict):
                raise ValueError("patch/remove_keys target must be an object")
            for key_name in args.get("remove_keys") or []:
                target.pop(str(key_name), None)
            if args.get("patch") is not None:
                patch = args["patch"]
                if not isinstance(patch, dict):
                    raise ValueError("patch must be an object")
                target.update(patch)
            operation = "patch"
            after = json.loads(json.dumps(target, default=str))
        else:
            raise ValueError("Pass patch, replace, append, insert, remove=true, or remove_keys")
    if bool(args.get("dry_run")):
        return {"changed": False, "dry_run": True, "warning": LOVELACE_STORAGE_EDIT_WARNING, "item": item, "key": key, "path": path, "operation": operation, "before": before, "after": after, "current_hash": path_hash(storage_file)}
    saved = lovelace_save_mutation(args, key, storage, "patch_lovelace_json_path", {"path": path, "operation": operation})
    return {"changed": True, "item": item, "key": key, "path": path, "operation": operation, "before": before, "after": after} | saved


def insert_lovelace_card(args: dict[str, Any]) -> dict[str, Any]:
    item, storage, key, config = dashboard_storage(args)
    storage_file = storage_path(key)
    require_expected_hash(storage_file, args.get("expected_hash"))
    view_index = resolve_view_index(config, args)
    view = dashboard_views(config)[view_index]
    if not isinstance(view, dict):
        raise ValueError("Matched view is not an object")
    cards = view.setdefault("cards", [])
    if not isinstance(cards, list):
        raise ValueError("Matched view cards is not a list")
    index = int(args.get("index") if args.get("index") is not None else len(cards))
    if index < 0 or index > len(cards):
        raise ValueError("index is out of range")
    card = args["card"]
    before_count = len(cards)
    cards.insert(index, card)
    path = f"$.data.config.views[{view_index}].cards[{index}]"
    if bool(args.get("dry_run")):
        return {"changed": False, "dry_run": True, "warning": LOVELACE_STORAGE_EDIT_WARNING, "item": item, "key": key, "view_index": view_index, "index": index, "path": path, "before_count": before_count, "after_count": len(cards), "current_hash": path_hash(storage_file), "card": card}
    saved = lovelace_save_mutation(args, key, storage, "insert_lovelace_card", {"view_index": view_index, "index": index, "path": path})
    return {"changed": True, "item": item, "key": key, "view_index": view_index, "index": index, "path": path, "before_count": before_count, "after_count": len(cards), "card": card} | saved


def matched_card_path(args: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any], str, str, dict[str, Any]]:
    item, storage, key, _config = dashboard_storage(args)
    search = find_lovelace_cards(args)
    matches = search["matches"]
    expected = int(args.get("expected_matches") or 1)
    if len(matches) != expected:
        raise ValueError(f"Expected {expected} card match(es), found {len(matches)}")
    if expected != 1:
        raise ValueError("This operation requires expected_matches=1")
    path = matches[0]["path"]
    card = value_at_path(storage, path)
    return item, storage, key, path, card


def delete_lovelace_card(args: dict[str, Any]) -> dict[str, Any]:
    if not bool(args.get("force")):
        raise ValueError("delete_lovelace_card requires force=true")
    item, storage, key, path, card = matched_card_path(args)
    storage_file = storage_path(key)
    require_expected_hash(storage_file, args.get("expected_hash"))
    before = json.loads(json.dumps(card, default=str))
    if bool(args.get("dry_run")):
        return {"changed": False, "dry_run": True, "warning": LOVELACE_STORAGE_EDIT_WARNING, "item": item, "key": key, "path": path, "card": before, "current_hash": path_hash(storage_file)}
    removed = remove_value_at_path(storage, path)
    saved = lovelace_save_mutation(args, key, storage, "delete_lovelace_card", {"path": path})
    return {"changed": True, "item": item, "key": key, "path": path, "card": removed} | saved


def move_lovelace_card(args: dict[str, Any]) -> dict[str, Any]:
    item, storage, key, source_path, card = matched_card_path(args)
    storage_file = storage_path(key)
    require_expected_hash(storage_file, args.get("expected_hash"))
    config = storage.get("data", {}).get("config")
    if not isinstance(config, dict):
        raise ValueError("Dashboard storage does not contain data.config")
    target_view_index = resolve_view_index(config, args, "target_")
    target_view = dashboard_views(config)[target_view_index]
    if not isinstance(target_view, dict):
        raise ValueError("Target view is not an object")
    target_cards = target_view.setdefault("cards", [])
    if not isinstance(target_cards, list):
        raise ValueError("Target view cards is not a list")
    target_index = int(args.get("target_index") if args.get("target_index") is not None else len(target_cards))
    if target_index < 0 or target_index > len(target_cards):
        raise ValueError("target_index is out of range")
    moving = json.loads(json.dumps(card, default=str))
    if bool(args.get("dry_run")):
        return {"changed": False, "dry_run": True, "warning": LOVELACE_STORAGE_EDIT_WARNING, "item": item, "key": key, "source_path": source_path, "target_view_index": target_view_index, "target_index": target_index, "card": moving, "current_hash": path_hash(storage_file)}
    source_parts = path_parts(source_path)
    if len(source_parts) >= 6 and source_parts[:3] == ["data", "config", "views"] and source_parts[4] == "cards":
        source_view_index = source_parts[3]
        source_card_index = source_parts[5]
        if source_view_index == target_view_index and isinstance(source_card_index, int) and source_card_index < target_index:
            target_index -= 1
    removed = remove_value_at_path(storage, source_path)
    target_cards = target_view.setdefault("cards", [])
    if target_index > len(target_cards):
        target_index = len(target_cards)
    target_cards.insert(target_index, removed)
    target_path = f"$.data.config.views[{target_view_index}].cards[{target_index}]"
    saved = lovelace_save_mutation(args, key, storage, "move_lovelace_card", {"source_path": source_path, "target_path": target_path})
    return {"changed": True, "item": item, "key": key, "source_path": source_path, "target_path": target_path, "card": moving} | saved


def lovelace_storage_path(key: str) -> Path:
    if not (key == "lovelace_dashboards" or key == "lovelace_resources" or key.startswith("lovelace.")):
        raise ValueError("Lovelace dashboard keys must be lovelace.*, lovelace_dashboards, or lovelace_resources")
    return storage_path(key)


def save_lovelace_dashboard(args: dict[str, Any]) -> dict[str, Any]:
    if args.get("key") and not any(args.get(name) is not None for name in ("id", "url_path", "title", "config", "views")):
        path = lovelace_storage_path(args["key"])
        require_expected_hash(path, args.get("expected_hash"))
        if bool(args.get("dry_run")):
            return {"key": args["key"], "path": str(path), "dry_run": True, "warning": LOVELACE_STORAGE_EDIT_WARNING, "current_hash": path_hash(path), "would_backup": bool(path.exists() and args.get("backup", True))}
        backup = backup_path(path, args.get("label") or args["key"]) if bool(args.get("backup", True)) and path.exists() else None
        if "content" in args and args["content"] is not None:
            path.write_text(str(args["content"]))
        else:
            path.write_text(json.dumps(args.get("data"), indent=2, default=str))
        if args.get("mode"):
            path.chmod(int(str(args["mode"]), 8))
        audit_event("save_lovelace_dashboard_raw", {"key": args["key"], "path": str(path), "backup": backup})
        return path_info(path) | {"key": args["key"], "backup": backup, "mode": "raw_storage_key", "warning": LOVELACE_STORAGE_EDIT_WARNING}

    registry, item = resolve_lovelace_dashboard(args, allow_missing=bool(args.get("create", True)))
    if item is None:
        raise ValueError("Dashboard not found; pass create=true with id or url_path to create it")
    for field in ("title", "icon", "url_path"):
        if args.get(field) is not None:
            item[field] = args[field]
    for field in ("show_in_sidebar", "require_admin"):
        if args.get(field) is not None:
            item[field] = bool(args[field])
    item["mode"] = "storage"

    key = dashboard_item_key(item)
    path = storage_path(key)
    require_expected_hash(path, args.get("expected_hash"))

    if args.get("content") is not None:
        dashboard_storage = json.loads(str(args["content"]))
    elif args.get("data") is not None and "version" in args["data"] and "data" in args["data"]:
        dashboard_storage = args["data"]
    else:
        config = args.get("config")
        if config is None:
            config = {"title": item.get("title"), "views": args.get("views") or []}
        elif args.get("views") is not None:
            config = dict(config)
            config["views"] = args["views"]
        dashboard_storage = {"version": 1, "minor_version": 1, "key": key, "data": {"config": config}}
    dashboard_storage["key"] = key
    if bool(args.get("dry_run")):
        return {"item": item, "key": key, "dry_run": True, "warning": LOVELACE_STORAGE_EDIT_WARNING, "current_hash": path_hash(path), "would_backup": bool(args.get("backup", True)), "dashboard_storage": dashboard_storage}
    backups: dict[str, Any] = {}
    if bool(args.get("backup", True)):
        if path.exists():
            backups["dashboard"] = backup_path(path, args.get("label") or key)
        registry_path = storage_path("lovelace_dashboards")
        if registry_path.exists():
            backups["registry"] = backup_path(registry_path, args.get("label") or "lovelace_dashboards")
    dashboard_info = dump_storage_json(key, dashboard_storage, args.get("mode"))
    registry_info = dump_storage_json("lovelace_dashboards", registry)
    audit_event("save_lovelace_dashboard", {"key": key, "item": item, "backups": backups})
    return {"item": item, "key": key, "warning": LOVELACE_STORAGE_EDIT_WARNING, "dashboard": dashboard_info, "registry": registry_info, "backups": backups}


def delete_lovelace_dashboard(args: dict[str, Any]) -> dict[str, Any]:
    registry, item = resolve_lovelace_dashboard(args)
    if item is None:
        raise ValueError("Dashboard not found")
    if not bool(args.get("force")):
        raise ValueError("delete_lovelace_dashboard requires force=true")
    key = dashboard_item_key(item)
    path = storage_path(key)
    if bool(args.get("dry_run")):
        return {"item": item, "key": key, "path": str(path), "dry_run": True, "warning": LOVELACE_STORAGE_EDIT_WARNING, "exists": path.exists()}
    backups: dict[str, Any] = {}
    if bool(args.get("backup", True)):
        if path.exists():
            backups["dashboard"] = backup_path(path, key)
        registry_path = storage_path("lovelace_dashboards")
        if registry_path.exists():
            backups["registry"] = backup_path(registry_path, "lovelace_dashboards")
    registry["data"]["items"] = [candidate for candidate in registry["data"]["items"] if candidate.get("id") != item.get("id")]
    registry_info = dump_storage_json("lovelace_dashboards", registry)
    deleted = False
    if path.exists():
        path.unlink()
        deleted = True
    audit_event("delete_lovelace_dashboard", {"key": key, "item": item, "deleted_storage": deleted, "backups": backups})
    return {"item": item, "key": key, "warning": LOVELACE_STORAGE_EDIT_WARNING, "deleted_storage": deleted, "registry": registry_info, "backups": backups}


def resource_text(uri: str, value: Any, mime_type: str = "application/json") -> dict[str, Any]:
    text = value if isinstance(value, str) else json.dumps(value, indent=2, default=str)
    return {"uri": uri, "mimeType": mime_type, "text": text}


def read_resource(uri: str) -> dict[str, Any]:
    parsed = urllib.parse.urlparse(uri)
    if parsed.scheme != "ha":
        raise ValueError("Unsupported resource URI scheme")
    path = parsed.netloc + parsed.path
    path = path.strip("/")
    if path == "core/info":
        return {"contents": [resource_text(uri, supervisor_request("GET", "/core/info"))]}
    if path == "supervisor/info":
        return {"contents": [resource_text(uri, supervisor_request("GET", "/supervisor/info"))]}
    if path == "host/info":
        return {"contents": [resource_text(uri, supervisor_request("GET", "/host/info"))]}
    if path == "states":
        return {"contents": [resource_text(uri, ha_request("GET", "/states"))]}
    if path.startswith("state/"):
        entity_id = urllib.parse.unquote(path.removeprefix("state/"))
        return {"contents": [resource_text(uri, ha_request("GET", f"/states/{entity_id}"))]}
    if path == "services":
        return {"contents": [resource_text(uri, ha_request("GET", "/services"))]}
    if path == "events":
        return {"contents": [resource_text(uri, ha_request("GET", "/events"))]}
    if path == "lovelace/dashboards":
        return {"contents": [resource_text(uri, list_lovelace_dashboards(False, MAX_READ_BYTES))]}
    if path.startswith("lovelace/dashboard/"):
        dashboard_id = urllib.parse.unquote(path.removeprefix("lovelace/dashboard/"))
        return {"contents": [resource_text(uri, get_lovelace_dashboard({"id": dashboard_id}, MAX_READ_BYTES))]}
    if path.startswith("lovelace/view/"):
        parts = path.split("/", 3)
        if len(parts) != 4:
            raise ValueError("Lovelace view resource must be ha://lovelace/view/{id}/{view}")
        dashboard_id = urllib.parse.unquote(parts[2])
        view = urllib.parse.unquote(parts[3])
        args: dict[str, Any] = {"id": dashboard_id, "include_cards": True}
        if view.isdigit():
            args["view_index"] = int(view)
        else:
            args["view_title"] = view
        return {"contents": [resource_text(uri, get_lovelace_view(args))]}
    if path.startswith("config/"):
        relpath = urllib.parse.unquote(path.removeprefix("config/"))
        content, truncated = read_limited(config_path(relpath), MAX_READ_BYTES)
        suffix = Path(relpath).suffix.lower()
        mime = "text/yaml" if suffix in (".yaml", ".yml") else "text/plain"
        if truncated:
            content += "\n...<truncated>"
        return {"contents": [resource_text(uri, content, mime)]}
    if path.startswith("storage/"):
        key = urllib.parse.unquote(path.removeprefix("storage/"))
        return {"contents": [resource_text(uri, read_storage_key(key, MAX_READ_BYTES))]}
    raise ValueError(f"Unknown resource URI: {uri}")


def prompt_message(text: str) -> dict[str, Any]:
    return {"role": "user", "content": {"type": "text", "text": text}}


def get_prompt(name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    if name == "ha_admin_audit":
        text = (
            "Audit this Home Assistant instance before changing it. Use core_info, supervisor_info, "
            "check_reload_readiness, tail_log, search_config_entries, search_entity_registry, and targeted reads. "
            "Keep evidence separate from guesses and do not restart/reload unless the change requires it."
        )
    elif name == "lovelace_safe_patch":
        dashboard = arguments.get("dashboard") or "the relevant dashboard"
        target = arguments.get("target") or "the requested card"
        text = (
            f"Patch {target} on {dashboard} safely. Use list_lovelace_dashboards, get_lovelace_view or "
            "find_lovelace_cards/get_lovelace_card to locate exactly one card. For actual UI/dashboard changes, prefer "
            "live_lovelace_get_outline/live_lovelace_find_cards/live_lovelace_patch_card or the Home Assistant UI path, then verify the rendered UI. "
            "Storage-backed Lovelace patch tools return a warning because they are not the preferred UI change path."
        )
    elif name == "config_safe_edit":
        path = arguments.get("path") or "the relevant config file"
        text = (
            f"Edit {path} safely. Read/search the current config first, write the smallest change, run check_config, "
            "then reload the relevant domain or report that restart is required."
        )
    else:
        raise ValueError(f"Unknown prompt: {name}")
    return {"description": next((prompt["description"] for prompt in PROMPTS if prompt["name"] == name), name), "messages": [prompt_message(text)]}


def completion_result() -> dict[str, Any]:
    return {"completion": {"values": [], "total": 0, "hasMore": False}}


class Handler(BaseHTTPRequestHandler):
    server_version = "HAAdminMCP/0.1"

    def do_GET(self) -> None:
        if self.path == "/health":
            self.write_json({"ok": True, "dangerous": True})
            return
        if self.path == MCP_PATH:
            self.send_error(405, "SSE streams are not implemented")
            return
        self.send_error(404)

    def do_POST(self) -> None:
        if self.path != MCP_PATH:
            self.send_error(404)
            return
        if not self.authorized():
            self.write_json({"error": "unauthorized"}, status=401)
            return
        length = int(self.headers.get("Content-Length", "0"))
        try:
            message = json.loads(self.rfile.read(length) or b"{}")
        except json.JSONDecodeError as err:
            self.write_json({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": f"Parse error: {err}"}})
            return
        response = self.handle_message(message)
        if response is None:
            self.send_response(202)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        extra_headers = {}
        if isinstance(message, dict) and message.get("method") == "initialize":
            extra_headers["Mcp-Session-Id"] = str(uuid.uuid4())
        self.write_json(response, headers=extra_headers)

    def do_DELETE(self) -> None:
        if self.path == MCP_PATH:
            self.send_response(202)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self.send_error(404)

    def authorized(self) -> bool:
        token = OPTIONS.get("admin_token") or ""
        if not token:
            return True
        return self.headers.get("Authorization") == f"Bearer {token}"

    def handle_message(self, message: Any) -> Any | None:
        if isinstance(message, list):
            responses = [response for item in message if (response := self.handle_rpc(item)) is not None]
            return responses or None
        return self.handle_rpc(message)

    def handle_rpc(self, request: dict[str, Any]) -> dict[str, Any] | None:
        request_id = request.get("id")
        method = request.get("method")
        try:
            if method == "initialize":
                params = request.get("params") or {}
                requested_version = params.get("protocolVersion")
                protocol_version = requested_version if requested_version in SUPPORTED_PROTOCOL_VERSIONS else "2025-03-26"
                result = {
                    "protocolVersion": protocol_version,
                    "serverInfo": {"name": "ha-admin-mcp", "version": APP_VERSION},
                    "capabilities": {
                        "tools": {"listChanged": True},
                        "resources": {"subscribe": False, "listChanged": True},
                        "prompts": {"listChanged": True},
                        "logging": {},
                    },
                }
            elif method == "tools/list":
                result = {"tools": TOOLS}
            elif method == "prompts/list":
                result = {"prompts": PROMPTS}
            elif method == "prompts/get":
                params = request.get("params") or {}
                result = get_prompt(params["name"], params.get("arguments") or {})
            elif method == "resources/list":
                result = {"resources": RESOURCES}
            elif method == "resources/read":
                params = request.get("params") or {}
                result = read_resource(params["uri"])
            elif method == "resources/templates/list":
                result = {"resourceTemplates": RESOURCE_TEMPLATES}
            elif method == "tools/call":
                params = request.get("params") or {}
                result = text_result(call_tool(params["name"], params.get("arguments") or {}))
            elif method == "ping":
                result = {}
            elif method == "completion/complete":
                result = completion_result()
            elif method == "logging/setLevel":
                global LOG_LEVEL
                params = request.get("params") or {}
                LOG_LEVEL = str(params.get("level") or "info")
                result = {}
            elif method and method.startswith("notifications/"):
                return None
            else:
                return self.rpc_error(request_id, -32601, f"Method not found: {method}")
            return {"jsonrpc": "2.0", "id": request_id, "result": result}
        except Exception as err:
            if request_id is None:
                return None
            return self.rpc_error(request_id, -32000, str(err))

    def rpc_error(self, request_id: Any, code: int, message: str) -> dict[str, Any] | None:
        if request_id is None:
            return None
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "error": {"code": code, "message": message},
        }

    def write_json(self, payload: Any, status: int = 200, headers: dict[str, str] | None = None) -> None:
        data = json.dumps(payload, default=str).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, fmt: str, *args: Any) -> None:
        print(f"[ha-admin-mcp] {self.address_string()} {fmt % args}", flush=True)


def main() -> None:
    host = str(OPTIONS.get("bind_host") or "0.0.0.0")
    port = int(OPTIONS.get("port") or 8124)
    print(
        "[ha-admin-mcp] EXTREMELY DANGEROUS server listening on "
        f"{host}:{port}; installing and starting this app grants admin MCP access",
        flush=True,
    )
    ThreadingHTTPServer((host, port), Handler).serve_forever()


if __name__ == "__main__":
    main()
