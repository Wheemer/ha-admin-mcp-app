from __future__ import annotations

import asyncio
import fnmatch
import ast
import base64
import json
import os
import re
import secrets
import shutil
import sqlite3
import subprocess
import textwrap
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
CONFIG_ROOT = Path("/config")
DEFAULT_BACKUP_DIR = Path("/backup/ha-admin-mcp")
SECRET_PATH_FILE = Path("/data/secret_path.txt")
AUDIT_LOG = DEFAULT_BACKUP_DIR / "audit.log"
APP_ROOT = Path("/app")
SAVED_TOOLS_PATH = Path(os.environ.get("CODE_MODE_SAVED_TOOLS_PATH", "/data/saved_tools.json"))
MAX_READ_BYTES = 20_000_000
SUPPORTED_PROTOCOL_VERSIONS = {"2025-06-18", "2025-03-26", "2024-11-05"}
S6_ENV_DIR = Path("/run/s6/container_environment")
DEFAULT_MCP_PATH = "/mcp"
MCP_PORT = 9583
LOG_LEVEL = "info"
SELF_ADDON_SLUGS = {"ha_admin_mcp", "bd7cf910_ha_admin_mcp"}
SELF_UPDATE_ACTIONS = {"update", "rebuild"}
DANGEROUS_PATHS = {"/", "/config", "/backup", "/data", "/share", "/ssl", "/addons", "/usr", "/bin", "/sbin", "/etc", "/root", "/var"}
READ_ONLY_HINTS = ("get", "list", "read", "search", "hash", "stat", "tail", "check", "render", "overview", "summary")
DESTRUCTIVE_HINTS = ("delete", "remove", "restart", "stop", "write", "patch", "set", "save", "run", "shell", "control", "call", "fire", "manage")
LOVELACE_STORAGE_EDIT_WARNING = (
    "Reminder: storage-backed Lovelace edits are not the preferred path for UI changes. "
    "Use live_lovelace_get_outline/live_lovelace_find_cards/live_lovelace_patch_card/live_lovelace_save_config "
    "or the Home Assistant UI path when changing dashboards, "
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
REGISTRY_DEFINITIONS = {
    "entity": {"key": "core.entity_registry", "list": "entities", "selectors": ["entity_id", "unique_id", "id"]},
    "device": {"key": "core.device_registry", "list": "devices", "selectors": ["id", "name", "name_by_user"]},
    "area": {"key": "core.area_registry", "list": "areas", "selectors": ["id", "name"]},
    "floor": {"key": "core.floor_registry", "list": "floors", "selectors": ["id", "name"]},
    "label": {"key": "core.label_registry", "list": "labels", "selectors": ["id", "name"]},
    "category": {"key": "core.category_registry", "list": "categories", "selectors": ["id", "name", "scope"]},
    "config_entry": {"key": "core.config_entries", "list": "entries", "selectors": ["entry_id", "domain", "title", "source"]},
    "issue": {"key": "repairs.issue_registry", "list": "issues", "selectors": ["issue_id", "domain", "translation_key"]},
}
REGISTRY_KEY_ALIASES = {
    definition["key"]: name for name, definition in REGISTRY_DEFINITIONS.items()
}


def read_app_version() -> str:
    config_file = Path(__file__).resolve().parents[1] / "config.yaml"
    try:
        text = config_file.read_text(encoding="utf-8")
        match = re.search(r"(?m)^version:\s*['\"]?([^'\"\s]+)", text)
        if match:
            return match.group(1)
    except Exception:
        pass
    return os.environ.get("HA_ADMIN_MCP_VERSION", "0.0.0")


APP_VERSION = read_app_version()


def load_options() -> dict[str, Any]:
    if ADDON_OPTIONS.exists():
        return json.loads(ADDON_OPTIONS.read_text())
    return {
        "admin_token": os.environ.get("ADMIN_TOKEN", ""),
        "bind_host": os.environ.get("BIND_HOST", "0.0.0.0"),
        "secret_path": os.environ.get("SECRET_PATH", ""),
        "command_timeout_seconds": int(os.environ.get("COMMAND_TIMEOUT_SECONDS", "300")),
    }


OPTIONS = load_options()
SECRET_PATH_RE = re.compile(r"^/(?!.*://)\S{7,}$")


def generate_secret_mcp_path() -> str:
    return "/private_" + secrets.token_urlsafe(16)


def valid_mcp_path(path: str) -> bool:
    return bool(SECRET_PATH_RE.match(path))


def resolve_mcp_path() -> str:
    if os.name == "nt" and not ADDON_OPTIONS.exists():
        return DEFAULT_MCP_PATH
    configured = str(OPTIONS.get("secret_path") or "").strip()
    if configured:
        path = configured if configured.startswith("/") else f"/{configured}"
        if not valid_mcp_path(path):
            raise ValueError("secret_path must start with '/', contain no '://', and be at least 8 characters")
        SECRET_PATH_FILE.parent.mkdir(parents=True, exist_ok=True)
        SECRET_PATH_FILE.write_text(path)
        return path
    if SECRET_PATH_FILE.exists():
        path = SECRET_PATH_FILE.read_text().strip()
        if valid_mcp_path(path):
            return path
    if not SECRET_PATH_FILE.parent.exists():
        return DEFAULT_MCP_PATH
    if os.environ.get("HA_ADMIN_MCP_USE_PUBLIC_MCP_PATH") == "1":
        return DEFAULT_MCP_PATH
    path = generate_secret_mcp_path()
    SECRET_PATH_FILE.parent.mkdir(parents=True, exist_ok=True)
    SECRET_PATH_FILE.write_text(path)
    return path


MCP_PATH = resolve_mcp_path()


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


def public_base_url(headers: Any | None = None) -> str:
    scheme = "http"
    if headers:
        forwarded_proto = headers.get("X-Forwarded-Proto")
        if forwarded_proto:
            scheme = str(forwarded_proto).split(",", 1)[0].strip() or scheme
        host = headers.get("Host")
    else:
        host = None
    if not host:
        host = f"127.0.0.1:{MCP_PORT}"
    return f"{scheme}://{host}"


def app_server_info(headers: Any | None = None) -> dict[str, Any]:
    base = public_base_url(headers)
    return {
        "name": "ha-admin-mcp",
        "title": "HA Admin MCP",
        "version": APP_VERSION,
        "description": "Privileged Home Assistant administration MCP add-on",
        "icons": [
            {"src": f"{base}/icon.png", "mimeType": "image/png", "sizes": "512x512"},
            {"src": f"{base}/logo.png", "mimeType": "image/png", "sizes": "512x512"},
            {"src": f"{base}/icon.svg", "mimeType": "image/svg+xml"},
        ],
        "websiteUrl": "https://github.com/Wheemer/ha-admin-mcp-app",
    }


def tool_error_result(message: str, details: Any | None = None) -> dict[str, Any]:
    payload: dict[str, Any] = {"error": message}
    if details is not None:
        payload["details"] = details
    result = text_result(payload)
    result["isError"] = True
    return result


def is_mcp_content_result(value: Any) -> bool:
    return isinstance(value, dict) and isinstance(value.get("content"), list)


def paginated(items: list[dict[str, Any]], params: dict[str, Any], key: str) -> dict[str, Any]:
    cursor_raw = params.get("cursor")
    if cursor_raw in (None, ""):
        start = 0
    else:
        try:
            start = int(str(cursor_raw))
        except ValueError as err:
            raise ValueError(f"Invalid cursor: {cursor_raw}") from err
    if start < 0:
        raise ValueError("Invalid cursor: cursor must be non-negative")
    page_size = int(params.get("limit") or params.get("pageSize") or 500)
    page_size = max(1, min(page_size, 1000))
    end = start + page_size
    result: dict[str, Any] = {key: items[start:end]}
    if end < len(items):
        result["nextCursor"] = str(end)
    return result


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


def load_upstream_tool_metadata() -> dict[str, dict[str, Any]]:
    path = Path(__file__).with_name("upstream_tools.json")
    if not path.exists():
        return {}
    try:
        items = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    metadata = {}
    for item in items:
        if isinstance(item, dict) and isinstance(item.get("name"), str):
            metadata[item["name"]] = item
    return metadata


UPSTREAM_TOOL_METADATA = load_upstream_tool_metadata()
UPSTREAM_HA_MCP_TOOL_NAMES = list(UPSTREAM_TOOL_METADATA.keys())
HA_ADMIN_COMPAT_EXTENSION_TOOL_NAMES = [
    "ha_search_entities",
    "ha_deep_search",
    "ha_search_tools",
    "ha_call_read_tool",
    "ha_call_write_tool",
    "ha_call_delete_tool",
]
UNIMPLEMENTED_UPSTREAM_TOOL_NAMES: set[str] = set()


def upstream_compat_schema(name: str) -> dict[str, Any]:
    metadata = UPSTREAM_TOOL_METADATA.get(name)
    if not metadata:
        return tool_schema(
            name,
            f"homeassistant-ai/ha-mcp compatibility tool for {name}; routed through this app's HA admin APIs",
            {},
            [],
        )
    schema = {
        "name": name,
        "description": metadata.get("description") or f"homeassistant-ai/ha-mcp compatibility tool for {name}",
        "annotations": tool_annotations(name) | (metadata.get("annotations") or {}),
        "inputSchema": metadata.get("inputSchema") or {"type": "object", "properties": {}, "required": []},
    }
    if metadata.get("tags"):
        schema["tags"] = metadata["tags"]
    if metadata.get("source_file"):
        schema["source_file"] = metadata["source_file"]
    return schema


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
        "Search this MCP server's live tool catalog by name, description, or schema",
        {"query": {"type": "string"}, "limit": {"type": "integer", "minimum": 1, "maximum": 1000}, "include_schema": {"type": "boolean"}},
        ["query"],
    ),
    tool_schema(
        "list_tools",
        "Return this MCP server's live tool catalog",
        {"query": {"type": "string"}, "limit": {"type": "integer", "minimum": 1, "maximum": 10000}, "include_schema": {"type": "boolean"}},
        [],
    ),
    tool_schema(
        "call_tool",
        "Call a currently registered MCP tool by name with an arguments object",
        {"name": {"type": "string"}, "arguments": {"type": "object"}},
        ["name"],
    ),
    tool_schema(
        "mcp_call_tool",
        "Alias for call_tool",
        {"name": {"type": "string"}, "arguments": {"type": "object"}},
        ["name"],
    ),
    tool_schema(
        "mcp_protocol_status",
        "Return MCP protocol support, endpoint metadata, and implemented upstream Home Assistant MCP tool parity",
        {},
        [],
    ),
    tool_schema(
        "refresh_tool_catalog",
        "Return the current tool catalog fingerprint and MCP list-changed notification payload",
        {"include_tools": {"type": "boolean"}, "include_schema": {"type": "boolean"}, "query": {"type": "string"}, "limit": {"type": "integer", "minimum": 1, "maximum": 10000}},
        [],
    ),
    tool_schema(
        "batch_call_tools",
        "Call multiple registered MCP tools sequentially and return per-call results",
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
    tool_schema("stat_path", "Return filesystem metadata. Defaults to /config; relative paths are /config-relative.", {"path": {"type": "string"}}, []),
    tool_schema(
        "list_dir",
        "List a directory. Defaults to /config; relative paths are /config-relative.",
        {"path": {"type": "string"}, "limit": {"type": "integer", "minimum": 1, "maximum": 10000}},
        [],
    ),
    tool_schema(
        "read_file",
        "Read a visible file. Relative paths are /config-relative.",
        {"path": {"type": "string"}, "max_bytes": {"type": "integer", "minimum": 1, "maximum": 100000000}},
        ["path"],
    ),
    tool_schema(
        "read_file_window",
        "Read a byte window from a visible file. Relative paths are /config-relative.",
        {"path": {"type": "string"}, "offset": {"type": "integer", "minimum": 0}, "length": {"type": "integer", "minimum": 1, "maximum": 10000000}},
        ["path"],
    ),
    tool_schema(
        "read_file_lines",
        "Read a line-numbered window from a visible text file. Relative paths are /config-relative.",
        {"path": {"type": "string"}, "start_line": {"type": "integer", "minimum": 1}, "line_count": {"type": "integer", "minimum": 1, "maximum": 10000}},
        ["path"],
    ),
    tool_schema(
        "read_file_base64",
        "Read any visible file as base64. Relative paths are /config-relative.",
        {"path": {"type": "string"}, "max_bytes": {"type": "integer", "minimum": 1, "maximum": 100000000}},
        ["path"],
    ),
    tool_schema(
        "write_file_base64",
        "Write a visible file from base64 content. Relative paths are /config-relative.",
        {"path": {"type": "string"}, "content_base64": {"type": "string"}, "mode": {"type": "string"}, "dry_run": {"type": "boolean"}, "expected_hash": {"type": "string"}},
        ["path", "content_base64"],
    ),
    tool_schema(
        "write_file",
        "Write a file visible to the app. Relative paths are /config-relative.",
        {"path": {"type": "string"}, "content": {"type": "string"}, "mode": {"type": "string"}, "dry_run": {"type": "boolean"}, "expected_hash": {"type": "string"}},
        ["path", "content"],
    ),
    tool_schema(
        "delete_path",
        "Delete any visible file or directory. Relative paths are /config-relative.",
        {"path": {"type": "string"}, "recursive": {"type": "boolean"}, "force": {"type": "boolean"}, "dry_run": {"type": "boolean"}},
        ["path"],
    ),
    tool_schema(
        "search_files",
        "Search filenames and text file contents. Defaults to /config; relative paths are /config-relative.",
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
        "glob_paths",
        "Expand filesystem glob patterns visible to the app",
        {"pattern": {"type": "string"}, "limit": {"type": "integer", "minimum": 1, "maximum": 10000}},
        ["pattern"],
    ),
    tool_schema(
        "hash_file",
        "Return cryptographic hashes for a visible file. Relative paths are /config-relative.",
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
    tool_schema("get_automation", "Get the full live automation config plus entity state/source context", {"entity_id": {"type": "string"}, "id": {"type": "string"}, "query": {"type": "string"}, "context_lines": {"type": "integer", "minimum": 1, "maximum": 200}}, []),
    tool_schema("patch_automation", "Patch a live automation config by id/entity/query with shallow or deep object merge", {"entity_id": {"type": "string"}, "id": {"type": "string"}, "identifier": {"type": "string"}, "query": {"type": "string"}, "patch": {"type": "object"}, "replace": {"type": "object"}, "remove_keys": {"type": "array", "items": {"type": "string"}}, "deep": {"type": "boolean"}, "config_hash": {"type": "string"}, "dry_run": {"type": "boolean"}, "check_config": {"type": "boolean"}, "reload": {"type": "boolean"}}, []),
    tool_schema("rename_automation", "Rename an automation alias while preserving its config id", {"entity_id": {"type": "string"}, "id": {"type": "string"}, "query": {"type": "string"}, "alias": {"type": "string"}, "dry_run": {"type": "boolean"}, "check_config": {"type": "boolean"}, "reload": {"type": "boolean"}}, ["alias"]),
    tool_schema("duplicate_automation", "Copy an existing automation to a new id with optional alias and disabled state", {"source_entity_id": {"type": "string"}, "source_id": {"type": "string"}, "source_query": {"type": "string"}, "new_id": {"type": "string"}, "alias": {"type": "string"}, "enabled": {"type": "boolean"}, "dry_run": {"type": "boolean"}, "check_config": {"type": "boolean"}, "reload": {"type": "boolean"}}, ["new_id"]),
    tool_schema("automation_control", "Run an automation service action: enable, disable, toggle, trigger, reload, turn_on, or turn_off", {"entity_id": {"type": "string"}, "id": {"type": "string"}, "query": {"type": "string"}, "action": {"type": "string", "enum": ["enable", "disable", "toggle", "trigger", "reload", "turn_on", "turn_off"]}, "skip_condition": {"type": "boolean"}, "dry_run": {"type": "boolean"}}, ["action"]),
    tool_schema("trigger_automation", "Trigger one automation with optional skip_condition", {"entity_id": {"type": "string"}, "id": {"type": "string"}, "query": {"type": "string"}, "skip_condition": {"type": "boolean"}, "dry_run": {"type": "boolean"}}, []),
    tool_schema("enable_automation", "Enable one automation entity", {"entity_id": {"type": "string"}, "id": {"type": "string"}, "query": {"type": "string"}, "dry_run": {"type": "boolean"}}, []),
    tool_schema("disable_automation", "Disable one automation entity", {"entity_id": {"type": "string"}, "id": {"type": "string"}, "query": {"type": "string"}, "dry_run": {"type": "boolean"}}, []),
    tool_schema("reload_automations", "Reload Home Assistant automations through automation.reload", {"dry_run": {"type": "boolean"}}, []),
    tool_schema("automation_diagnostics", "Return automation state, full config, source context, traces, and optional latest trace in one bundle", {"entity_id": {"type": "string"}, "id": {"type": "string"}, "query": {"type": "string"}, "include_trace": {"type": "boolean"}, "latest": {"type": "boolean"}, "limit": {"type": "integer", "minimum": 1, "maximum": 10000}, "context_lines": {"type": "integer", "minimum": 1, "maximum": 200}}, []),
    tool_schema("list_script_configs", "List script entities compactly with config ids and source hints", {"query": {"type": "string"}, "limit": {"type": "integer", "minimum": 1, "maximum": 10000}}, []),
    tool_schema("get_script_config", "Get compact script config/source context by entity_id, id, or query", {"entity_id": {"type": "string"}, "id": {"type": "string"}, "query": {"type": "string"}, "context_lines": {"type": "integer", "minimum": 1, "maximum": 200}}, []),
    tool_schema("list_scene_configs", "List scene entities compactly with config ids and source hints", {"query": {"type": "string"}, "limit": {"type": "integer", "minimum": 1, "maximum": 10000}}, []),
    tool_schema("get_scene_config", "Get compact scene config/source context by entity_id, id, or query", {"entity_id": {"type": "string"}, "id": {"type": "string"}, "query": {"type": "string"}, "context_lines": {"type": "integer", "minimum": 1, "maximum": 200}}, []),
    tool_schema("list_traces", "List Home Assistant automation or script traces through the live WebSocket trace/list API", {"domain": {"type": "string", "enum": ["automation", "script"]}, "entity_id": {"type": "string"}, "id": {"type": "string"}, "item_id": {"type": "string"}, "limit": {"type": "integer", "minimum": 1, "maximum": 10000}}, ["domain"]),
    tool_schema("get_trace", "Read one Home Assistant automation or script trace by run_id through the live WebSocket trace/get API", {"domain": {"type": "string", "enum": ["automation", "script"]}, "entity_id": {"type": "string"}, "id": {"type": "string"}, "item_id": {"type": "string"}, "run_id": {"type": "string"}, "latest": {"type": "boolean"}}, ["domain"]),
    tool_schema("list_trace_contexts", "List Home Assistant automation or script trace contexts through the live WebSocket trace/contexts API", {"domain": {"type": "string", "enum": ["automation", "script"]}, "entity_id": {"type": "string"}, "id": {"type": "string"}, "item_id": {"type": "string"}}, ["domain"]),
    tool_schema("get_automation_traces", "List automation traces and optionally fetch a specific or latest run", {"entity_id": {"type": "string"}, "id": {"type": "string"}, "item_id": {"type": "string"}, "run_id": {"type": "string"}, "latest": {"type": "boolean"}, "include_trace": {"type": "boolean"}, "limit": {"type": "integer", "minimum": 1, "maximum": 10000}}, []),
    tool_schema("active_config_index", "Return a compact index of the active /config tree, packages, blueprints, templates, and key YAML files", {"limit": {"type": "integer", "minimum": 1, "maximum": 10000}}, []),
    tool_schema("search_active_config", "Search active /config YAML, package, template, and blueprint files with /config or relative paths accepted", {"query": {"type": "string"}, "path": {"type": "string"}, "filename": {"type": "string"}, "limit": {"type": "integer", "minimum": 1, "maximum": 10000}, "context_lines": {"type": "integer", "minimum": 0, "maximum": 50}}, ["query"]),
    tool_schema("list_template_configs", "Find template configuration blocks in templates.yaml, configuration.yaml, and package YAML", {"query": {"type": "string"}, "limit": {"type": "integer", "minimum": 1, "maximum": 10000}, "context_lines": {"type": "integer", "minimum": 1, "maximum": 200}}, []),
    tool_schema("get_template_config", "Get template source context by entity_id, unique text, or query", {"entity_id": {"type": "string"}, "query": {"type": "string"}, "context_lines": {"type": "integer", "minimum": 1, "maximum": 200}}, []),
    tool_schema("list_blueprints", "List blueprint YAML files under /config/blueprints", {"domain": {"type": "string"}, "query": {"type": "string"}, "limit": {"type": "integer", "minimum": 1, "maximum": 10000}}, []),
    tool_schema("read_blueprint", "Read one blueprint YAML file by relative path or domain/name", {"path": {"type": "string"}, "domain": {"type": "string"}, "name": {"type": "string"}, "max_bytes": {"type": "integer", "minimum": 1, "maximum": 100000000}}, []),
    tool_schema("search_blueprints", "Search blueprint YAML files under /config/blueprints", {"query": {"type": "string"}, "domain": {"type": "string"}, "limit": {"type": "integer", "minimum": 1, "maximum": 10000}, "context_lines": {"type": "integer", "minimum": 0, "maximum": 50}}, ["query"]),
    tool_schema("get_recorder_config", "Find recorder config source context and return recorder DB info", {"query": {"type": "string"}, "context_lines": {"type": "integer", "minimum": 1, "maximum": 200}}, []),
    tool_schema("write_recorder_package", "Write a dedicated /config/packages recorder YAML file with dry-run, backup, and config check", {"filename": {"type": "string"}, "config": {"type": "object"}, "content": {"type": "string"}, "backup": {"type": "boolean"}, "dry_run": {"type": "boolean"}, "expected_hash": {"type": "string"}, "check_config": {"type": "boolean"}, "force": {"type": "boolean"}}, []),
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
    tool_schema("list_registries", "List known Home Assistant registries exposed by the Admin App", {"include_counts": {"type": "boolean"}}, []),
    tool_schema(
        "read_registry",
        "Read one Home Assistant registry by registry name or storage key",
        {"registry": {"type": "string"}, "key": {"type": "string"}, "include_entries": {"type": "boolean"}, "limit": {"type": "integer", "minimum": 1, "maximum": 100000}},
        [],
    ),
    tool_schema(
        "search_registry",
        "Search any known Home Assistant registry with exact filters plus text query",
        {
            "registry": {"type": "string"},
            "key": {"type": "string"},
            "filters": {"type": "object"},
            "query": {"type": "string"},
            "limit": {"type": "integer", "minimum": 1, "maximum": 10000},
        },
        [],
    ),
    tool_schema(
        "get_registry_entry",
        "Get exactly one registry entry by registry name/key and selectors or query",
        {
            "registry": {"type": "string"},
            "key": {"type": "string"},
            "id": {"type": "string"},
            "entity_id": {"type": "string"},
            "unique_id": {"type": "string"},
            "entry_id": {"type": "string"},
            "name": {"type": "string"},
            "domain": {"type": "string"},
            "title": {"type": "string"},
            "query": {"type": "string"},
        },
        [],
    ),
    tool_schema(
        "create_registry_entry",
        "Append one entry to a Home Assistant registry, or upsert when upsert=true",
        {
            "registry": {"type": "string"},
            "key": {"type": "string"},
            "entry": {"type": "object"},
            "upsert": {"type": "boolean"},
            "backup": {"type": "boolean"},
            "dry_run": {"type": "boolean"},
            "expected_hash": {"type": "string"},
        },
        ["entry"],
    ),
    tool_schema(
        "replace_registry_entry",
        "Replace exactly one Home Assistant registry entry with a full object",
        {
            "registry": {"type": "string"},
            "key": {"type": "string"},
            "entry": {"type": "object"},
            "id": {"type": "string"},
            "entity_id": {"type": "string"},
            "unique_id": {"type": "string"},
            "entry_id": {"type": "string"},
            "name": {"type": "string"},
            "domain": {"type": "string"},
            "title": {"type": "string"},
            "query": {"type": "string"},
            "backup": {"type": "boolean"},
            "dry_run": {"type": "boolean"},
            "expected_hash": {"type": "string"},
        },
        ["entry"],
    ),
    tool_schema(
        "patch_registry_entry",
        "Patch exactly one Home Assistant registry entry with dry-run, backup, and expected_hash support",
        {
            "registry": {"type": "string"},
            "key": {"type": "string"},
            "id": {"type": "string"},
            "entity_id": {"type": "string"},
            "unique_id": {"type": "string"},
            "entry_id": {"type": "string"},
            "name": {"type": "string"},
            "domain": {"type": "string"},
            "title": {"type": "string"},
            "query": {"type": "string"},
            "patch": {"type": "object"},
            "remove_keys": {"type": "array", "items": {"type": "string"}},
            "backup": {"type": "boolean"},
            "dry_run": {"type": "boolean"},
            "expected_hash": {"type": "string"},
        },
        [],
    ),
    tool_schema(
        "delete_registry_entry",
        "Delete exactly one Home Assistant registry entry; requires force=true unless dry_run=true",
        {
            "registry": {"type": "string"},
            "key": {"type": "string"},
            "id": {"type": "string"},
            "entity_id": {"type": "string"},
            "unique_id": {"type": "string"},
            "entry_id": {"type": "string"},
            "name": {"type": "string"},
            "domain": {"type": "string"},
            "title": {"type": "string"},
            "query": {"type": "string"},
            "force": {"type": "boolean"},
            "backup": {"type": "boolean"},
            "dry_run": {"type": "boolean"},
            "expected_hash": {"type": "string"},
        },
        [],
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
        "search_category_registry",
        "Filter core.category_registry without returning the whole file",
        {"id": {"type": "string"}, "name": {"type": "string"}, "scope": {"type": "string"}, "query": {"type": "string"}, "limit": {"type": "integer", "minimum": 1, "maximum": 10000}},
        [],
    ),
    tool_schema("get_config_entry", "Get exactly one core.config_entries entry by entry_id, domain/title query, or source", {"entry_id": {"type": "string"}, "domain": {"type": "string"}, "title": {"type": "string"}, "source": {"type": "string"}, "query": {"type": "string"}}, []),
    tool_schema("patch_config_entry", "Patch exactly one core.config_entries entry with dry-run, backup, and expected_hash support", {"entry_id": {"type": "string"}, "domain": {"type": "string"}, "title": {"type": "string"}, "source": {"type": "string"}, "query": {"type": "string"}, "patch": {"type": "object"}, "replace": {"type": "object"}, "remove_keys": {"type": "array", "items": {"type": "string"}}, "backup": {"type": "boolean"}, "dry_run": {"type": "boolean"}, "expected_hash": {"type": "string"}}, []),
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


IMPLEMENTED_UPSTREAM_HA_MCP_TOOL_NAMES = [
    name for name in UPSTREAM_HA_MCP_TOOL_NAMES if name not in UNIMPLEMENTED_UPSTREAM_TOOL_NAMES
]
UPSTREAM_COMPAT_TOOL_SCHEMAS = [upstream_compat_schema(name) for name in IMPLEMENTED_UPSTREAM_HA_MCP_TOOL_NAMES]
HA_ADMIN_COMPAT_EXTENSION_TOOL_SCHEMAS = [
    tool_schema(
        "ha_search_entities",
        "HA Admin extension: search Home Assistant entities with optional domain filtering",
        {"query": {"type": "string"}, "name": {"type": "string"}, "limit": {"type": "integer", "minimum": 1, "maximum": 1000}, "domain": {"type": "string"}, "domain_filter": {"type": "string"}},
        [],
    ),
    tool_schema(
        "ha_deep_search",
        "HA Admin extension: search entities, active config, storage, files, and tools from one query",
        {"query": {"type": "string"}, "limit": {"type": "integer", "minimum": 1, "maximum": 1000}},
        ["query"],
    ),
    tool_schema(
        "ha_search_tools",
        "HA Admin extension: search this server's live tool catalog",
        {"query": {"type": "string"}, "limit": {"type": "integer", "minimum": 1, "maximum": 1000}, "include_schema": {"type": "boolean"}},
        ["query"],
    ),
    tool_schema(
        "ha_call_read_tool",
        "HA Admin extension: call a registered read-oriented tool by name",
        {"name": {"type": "string"}, "tool": {"type": "string"}, "arguments": {"type": "object"}},
        [],
    ),
    tool_schema(
        "ha_call_write_tool",
        "HA Admin extension: call a registered write-oriented tool by name",
        {"name": {"type": "string"}, "tool": {"type": "string"}, "arguments": {"type": "object"}},
        [],
    ),
    tool_schema(
        "ha_call_delete_tool",
        "HA Admin extension: call a registered delete/remove-oriented tool by name",
        {"name": {"type": "string"}, "tool": {"type": "string"}, "arguments": {"type": "object"}},
        [],
    ),
]


TOOLS.extend(UPSTREAM_COMPAT_TOOL_SCHEMAS)
TOOLS.extend(HA_ADMIN_COMPAT_EXTENSION_TOOL_SCHEMAS)


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
    if name in IMPLEMENTED_UPSTREAM_HA_MCP_TOOL_NAMES or name in HA_ADMIN_COMPAT_EXTENSION_TOOL_NAMES:
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
        return search_tools(args["query"], int(args.get("limit") or 50), bool(args.get("include_schema")))
    if name == "list_tools":
        return list_tools(args)
    if name in ("call_tool", "mcp_call_tool"):
        return proxy_call_tool(args, proxy_name=name)
    if name == "mcp_protocol_status":
        return mcp_protocol_status()
    if name == "refresh_tool_catalog":
        return refresh_tool_catalog(args)
    if name == "batch_call_tools":
        return batch_call_tools(args)
    if name == "stat_path":
        path = visible_path(args.get("path"))
        return path_info(path) if path.exists() or path.is_symlink() else {"path": str(path), "exists": False}
    if name == "list_dir":
        path = visible_path(args.get("path"))
        limit = int(args.get("limit") or 500)
        return [path_info(child) for child in list(path.iterdir())[:limit]]
    if name == "read_file":
        path = visible_path(args.get("path"))
        content, truncated = read_limited(path, int(args.get("max_bytes") or MAX_READ_BYTES))
        return {"path": str(path), "content": content, "truncated": truncated}
    if name == "read_file_window":
        return read_file_window(visible_path(args.get("path")), int(args.get("offset") or 0), int(args.get("length") or 100000))
    if name == "read_file_lines":
        return read_file_lines(visible_path(args.get("path")), int(args.get("start_line") or 1), int(args.get("line_count") or 200))
    if name == "read_file_base64":
        path = visible_path(args.get("path"))
        data, truncated = read_bytes_limited(path, int(args.get("max_bytes") or MAX_READ_BYTES))
        return {"path": str(path), "content_base64": base64.b64encode(data).decode(), "truncated": truncated}
    if name == "write_file":
        path = visible_path(args.get("path"), require=True)
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
        path = visible_path(args.get("path"), require=True)
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
        path = visible_path(args.get("path"), require=True)
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
        return hash_file(visible_path(args.get("path")), args.get("algorithm") or "sha256")
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
        if is_self_addon_slug(args.get("slug")) and args.get("action") in SELF_UPDATE_ACTIONS:
            return self_update_not_supported(str(args["slug"]), str(args["action"]))
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
    if name == "get_automation":
        return get_automation(args)
    if name == "patch_automation":
        return patch_automation(args)
    if name == "rename_automation":
        return rename_automation(args)
    if name == "duplicate_automation":
        return duplicate_automation(args)
    if name == "automation_control":
        return automation_control(args)
    if name == "trigger_automation":
        return automation_control(args | {"action": "trigger"})
    if name == "enable_automation":
        return automation_control(args | {"action": "enable"})
    if name == "disable_automation":
        return automation_control(args | {"action": "disable"})
    if name == "reload_automations":
        return automation_control(args | {"action": "reload"})
    if name == "automation_diagnostics":
        return automation_diagnostics(args)
    if name == "list_script_configs":
        return list_domain_configs("script", args)
    if name == "get_script_config":
        return get_domain_config("script", args)
    if name == "list_scene_configs":
        return list_domain_configs("scene", args)
    if name == "get_scene_config":
        return get_domain_config("scene", args)
    if name == "list_traces":
        return list_traces(args)
    if name == "get_trace":
        return get_trace(args)
    if name == "list_trace_contexts":
        return list_trace_contexts(args)
    if name == "get_automation_traces":
        return get_automation_traces(args)
    if name == "active_config_index":
        return active_config_index(args)
    if name == "search_active_config":
        return search_active_config(args)
    if name == "list_template_configs":
        return list_template_configs(args)
    if name == "get_template_config":
        return get_template_config(args)
    if name == "list_blueprints":
        return list_blueprints(args)
    if name == "read_blueprint":
        return read_blueprint(args)
    if name == "search_blueprints":
        return search_blueprints(args)
    if name == "get_recorder_config":
        return get_recorder_config(args)
    if name == "write_recorder_package":
        return write_recorder_package(args)
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
    if name == "list_registries":
        return list_registries(bool(args.get("include_counts")))
    if name == "read_registry":
        return read_registry(args)
    if name == "search_registry":
        return search_registry(args)
    if name == "get_registry_entry":
        return get_registry_entry(args)
    if name == "create_registry_entry":
        return create_registry_entry(args)
    if name == "replace_registry_entry":
        return replace_registry_entry(args)
    if name == "patch_registry_entry":
        return patch_any_registry_entry(args)
    if name == "delete_registry_entry":
        return delete_registry_entry(args)
    if name == "search_entity_registry":
        return search_entity_registry(args)
    if name == "get_entity_registry_entry":
        return get_entity_registry_entry(args)
    if name == "search_device_registry":
        return search_device_registry(args)
    if name == "search_config_entries":
        return search_config_entries(args)
    if name == "get_config_entry":
        return get_config_entry(args)
    if name == "patch_config_entry":
        return patch_config_entry(args)
    if name == "search_area_registry":
        return search_named_registry("core.area_registry", "areas", args)
    if name == "search_floor_registry":
        return search_named_registry("core.floor_registry", "floors", args)
    if name == "search_label_registry":
        return search_named_registry("core.label_registry", "labels", args)
    if name == "search_category_registry":
        return search_named_registry("core.category_registry", "categories", args)
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
        "app": {"name": "ha-admin-mcp", "version": APP_VERSION, "endpoint_path": MCP_PATH, "port": MCP_PORT},
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


def is_self_addon_slug(slug: str | None) -> bool:
    if not slug:
        return False
    normalized = slug.strip().lower().replace("-", "_")
    return normalized in SELF_ADDON_SLUGS


def self_update_not_supported(slug: str, action: str) -> dict[str, Any]:
    info: dict[str, Any] = {}
    try:
        result = supervisor_request("GET", f"/addons/{slug}/info")
        info = result.get("data", result) if isinstance(result, dict) else {}
    except Exception as err:
        info = {"error": str(err)}
    return {
        "success": False,
        "blocked": True,
        "slug": slug,
        "action": action,
        "reason": "Home Assistant Supervisor does not allow an add-on to update or rebuild itself through its own Supervisor token.",
        "supervisor_guard": "self_update_forbidden",
        "current_version": info.get("version"),
        "latest_version": info.get("version_latest"),
        "update_available": info.get("update_available"),
        "external_update_required": True,
        "external_update_paths": [
            "Use Home Assistant Settings > Add-ons > HA Admin MCP > Update.",
            "Call Supervisor /addons/{slug}/update from a different trusted add-on or host-level admin context.",
        ],
    }


def tool_catalog_row(tool: dict[str, Any], include_schema: bool = False) -> dict[str, Any]:
    row = {
        "name": tool["name"],
        "description": tool.get("description", ""),
        "required": tool.get("inputSchema", {}).get("required", []),
        "properties": sorted((tool.get("inputSchema", {}).get("properties") or {}).keys()),
    }
    if include_schema:
        row["inputSchema"] = tool.get("inputSchema", {})
    return row


def tool_catalog_fingerprint() -> str:
    payload = [
        {
            "name": tool.get("name"),
            "description": tool.get("description"),
            "inputSchema": tool.get("inputSchema"),
            "annotations": tool.get("annotations"),
        }
        for tool in sorted(TOOLS, key=lambda item: item["name"])
    ]
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()[:16]


def list_tools(args: dict[str, Any]) -> dict[str, Any]:
    query = str(args.get("query") or "").lower()
    limit = int(args.get("limit") or 1000)
    include_schema = bool(args.get("include_schema"))
    rows = []
    for tool in TOOLS:
        if query and query not in json.dumps(tool, default=str).lower():
            continue
        rows.append(tool_catalog_row(tool, include_schema))
        if len(rows) >= limit:
            break
    return {"query": query, "count": len(rows), "total": len(TOOLS), "tools": rows}


def search_tools(query: str, limit: int, include_schema: bool = False) -> dict[str, Any]:
    catalog = list_tools({"query": query, "limit": limit, "include_schema": include_schema})
    return {
        "query": catalog["query"],
        "count": catalog["count"],
        "total": catalog["total"],
        "tools": catalog["tools"],
        "matches": catalog["tools"],
        "catalog_hash": tool_catalog_fingerprint(),
    }


def refresh_tool_catalog(args: dict[str, Any]) -> dict[str, Any]:
    catalog = list_tools({
        "query": args.get("query") or "",
        "limit": int(args.get("limit") or 10000),
        "include_schema": bool(args.get("include_schema")),
    })
    result: dict[str, Any] = {
        "success": True,
        "catalog_hash": tool_catalog_fingerprint(),
        "tool_count": len(TOOLS),
        "upstream_ha_mcp_tool_count": len(UPSTREAM_HA_MCP_TOOL_NAMES),
        "implemented_upstream_ha_mcp_tool_count": len(IMPLEMENTED_UPSTREAM_HA_MCP_TOOL_NAMES),
        "unimplemented_upstream_ha_mcp_tools": sorted(UNIMPLEMENTED_UPSTREAM_TOOL_NAMES),
        "mcp_notification": {"jsonrpc": "2.0", "method": "notifications/tools/list_changed"},
    }
    if bool(args.get("include_tools")):
        result["catalog"] = catalog
    else:
        result["catalog_summary"] = {"query": catalog["query"], "count": catalog["count"], "total": catalog["total"]}
    return result


def proxy_call_tool(args: dict[str, Any], proxy_name: str) -> Any:
    target = args.get("name") or args.get("tool")
    if not target:
        raise ValueError("name is required")
    target_name = str(target)
    if target_name in {proxy_name, "call_tool", "mcp_call_tool", "batch_call_tools", "ha_call_read_tool", "ha_call_write_tool", "ha_call_delete_tool"}:
        raise ValueError("Refusing recursive proxy tool call")
    known = {tool["name"] for tool in TOOLS}
    if target_name not in known:
        matches = search_tools(target_name, 10).get("matches", [])
        raise ValueError(f"Unknown tool {target_name!r}. Matching tools: {[match['name'] for match in matches]}")
    return call_tool(target_name, args.get("arguments") or {})


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
            elif tool_name in {"batch_call_tools", "call_tool", "mcp_call_tool"}:
                row = {"index": index, "name": tool_name, "error": "Refusing recursive proxy tool call"}
            else:
                try:
                    row = {"index": index, "name": tool_name, "result": call_tool(tool_name, call.get("arguments") or {})}
                except Exception as err:
                    row = {"index": index, "name": tool_name, "error": str(err)}
        results.append(row)
        if stop_on_error and row.get("error"):
            break
    return {"count": len(results), "results": results}


def mcp_protocol_status() -> dict[str, Any]:
    tool_names = {tool["name"] for tool in TOOLS}
    implemented = set(IMPLEMENTED_UPSTREAM_HA_MCP_TOOL_NAMES)
    return {
        "app": {"name": "ha-admin-mcp", "version": APP_VERSION, "endpoint_path": MCP_PATH, "port": MCP_PORT},
        "transport": {
            "kind": "streamable_http_json",
            "post": True,
            "get": "405_no_sse_stream",
            "delete": "202_session_close_ack",
            "session_header": "Mcp-Session-Id",
            "protocol_version_header": "MCP-Protocol-Version",
        },
        "protocol_versions": sorted(SUPPORTED_PROTOCOL_VERSIONS),
        "server_capabilities": {
            "tools": {"listChanged": True, "paginated": True},
            "resources": {"subscribe": False, "listChanged": True, "paginated": True},
            "resourceTemplates": {"paginated": True},
            "prompts": {"listChanged": True, "paginated": True},
            "completions": True,
            "logging": True,
        },
        "server_methods": [
            "initialize",
            "tools/list",
            "tools/call",
            "resources/list",
            "resources/read",
            "resources/templates/list",
            "resources/subscribe",
            "resources/unsubscribe",
            "prompts/list",
            "prompts/get",
            "completion/complete",
            "logging/setLevel",
            "ping",
            "notifications/*",
        ],
        "tool_counts": {
            "total": len(tool_names),
            "upstream_homeassistant_ai_standard": len(UPSTREAM_HA_MCP_TOOL_NAMES),
            "upstream_homeassistant_ai_implemented": len(implemented),
            "upstream_homeassistant_ai_implemented_missing": len(implemented - tool_names),
            "ha_admin_extensions": len(HA_ADMIN_COMPAT_EXTENSION_TOOL_NAMES),
        },
        "upstream_homeassistant_ai_implemented_missing": sorted(implemented - tool_names),
        "unimplemented_upstream_homeassistant_ai_tools": sorted(UNIMPLEMENTED_UPSTREAM_TOOL_NAMES),
        "ha_admin_extension_tools": HA_ADMIN_COMPAT_EXTENSION_TOOL_NAMES,
    }


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
        "template": ["templates.yaml", "configuration.yaml"],
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


def automation_item_id(args: dict[str, Any]) -> str:
    item_id = config_item_id("automation", args)
    if not item_id:
        raise ValueError("automation id, entity_id, or query is required")
    return item_id


def automation_entity_id(args: dict[str, Any]) -> str:
    raw = first_present(args, "entity_id", "id", "identifier", "item_id", "name")
    if raw:
        text = str(raw)
        if text.startswith("automation."):
            return text
        if "." not in text:
            return f"automation.{text}"
    item_id = automation_item_id(args)
    return f"automation.{item_id}"


def get_automation(args: dict[str, Any]) -> dict[str, Any]:
    item_id = automation_item_id(args)
    endpoint = f"/config/automation/config/{item_id}"
    config = ha_request("GET", endpoint)
    normalized_config = normalize_automation_config(config) if isinstance(config, dict) else config
    context = get_domain_config("automation", args | {"id": item_id, "context_lines": int(args.get("context_lines") or 20)})
    return {
        "domain": "automation",
        "id": item_id,
        "endpoint": endpoint,
        "config": normalized_config,
        "config_hash": compute_config_hash(normalized_config) if isinstance(normalized_config, dict) else None,
        "raw_config": config,
        "state": context.get("state"),
        "matches": context.get("matches"),
        "source_contexts": context.get("source_contexts"),
    }


def merge_dicts(base: dict[str, Any], patch: dict[str, Any], deep: bool = True) -> dict[str, Any]:
    merged = json.loads(json.dumps(base, default=str))
    for key, value in patch.items():
        if deep and isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = merge_dicts(merged[key], value, deep=True)
        else:
            merged[key] = value
    return merged


def patch_automation(args: dict[str, Any]) -> dict[str, Any]:
    item_id = automation_item_id(args)
    current = ha_request("GET", f"/config/automation/config/{item_id}")
    if not isinstance(current, dict):
        raise ValueError("Current automation config is not an object")
    current = normalize_automation_config(current)
    if args.get("config_hash") and compute_config_hash(current) != str(args["config_hash"]):
        raise ValueError("config_hash mismatch; call get_automation again and retry with the fresh hash")
    before = json.loads(json.dumps(current, default=str))
    if args.get("replace") is not None:
        if not isinstance(args["replace"], dict):
            raise ValueError("replace must be an object")
        after = args["replace"]
    else:
        after = json.loads(json.dumps(current, default=str))
        for key_name in args.get("remove_keys") or []:
            after.pop(str(key_name), None)
        patch = args.get("patch") or {}
        if patch:
            if not isinstance(patch, dict):
                raise ValueError("patch must be an object")
            after = merge_dicts(after, patch, deep=bool(args.get("deep", True)))
    after = normalize_automation_config(after)
    after_hash = compute_config_hash(after)
    if bool(args.get("dry_run")):
        return {"domain": "automation", "id": item_id, "endpoint": f"/config/automation/config/{item_id}", "dry_run": True, "before": before, "after": after, "before_hash": compute_config_hash(before), "after_hash": after_hash}
    result = update_config_item("automation", args | {"id": item_id, "config": after})
    return {"domain": "automation", "id": item_id, "before": before, "after": after, "before_hash": compute_config_hash(before), "after_hash": after_hash, "result": result}


def rename_automation(args: dict[str, Any]) -> dict[str, Any]:
    return patch_automation(args | {"patch": {"alias": args["alias"]}})


def duplicate_automation(args: dict[str, Any]) -> dict[str, Any]:
    source_args = {
        "id": args.get("source_id"),
        "entity_id": args.get("source_entity_id"),
        "query": args.get("source_query"),
    }
    source_id = automation_item_id(source_args)
    new_id = str(args["new_id"])
    source = ha_request("GET", f"/config/automation/config/{source_id}")
    if not isinstance(source, dict):
        raise ValueError("Source automation config is not an object")
    new_config = normalize_automation_config(json.loads(json.dumps(source, default=str)))
    new_config["id"] = new_id
    if args.get("alias"):
        new_config["alias"] = args["alias"]
    if args.get("enabled") is not None:
        new_config["enabled"] = bool(args["enabled"])
    if bool(args.get("dry_run")):
        return {"domain": "automation", "source_id": source_id, "new_id": new_id, "dry_run": True, "would_write": new_config}
    result = update_config_item("automation", args | {"id": new_id, "config": new_config})
    return {"domain": "automation", "source_id": source_id, "new_id": new_id, "config": new_config, "result": result}


def automation_control(args: dict[str, Any]) -> dict[str, Any]:
    action = str(args["action"])
    service = {
        "enable": "turn_on",
        "disable": "turn_off",
        "turn_on": "turn_on",
        "turn_off": "turn_off",
        "toggle": "toggle",
        "trigger": "trigger",
        "reload": "reload",
    }.get(action)
    if not service:
        raise ValueError(f"Unsupported automation action: {action}")
    data: dict[str, Any] = {}
    entity_id = None
    if service != "reload":
        entity_id = automation_entity_id(args)
        data["entity_id"] = entity_id
    if service == "trigger":
        data["skip_condition"] = bool(args.get("skip_condition", True))
    endpoint = f"/services/automation/{service}"
    if bool(args.get("dry_run")):
        return {"domain": "automation", "action": action, "service": service, "endpoint": endpoint, "dry_run": True, "would_call": data}
    audit_event("automation_control", {"action": action, "service": service, "entity_id": entity_id})
    result = ha_request("POST", endpoint, data)
    return {"domain": "automation", "action": action, "service": service, "entity_id": entity_id, "result": result}


def automation_diagnostics(args: dict[str, Any]) -> dict[str, Any]:
    item_id = automation_item_id(args)
    entity_id = automation_entity_id(args | {"id": item_id})
    result = get_automation(args | {"id": item_id})
    result["traces"] = get_automation_traces({
        "id": item_id,
        "entity_id": entity_id,
        "include_trace": bool(args.get("include_trace")),
        "latest": bool(args.get("latest", True)),
        "limit": int(args.get("limit") or 10),
    })
    try:
        result["config_check"] = run_config_check()
    except Exception as err:
        result["config_check_error"] = str(err)
    return result


def get_automation_traces(args: dict[str, Any]) -> dict[str, Any]:
    trace_args = dict(args)
    trace_args["domain"] = "automation"
    listed = list_traces(trace_args)
    result = {"domain": "automation", "item_id": listed.get("item_id"), "entity_id": listed.get("entity_id"), "count": listed.get("count"), "traces": listed.get("traces", [])}
    run_id = args.get("run_id")
    if not run_id and bool(args.get("latest") or args.get("include_trace")) and result["traces"]:
        run_id = result["traces"][0].get("run_id")
    if run_id:
        result["trace"] = get_trace({"domain": "automation", "item_id": listed.get("item_id"), "run_id": run_id})
    return result


def trace_item_id(domain: str, args: dict[str, Any]) -> tuple[str | None, str | None]:
    identifier = args.get("item_id") or args.get("id") or args.get("entity_id")
    if not identifier:
        return None, None
    text = str(identifier)
    entity_id = text if text.startswith(f"{domain}.") else args.get("entity_id")
    item_id = text.removeprefix(f"{domain}.")
    if entity_id:
        try:
            state = ha_request("GET", f"/states/{entity_id}")
            attrs = state.get("attributes") or {}
            item_id = str(attrs.get("id") or item_id)
        except Exception:
            pass
    return item_id, str(entity_id) if entity_id else None


def list_traces(args: dict[str, Any]) -> dict[str, Any]:
    domain = str(args["domain"])
    item_id, entity_id = trace_item_id(domain, args)
    message: dict[str, Any] = {"type": "trace/list", "domain": domain}
    if item_id:
        message["item_id"] = item_id
    response = ha_ws_call(message)
    if not response.get("success"):
        return {"domain": domain, "item_id": item_id, "entity_id": entity_id, "success": False, "error": response.get("error"), "raw": response}
    traces = response.get("result") or []
    if isinstance(traces, list):
        traces = sorted(traces, key=lambda row: (((row.get("timestamp") or {}).get("start")) or ""), reverse=True)
        traces = traces[: int(args.get("limit") or 100)]
    return {"domain": domain, "item_id": item_id, "entity_id": entity_id, "success": True, "count": len(traces) if isinstance(traces, list) else None, "traces": traces}


def get_trace(args: dict[str, Any]) -> dict[str, Any]:
    domain = str(args["domain"])
    item_id, entity_id = trace_item_id(domain, args)
    if not item_id:
        raise ValueError("Pass item_id, id, or entity_id")
    run_id = args.get("run_id")
    listed = None
    if not run_id and bool(args.get("latest")):
        listed = list_traces({"domain": domain, "item_id": item_id, "limit": 1})
        if listed.get("traces"):
            run_id = listed["traces"][0].get("run_id")
    if not run_id:
        raise ValueError("Pass run_id or latest=true")
    response = ha_ws_call({"type": "trace/get", "domain": domain, "item_id": item_id, "run_id": str(run_id)})
    return {"domain": domain, "item_id": item_id, "entity_id": entity_id, "run_id": str(run_id), "success": bool(response.get("success")), "trace": response.get("result"), "error": response.get("error"), "listed": listed}


def list_trace_contexts(args: dict[str, Any]) -> dict[str, Any]:
    domain = str(args["domain"])
    item_id, entity_id = trace_item_id(domain, args)
    message: dict[str, Any] = {"type": "trace/contexts"}
    if item_id:
        message.update({"domain": domain, "item_id": item_id})
    response = ha_ws_call(message)
    return {"domain": domain, "item_id": item_id, "entity_id": entity_id, "success": bool(response.get("success")), "contexts": response.get("result"), "error": response.get("error")}


def yaml_config_files(include_blueprints: bool = False) -> list[Path]:
    roots = [CONFIG_ROOT]
    packages = config_path("packages")
    if packages.exists():
        roots.append(packages)
    if include_blueprints:
        blueprints = config_path("blueprints")
        if blueprints.exists():
            roots.append(blueprints)
    seen: set[Path] = set()
    files: list[Path] = []
    for root in roots:
        if root.is_file():
            candidates = [root]
        else:
            candidates = list(root.rglob("*.yaml")) + list(root.rglob("*.yml"))
        for path in candidates:
            resolved = path.resolve()
            if resolved in seen or not path.is_file():
                continue
            try:
                path.relative_to(CONFIG_ROOT)
            except ValueError:
                continue
            seen.add(resolved)
            files.append(path)
    return sorted(files, key=lambda item: str(item.relative_to(CONFIG_ROOT)))


def active_config_index(args: dict[str, Any]) -> dict[str, Any]:
    limit = int(args.get("limit") or 1000)
    yaml_files = yaml_config_files(include_blueprints=True)
    key_files = []
    for rel in ("configuration.yaml", "automations.yaml", "scripts.yaml", "scenes.yaml", "templates.yaml", "secrets.yaml"):
        path = config_path(rel)
        if path.exists():
            key_files.append(path_info(path) | {"relative_path": rel})
    packages = [path_info(path) | {"relative_path": str(path.relative_to(CONFIG_ROOT))} for path in yaml_config_files() if "packages" in path.relative_to(CONFIG_ROOT).parts]
    blueprints = list_blueprints({"limit": limit})
    template_hits = list_template_configs({"limit": 50, "context_lines": 3})
    return {
        "config_root": str(CONFIG_ROOT),
        "key_files": key_files,
        "yaml_file_count": len(yaml_files),
        "yaml_files": [str(path.relative_to(CONFIG_ROOT)) for path in yaml_files[:limit]],
        "packages": packages[:limit],
        "blueprints": blueprints,
        "template_sources": template_hits,
    }


def search_active_config(args: dict[str, Any]) -> dict[str, Any]:
    root = config_path(args.get("path") or ".")
    search_args = {
        "path": str(root),
        "query": args.get("query"),
        "filename": args.get("filename"),
        "recursive": True,
        "limit": int(args.get("limit") or 100),
        "max_file_bytes": args.get("max_file_bytes") or 5_000_000,
    }
    matches = search_files(search_args)
    context_lines = int(args.get("context_lines") or 0)
    if context_lines > 0:
        for match in matches:
            if "line" in match and match.get("path"):
                match["context"] = read_file_lines(Path(match["path"]), max(1, int(match["line"]) - context_lines // 2), context_lines)
                try:
                    match["relative_path"] = str(Path(match["path"]).resolve().relative_to(CONFIG_ROOT))
                except ValueError:
                    pass
    return {"root": str(root), "query": args.get("query"), "count": len(matches), "matches": matches}


def template_source_files() -> list[Path]:
    files: list[Path] = []
    for rel_path in config_reference_files("template"):
        path = config_path(rel_path)
        if path.exists() and path.is_file():
            files.append(path)
    for path in yaml_config_files():
        if "packages" in path.relative_to(CONFIG_ROOT).parts and path not in files:
            files.append(path)
    return files


def list_template_configs(args: dict[str, Any]) -> dict[str, Any]:
    query = str(args.get("query") or "").lower()
    limit = int(args.get("limit") or 100)
    context_lines = int(args.get("context_lines") or 20)
    matches: list[dict[str, Any]] = []
    for path in template_source_files():
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError as err:
            matches.append({"relative_path": str(path.relative_to(CONFIG_ROOT)), "error": str(err)})
            continue
        for number, line in enumerate(lines, 1):
            line_l = line.lower()
            if "template:" not in line_l and query and query not in line_l:
                continue
            if query and query not in "\n".join(lines[max(0, number - context_lines): min(len(lines), number + context_lines)]).lower():
                continue
            matches.append({"relative_path": str(path.relative_to(CONFIG_ROOT)), "match_line": number, "text": line[:500], "context": read_file_lines(path, max(1, number - context_lines // 2), context_lines)})
            if len(matches) >= limit:
                return {"count": len(matches), "matches": matches}
            if not query:
                break
    return {"count": len(matches), "matches": matches}


def get_template_config(args: dict[str, Any]) -> dict[str, Any]:
    query = args.get("query") or args.get("entity_id")
    if not query:
        raise ValueError("Pass entity_id or query")
    result = list_template_configs({"query": str(query), "limit": int(args.get("limit") or 20), "context_lines": int(args.get("context_lines") or 60)})
    result["query"] = query
    return result


def blueprint_root() -> Path:
    return config_path("blueprints")


def list_blueprints(args: dict[str, Any]) -> dict[str, Any]:
    root = blueprint_root()
    domain = str(args.get("domain") or "").strip("/")
    query = str(args.get("query") or "").lower()
    limit = int(args.get("limit") or 500)
    search_root = root / domain if domain else root
    rows = []
    if not search_root.exists():
        return {"root": str(search_root), "count": 0, "blueprints": []}
    for path in sorted(list(search_root.rglob("*.yaml")) + list(search_root.rglob("*.yml")), key=str):
        if len(rows) >= limit:
            break
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
            rel = str(path.relative_to(CONFIG_ROOT))
        except OSError as err:
            rows.append({"path": str(path), "error": str(err)})
            continue
        if query and query not in rel.lower() and query not in text.lower():
            continue
        rows.append(path_info(path) | {"relative_path": rel, "domain": path.relative_to(root).parts[0] if len(path.relative_to(root).parts) > 1 else None})
    return {"root": str(search_root), "count": len(rows), "blueprints": rows}


def resolve_blueprint_path(args: dict[str, Any]) -> Path:
    if args.get("path"):
        path_text = str(args["path"])
        if path_text.startswith("blueprints/"):
            return config_path(path_text)
        return config_path(str(Path("blueprints") / path_text))
    domain = args.get("domain")
    name = args.get("name")
    if not domain or not name:
        raise ValueError("Pass path or domain and name")
    candidates = list_blueprints({"domain": domain, "query": name, "limit": 20})["blueprints"]
    if len(candidates) != 1:
        raise ValueError(f"Expected exactly one blueprint match, found {len(candidates)}")
    return config_path(candidates[0]["relative_path"])


def read_blueprint(args: dict[str, Any]) -> dict[str, Any]:
    path = resolve_blueprint_path(args)
    content, truncated = read_limited(path, int(args.get("max_bytes") or MAX_READ_BYTES))
    return {"path": str(path), "relative_path": str(path.relative_to(CONFIG_ROOT)), "content": content, "truncated": truncated}


def search_blueprints(args: dict[str, Any]) -> dict[str, Any]:
    root = blueprint_root()
    if args.get("domain"):
        root = root / str(args["domain"]).strip("/")
    result = search_active_config({"path": str(root.relative_to(CONFIG_ROOT)), "query": args["query"], "filename": "*.y*ml", "limit": int(args.get("limit") or 100), "context_lines": int(args.get("context_lines") or 10)})
    result["blueprint_root"] = str(root)
    return result


def get_recorder_config(args: dict[str, Any]) -> dict[str, Any]:
    query = args.get("query") or "recorder:"
    contexts = search_active_config({"query": query, "filename": "*.yaml", "limit": 50, "context_lines": int(args.get("context_lines") or 40)})
    return {"query": query, "source_contexts": contexts, "db": recorder_get_db_info()}


def dump_simple_yaml(value: Any, indent: int = 0) -> str:
    space = " " * indent
    if isinstance(value, dict):
        lines = []
        for key, child in value.items():
            if isinstance(child, (dict, list)):
                lines.append(f"{space}{key}:")
                lines.append(dump_simple_yaml(child, indent + 2))
            else:
                lines.append(f"{space}{key}: {json.dumps(child) if isinstance(child, str) else child}")
        return "\n".join(lines)
    if isinstance(value, list):
        lines = []
        for child in value:
            if isinstance(child, (dict, list)):
                lines.append(f"{space}-")
                lines.append(dump_simple_yaml(child, indent + 2))
            else:
                lines.append(f"{space}- {json.dumps(child) if isinstance(child, str) else child}")
        return "\n".join(lines)
    return f"{space}{json.dumps(value) if isinstance(value, str) else value}"


def write_recorder_package(args: dict[str, Any]) -> dict[str, Any]:
    filename = str(args.get("filename") or "ha_admin_mcp_recorder.yaml")
    if Path(filename).name != filename or not filename.endswith((".yaml", ".yml")):
        raise ValueError("filename must be a simple .yaml or .yml file name")
    if not bool(args.get("dry_run")) and not bool(args.get("force")):
        raise ValueError("write_recorder_package requires force=true")
    if args.get("content") is not None:
        content = str(args["content"]).rstrip() + "\n"
    elif args.get("config") is not None:
        config = args["config"]
        if not isinstance(config, dict):
            raise ValueError("config must be an object")
        content = "recorder:\n" + dump_simple_yaml(config, 2).rstrip() + "\n"
    else:
        raise ValueError("Pass content or config")
    write_args = {
        "path": str(Path("packages") / filename),
        "content": content,
        "backup": bool(args.get("backup", True)),
        "dry_run": bool(args.get("dry_run")),
        "expected_hash": args.get("expected_hash"),
        "check_config": bool(args.get("check_config", True)),
    }
    result = write_config_file(write_args)
    result["note"] = "Dedicated recorder package written under /config/packages; use check_config_and_reload or restart if HA reports recorder changes require restart."
    return result


def first_present(args: dict[str, Any], *names: str) -> Any:
    for name in names:
        value = args.get(name)
        if value not in (None, ""):
            return value
    return None


def compute_config_hash(config: dict[str, Any]) -> str:
    config_text = json.dumps(config, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(config_text.encode()).hexdigest()[:16]


def normalize_automation_config(config: Any, is_root: bool = True) -> Any:
    if isinstance(config, list):
        return [normalize_automation_config(item, is_root=False) for item in config]
    if not isinstance(config, dict):
        return config
    normalized = dict(config)
    mappings: dict[str, str] = {}
    if is_root:
        mappings.update({"trigger": "triggers", "condition": "conditions", "action": "actions"})
    mappings["sequences"] = "sequence"
    for source, target in mappings.items():
        if source in normalized and target not in normalized:
            normalized[target] = normalized.pop(source)
        elif source in normalized and target in normalized:
            del normalized[source]
    for key, value in list(normalized.items()):
        normalized[key] = normalize_automation_config(value, is_root=False)
    if is_root and isinstance(normalized.get("triggers"), list):
        triggers = []
        for trigger in normalized["triggers"]:
            if isinstance(trigger, dict) and "platform" in trigger:
                trigger = dict(trigger)
                if "trigger" not in trigger:
                    trigger["trigger"] = trigger.pop("platform")
                else:
                    del trigger["platform"]
            triggers.append(trigger)
        normalized["triggers"] = triggers
    return normalized


def normalize_domain_config(domain: str, config: dict[str, Any]) -> dict[str, Any]:
    if domain == "automation":
        return normalize_automation_config(config)
    return config


def compat_identifier(args: dict[str, Any]) -> str | None:
    return first_present(args, "entity_id", "identifier", "id", "name", "slug")


def ws_result(message: dict[str, Any], timeout: int = 30) -> Any:
    response = ha_ws_call(message, timeout=timeout)
    if response.get("success"):
        return response.get("result")
    error = response.get("error")
    if isinstance(error, dict):
        detail = error.get("message") or error.get("code") or error
    else:
        detail = error or response
    raise RuntimeError(f"Home Assistant WebSocket {message.get('type')} failed: {detail}")


def ws_success(message: dict[str, Any], timeout: int = 30) -> dict[str, Any]:
    return {"success": True, "result": ws_result(message, timeout=timeout)}


def parse_maybe_json(value: Any) -> Any:
    if isinstance(value, str):
        text = value.strip()
        if text.startswith(("{", "[")):
            return json.loads(text)
    return value


def parse_string_list(value: Any, name: str) -> list[str] | None:
    value = parse_maybe_json(value)
    if value is None:
        return None
    if isinstance(value, str):
        value = [part.strip() for part in value.split(",") if part.strip()]
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError(f"{name} must be a string list")
    return value


def truthy_arg(args: dict[str, Any], *names: str) -> Any:
    for name in names:
        if args.get(name) not in (None, ""):
            return args.get(name)
    return None


def get_entity_registry_entry_ws(entity_id: str) -> dict[str, Any]:
    entry = ws_result({"type": "config/entity_registry/get", "entity_id": entity_id})
    return {
        "entity_id": entry.get("entity_id"),
        "name": entry.get("name"),
        "original_name": entry.get("original_name"),
        "icon": entry.get("icon"),
        "area_id": entry.get("area_id"),
        "disabled_by": entry.get("disabled_by"),
        "hidden_by": entry.get("hidden_by"),
        "enabled": entry.get("disabled_by") is None,
        "hidden": entry.get("hidden_by") is not None,
        "aliases": entry.get("aliases", []),
        "labels": entry.get("labels", []),
        "categories": entry.get("categories", {}),
        "device_class": entry.get("device_class"),
        "original_device_class": entry.get("original_device_class"),
        "options": entry.get("options", {}),
        "platform": entry.get("platform"),
        "device_id": entry.get("device_id"),
        "config_entry_id": entry.get("config_entry_id"),
        "unique_id": entry.get("unique_id"),
    }


def call_entity_registry_tool(name: str, args: dict[str, Any]) -> dict[str, Any]:
    entity_id = args.get("entity_id") or args.get("identifier") or args.get("id")
    if name == "ha_get_entity":
        entity_ids = parse_maybe_json(entity_id)
        if isinstance(entity_ids, list):
            entries = []
            errors = []
            for eid in entity_ids:
                try:
                    entries.append(get_entity_registry_entry_ws(str(eid)))
                except Exception as err:
                    errors.append({"entity_id": eid, "error": str(err)})
            return {"success": not errors, "count": len(entries), "entity_entries": entries, "errors": errors}
        if not entity_id:
            raise ValueError("entity_id is required")
        return {"success": True, "entity_id": entity_id, "entity_entry": get_entity_registry_entry_ws(str(entity_id))}
    if not entity_id:
        raise ValueError("entity_id is required")
    if name == "ha_remove_entity":
        return ws_success({"type": "config/entity_registry/remove", "entity_id": str(entity_id)})

    message: dict[str, Any] = {"type": "config/entity_registry/update", "entity_id": str(entity_id)}
    field_map = {
        "area_id": "area_id",
        "name": "name",
        "icon": "icon",
        "device_class": "device_class",
        "new_entity_id": "new_entity_id",
    }
    for source, target in field_map.items():
        if source in args:
            message[target] = args[source] if args[source] != "" else None
    if "enabled" in args:
        message["disabled_by"] = None if bool(args["enabled"]) else "user"
    if "hidden" in args:
        message["hidden_by"] = "user" if bool(args["hidden"]) else None
    if "aliases" in args:
        message["aliases"] = parse_string_list(args.get("aliases"), "aliases") or []
    if "categories" in args:
        categories = parse_maybe_json(args.get("categories"))
        if not isinstance(categories, dict):
            raise ValueError("categories must be an object")
        message["categories"] = categories
    labels = parse_string_list(args.get("labels"), "labels")
    if labels is not None:
        operation = str(args.get("label_operation") or "set")
        if operation in {"add", "remove"}:
            current = get_entity_registry_entry_ws(str(entity_id)).get("labels", [])
            if operation == "add":
                labels = sorted(set(current) | set(labels))
            else:
                labels = [label for label in current if label not in set(labels)]
        message["labels"] = labels
    if len(message) <= 2:
        raise ValueError("No entity updates specified")
    result = ws_result(message)
    new_entity_id = message.get("new_entity_id") or entity_id
    if args.get("expose_to") is not None:
        expose_to = parse_maybe_json(args.get("expose_to"))
        if not isinstance(expose_to, dict):
            raise ValueError("expose_to must be an object mapping assistant id to boolean")
        for should_expose in (True, False):
            assistants = [assistant for assistant, value in expose_to.items() if bool(value) is should_expose]
            if assistants:
                ws_result({"type": "homeassistant/expose_entity", "assistants": assistants, "entity_ids": [new_entity_id], "should_expose": should_expose})
    return {"success": True, "entity_id": new_entity_id, "entity_entry": result.get("entity_entry", result), "updated": [key for key in message if key not in {"type", "entity_id"}]}


def device_registry_summary(device: dict[str, Any], entities: list[dict[str, Any]], detail: str = "summary") -> dict[str, Any]:
    identifiers = device.get("identifiers", [])
    connections = device.get("connections", [])
    integrations = []
    ieee = None
    for pair in identifiers + connections:
        if isinstance(pair, (list, tuple)) and len(pair) >= 2:
            domain, value = str(pair[0]), str(pair[1])
            if domain not in integrations:
                integrations.append(domain)
            if domain in {"zha", "ieee"} or (domain == "mqtt" and "_0x" in value):
                ieee = value if domain != "mqtt" else "0x" + value.split("_0x")[-1]
    row = {
        "device_id": device.get("id"),
        "name": device.get("name_by_user") or device.get("name"),
        "manufacturer": device.get("manufacturer"),
        "model": device.get("model"),
        "sw_version": device.get("sw_version"),
        "area_id": device.get("area_id"),
        "integration_sources": integrations,
        "integration_type": "zigbee2mqtt" if any("zigbee2mqtt" in str(pair).lower() for pair in identifiers) else (integrations[0] if integrations else "unknown"),
        "via_device_id": device.get("via_device_id"),
    }
    if ieee:
        row["ieee_address"] = ieee
    if detail == "full":
        row.update({
            "entities": entities,
            "name_by_user": device.get("name_by_user"),
            "default_name": device.get("name"),
            "hw_version": device.get("hw_version"),
            "serial_number": device.get("serial_number"),
            "disabled_by": device.get("disabled_by"),
            "labels": device.get("labels", []),
            "config_entries": device.get("config_entries", []),
            "connections": connections,
            "identifiers": identifiers,
        })
    return row


def call_device_registry_tool(name: str, args: dict[str, Any]) -> dict[str, Any]:
    device_id = args.get("device_id") or args.get("identifier") or args.get("id")
    if name == "ha_set_device":
        if not device_id:
            raise ValueError("device_id is required")
        message: dict[str, Any] = {"type": "config/device_registry/update", "device_id": str(device_id)}
        if "name" in args:
            message["name_by_user"] = args.get("name") if args.get("name") != "" else None
        if "area_id" in args:
            message["area_id"] = args.get("area_id") if args.get("area_id") != "" else None
        if "disabled_by" in args:
            message["disabled_by"] = args.get("disabled_by") if args.get("disabled_by") != "" else None
        labels = parse_string_list(args.get("labels"), "labels")
        if labels is not None:
            message["labels"] = labels
        if len(message) <= 2:
            raise ValueError("No device updates specified")
        return {"success": True, "device_id": device_id, "device": ws_result(message)}
    if name == "ha_remove_device":
        if not device_id:
            raise ValueError("device_id is required")
        return ws_success({"type": "config/device_registry/remove", "device_id": str(device_id)})

    devices = ws_result({"type": "config/device_registry/list"})
    entities = ws_result({"type": "config/entity_registry/list"})
    entity_id = args.get("entity_id")
    if entity_id and not device_id:
        match = next((entity for entity in entities if entity.get("entity_id") == entity_id), None)
        device_id = match.get("device_id") if match else None
    by_device: dict[str, list[dict[str, Any]]] = {}
    for entity in entities:
        if entity.get("device_id"):
            by_device.setdefault(entity["device_id"], []).append({"entity_id": entity.get("entity_id"), "name": entity.get("name") or entity.get("original_name"), "platform": entity.get("platform")})
    detail = str(args.get("detail_level") or "summary")
    if device_id:
        device = next((item for item in devices if item.get("id") == device_id), None)
        if not device:
            raise ValueError(f"Device not found: {device_id}")
        row = device_registry_summary(device, by_device.get(str(device_id), []), "full")
        return {"success": True, "device": row, "entities": row.get("entities", []), "entity_count": len(row.get("entities", [])), "queried_entity_id": entity_id}
    limit = int(args.get("limit") or 50)
    offset = int(args.get("offset") or 0)
    query = str(args.get("query") or "").lower()
    integration = str(args.get("integration") or "").lower()
    area_id = args.get("area_id")
    manufacturer = str(args.get("manufacturer") or "").lower()
    rows = []
    for device in devices:
        blob = json.dumps(device, default=str).lower()
        if query and query not in blob:
            continue
        if area_id and device.get("area_id") != area_id:
            continue
        if manufacturer and manufacturer not in str(device.get("manufacturer") or "").lower():
            continue
        row = device_registry_summary(device, by_device.get(device.get("id"), []), detail)
        if integration and integration not in json.dumps(row.get("integration_sources", []), default=str).lower() and row.get("integration_type") != integration:
            continue
        rows.append(row)
    total = len(rows)
    return {"success": True, "devices": rows[offset : offset + limit], "count": len(rows[offset : offset + limit]), "total": total, "offset": offset, "limit": limit, "total_devices": len(devices), "detail_level": detail}


def call_area_floor_tool(name: str, args: dict[str, Any]) -> dict[str, Any]:
    if name == "ha_list_floors_areas":
        areas = ws_result({"type": "config/area_registry/list"})
        floors = ws_result({"type": "config/floor_registry/list"})
        valid_floor_ids = {floor.get("floor_id") for floor in floors}
        floor_map = {floor.get("floor_id"): [] for floor in floors}
        unassigned = []
        orphaned = []
        for area in areas:
            floor_id = area.get("floor_id")
            if not floor_id:
                unassigned.append(area)
            elif floor_id in valid_floor_ids:
                floor_map.setdefault(floor_id, []).append(area)
            else:
                orphaned.append(area)
        topology = [{**floor, "areas": floor_map.get(floor.get("floor_id"), [])} for floor in floors]
        topology.sort(key=lambda floor: int(floor.get("level") or 0))
        return {"success": True, "floor_count": len(floors), "area_count": len(areas), "unassigned_count": len(unassigned), "orphaned_count": len(orphaned), "floors": topology, "unassigned_areas": unassigned, "orphaned_areas": orphaned}
    kind = args.get("kind") or ("floor" if args.get("floor_id") and not args.get("area_id") else "area")
    if kind not in {"area", "floor"}:
        raise ValueError("kind must be area or floor")
    id_key = "floor_id" if kind == "floor" else "area_id"
    registry = "floor_registry" if kind == "floor" else "area_registry"
    item_id = args.get("id") or args.get(id_key) or args.get("identifier")
    if name == "ha_remove_area_or_floor":
        if not item_id:
            raise ValueError("id is required")
        return ws_success({"type": f"config/{registry}/delete", id_key: item_id})
    action = "update" if item_id else "create"
    message: dict[str, Any] = {"type": f"config/{registry}/{action}"}
    if item_id:
        message[id_key] = item_id
    if action == "create" and not args.get("name"):
        raise ValueError("name is required when creating")
    for field in ("name", "icon", "aliases", "level", "floor_id", "picture"):
        if field in args:
            value = args[field]
            if field == "aliases":
                value = parse_string_list(value, "aliases") or []
            elif value == "":
                value = None
            if kind == "floor" and field in {"floor_id", "picture"}:
                continue
            if kind == "area" and field == "level":
                continue
            message[field] = value
    return {"success": True, "kind": kind, id_key: item_id, "result": ws_result(message)}


def call_label_category_tool(name: str, args: dict[str, Any]) -> dict[str, Any]:
    is_label = "label" in name
    registry = "label_registry" if is_label else "category_registry"
    id_key = "label_id" if is_label else "category_id"
    item_id = args.get(id_key) or args.get("id") or args.get("identifier")
    if is_label:
        list_message = {"type": "config/label_registry/list"}
    else:
        list_message = {"type": "config/category_registry/list", "scope": args.get("scope") or "automation"}
    if "_get_" in name:
        rows = ws_result(list_message)
        if item_id:
            row = next((item for item in rows if item.get(id_key) == item_id), None)
            if not row:
                raise ValueError(f"{id_key} not found: {item_id}")
            return {"success": True, id_key: item_id, "item": row}
        return {"success": True, "count": len(rows), "items": rows}
    if "_remove_" in name:
        if not item_id:
            raise ValueError(f"{id_key} is required")
        message = {"type": f"config/{registry}/delete", id_key: item_id}
        if not is_label:
            message["scope"] = args.get("scope") or "automation"
        return ws_success(message)
    action = "update" if item_id else "create"
    message = {"type": f"config/{registry}/{action}", "name": args.get("name") or args.get("title")}
    if not message["name"]:
        raise ValueError("name is required")
    if item_id:
        message[id_key] = item_id
    for field in ("color", "icon", "description"):
        if field in args:
            message[field] = args[field] if args[field] != "" else None
    if not is_label:
        message["scope"] = args.get("scope") or "automation"
    return {"success": True, id_key: item_id, "result": ws_result(message)}


def call_blueprint_tool(name: str, args: dict[str, Any]) -> dict[str, Any]:
    if name == "ha_import_blueprint":
        url = args.get("url")
        if not url:
            raise ValueError("url is required")
        imported = ws_result({"type": "blueprint/import", "url": url}, timeout=120)
        filename = imported.get("suggested_filename")
        raw = imported.get("raw_data")
        metadata = (imported.get("blueprint") or {}).get("metadata") or {}
        domain = metadata.get("domain") or args.get("domain") or "automation"
        if not filename or not raw:
            raise ValueError("Blueprint import validated but did not return suggested_filename/raw_data")
        if not str(filename).endswith((".yaml", ".yml")):
            filename = f"{filename}.yaml"
        saved = ws_result({"type": "blueprint/save", "domain": domain, "path": filename, "yaml": raw, "source_url": url}, timeout=120)
        return {"success": True, "url": url, "imported_blueprint": {"path": filename, "domain": domain, "name": metadata.get("name"), "description": metadata.get("description")}, "save_result": saved}
    domain = args.get("domain") or "automation"
    path = args.get("path")
    blueprints = ws_result({"type": "blueprint/list", "domain": domain})
    if not path:
        rows = [{"path": key, "name": value.get("name") or ((value.get("metadata") or {}).get("name")), "domain": domain, "metadata": value.get("metadata")} for key, value in blueprints.items()]
        return {"success": True, "domain": domain, "count": len(rows), "blueprints": rows}
    if path not in blueprints:
        raise ValueError(f"Blueprint not found: {path}")
    data = blueprints[path]
    return {"success": True, "path": path, "domain": domain, "name": data.get("name") or path, "metadata": data.get("metadata"), "inputs": (data.get("metadata") or {}).get("input"), "blueprint": data.get("blueprint")}


def call_calendar_tool(name: str, args: dict[str, Any]) -> dict[str, Any]:
    entity_id = args.get("entity_id") or args.get("calendar_entity_id") or args.get("identifier")
    if not entity_id:
        raise ValueError("entity_id is required")
    if name == "ha_config_get_calendar_events":
        start = args.get("start") or datetime.now().isoformat()
        end = args.get("end") or (datetime.now() + timedelta(days=7)).isoformat()
        events = ha_request("GET", maybe_query(f"/calendars/{entity_id}", {"start": start, "end": end}))
        limit = int(args.get("max_results") or args.get("limit") or 20)
        return {"success": True, "entity_id": entity_id, "events": events[:limit] if isinstance(events, list) else events, "count": min(len(events), limit) if isinstance(events, list) else None, "time_range": {"start": start, "end": end}}
    if name == "ha_config_set_calendar_event":
        summary = args.get("summary") or args.get("name")
        start = args.get("start")
        end = args.get("end")
        if not summary or not start or not end:
            raise ValueError("summary, start, and end are required")
        if args.get("rrule"):
            event = {"summary": summary, "dtstart": start, "dtend": end, "rrule": args.get("rrule")}
            for field in ("description", "location"):
                if args.get(field):
                    event[field] = args[field]
            return ws_success({"type": "calendar/event/create", "entity_id": entity_id, "event": event})
        data = {"entity_id": entity_id, "summary": summary, "start_date_time": start, "end_date_time": end}
        for field in ("description", "location"):
            if args.get(field):
                data[field] = args[field]
        return {"success": True, "result": ha_request("POST", "/services/calendar/create_event", data), "event": data}
    uid = args.get("uid")
    if not uid:
        raise ValueError("uid is required")
    message = {"type": "calendar/event/delete", "entity_id": entity_id, "uid": uid}
    for field in ("recurrence_id", "recurrence_range"):
        if args.get(field):
            message[field] = args[field]
    return ws_success(message)


def call_group_tool(name: str, args: dict[str, Any]) -> dict[str, Any]:
    if name == "ha_config_list_groups":
        groups = []
        for state in ha_request("GET", "/states"):
            entity_id = state.get("entity_id", "")
            if entity_id.startswith("group."):
                attrs = state.get("attributes") or {}
                groups.append({"entity_id": entity_id, "object_id": entity_id.removeprefix("group."), "state": state.get("state"), "friendly_name": attrs.get("friendly_name"), "icon": attrs.get("icon"), "entity_ids": attrs.get("entity_id", []), "all": attrs.get("all", False)})
        return {"success": True, "count": len(groups), "groups": sorted(groups, key=lambda row: row.get("friendly_name") or row.get("entity_id"))}
    object_id = args.get("object_id") or args.get("id") or args.get("identifier")
    if not object_id:
        raise ValueError("object_id is required")
    object_id = str(object_id).removeprefix("group.")
    if name == "ha_config_remove_group":
        return {"success": True, "entity_id": f"group.{object_id}", "result": ha_request("POST", "/services/group/remove", {"object_id": object_id})}
    data = {"object_id": object_id}
    if args.get("name"):
        data["name"] = args["name"]
    if args.get("icon"):
        data["icon"] = args["icon"]
    if "all_on" in args:
        data["all"] = bool(args["all_on"])
    for source, target in (("entities", "entities"), ("add_entities", "add_entities"), ("remove_entities", "remove_entities")):
        values = parse_string_list(args.get(source), source)
        if values is not None:
            data[target] = values
    return {"success": True, "entity_id": f"group.{object_id}", "result": ha_request("POST", "/services/group/set", data), "updated_fields": [key for key in data if key != "object_id"]}


def call_helper_tool(name: str, args: dict[str, Any]) -> dict[str, Any]:
    if name == "ha_config_list_helpers":
        helper_type = args.get("helper_type") or args.get("type") or args.get("domain")
        domains = [helper_type] if helper_type else ["input_button", "input_boolean", "input_select", "input_number", "input_text", "input_datetime", "counter", "timer", "schedule", "zone", "person", "tag"]
        entities = []
        for domain in domains:
            entities.extend(list_entities({"domain": domain, "detailed": True, "limit": 10000}).get("entities", []))
        return {"success": True, "count": len(entities), "helpers": entities, "helper_type": helper_type}
    if name == "ha_remove_helpers_integrations":
        entity_id = args.get("entity_id") or args.get("helper_id") or args.get("id") or args.get("identifier")
        if not entity_id:
            raise ValueError("entity_id/helper_id is required")
        if "." not in str(entity_id) and args.get("helper_type"):
            entity_id = f"{args['helper_type']}.{entity_id}"
        return call_entity_registry_tool("ha_remove_entity", {"entity_id": entity_id})
    helper_type = args.get("helper_type") or args.get("type")
    if not helper_type:
        raise ValueError("helper_type is required")
    action = args.get("action") or ("update" if args.get("helper_id") or args.get("id") else "create")
    message: dict[str, Any] = {"type": f"{helper_type}/{action}"}
    helper_id = args.get("helper_id") or args.get("id")
    if helper_id:
        message[f"{helper_type}_id"] = str(helper_id).removeprefix(f"{helper_type}.")
    for key, value in (args.get("config") or {}).items():
        message[key] = value
    for key in ("name", "icon", "initial", "min", "max", "min_value", "max_value", "step", "unit_of_measurement", "mode", "has_date", "has_time", "duration", "restore", "latitude", "longitude", "radius", "passive"):
        if key in args:
            message[key] = args[key]
    for key in ("options", "labels", "device_trackers"):
        values = parse_string_list(args.get(key), key)
        if values is not None:
            message[key] = values
    return {"success": True, "helper_type": helper_type, "action": action, "result": ws_result(message)}


def call_energy_tool(args: dict[str, Any]) -> dict[str, Any]:
    mode = args.get("mode") or args.get("action") or "get"
    current = ws_result({"type": "energy/get_prefs"})
    current_hash = compute_config_hash(current)
    if mode == "get":
        per_key = {key: compute_config_hash(value) for key, value in current.items() if key in {"energy_sources", "device_consumption", "device_consumption_water"}}
        return {"success": True, "config": current, "config_hash": current_hash, "config_hash_per_key": per_key}
    config = args.get("config")
    if mode == "add_device":
        key = "device_consumption_water" if args.get("water") else "device_consumption"
        config = {key: list(current.get(key) or [])}
        stat = args.get("stat_consumption")
        if not stat:
            raise ValueError("stat_consumption is required")
        entry = {"stat_consumption": stat}
        if args.get("name"):
            entry["name"] = args["name"]
        if args.get("included_in_stat"):
            entry["included_in_stat"] = args["included_in_stat"]
        config[key].append(entry)
    elif mode == "remove_device":
        key = "device_consumption_water" if args.get("water") else "device_consumption"
        stat = args.get("stat_consumption")
        if not stat:
            raise ValueError("stat_consumption is required")
        config = {key: [entry for entry in current.get(key, []) if entry.get("stat_consumption") != stat]}
    elif mode == "add_source":
        source = parse_maybe_json(args.get("source"))
        if not isinstance(source, dict):
            raise ValueError("source object is required")
        config = {"energy_sources": list(current.get("energy_sources") or []) + [source]}
    elif mode != "set":
        raise ValueError("mode must be get, set, add_device, remove_device, or add_source")
    if not isinstance(config, dict):
        raise ValueError("config object is required")
    if args.get("dry_run"):
        return {"success": True, "dry_run": True, "current_config_hash": current_hash, "would_save": config}
    expected = args.get("config_hash")
    if mode == "set" and expected and isinstance(expected, str) and expected != current_hash:
        raise ValueError(f"config_hash mismatch: current={current_hash}")
    return {"success": True, "result": ws_result({"type": "energy/save_prefs", **config}), "saved_keys": sorted(config), "previous_config_hash": current_hash}


def call_zone_tool(name: str, args: dict[str, Any]) -> dict[str, Any]:
    zone_id = args.get("zone_id") or args.get("id") or args.get("identifier")
    if name == "ha_get_zone":
        zones = ws_result({"type": "zone/list"})
        if not zone_id:
            return {"success": True, "count": len(zones), "zones": zones}
        zone = next((item for item in zones if item.get("id") == zone_id), None)
        if not zone:
            raise ValueError(f"Zone not found: {zone_id}")
        return {"success": True, "zone_id": zone_id, "zone": zone}
    if name == "ha_remove_zone":
        if not zone_id:
            raise ValueError("zone_id is required")
        return ws_success({"type": "zone/delete", "zone_id": zone_id})
    action = "update" if zone_id else "create"
    if action == "create":
        for required in ("name", "latitude", "longitude"):
            if args.get(required) is None:
                raise ValueError(f"{required} is required when creating a zone")
    message: dict[str, Any] = {"type": f"zone/{action}"}
    if zone_id:
        message["zone_id"] = zone_id
    for field in ("name", "latitude", "longitude", "radius", "icon", "passive"):
        if field in args and args[field] is not None:
            message[field] = args[field]
    if action == "create" and "radius" not in message:
        message["radius"] = 100
    result = ws_result(message)
    return {"success": True, "zone_id": result.get("id", zone_id), "zone_data": result, "action": action}


def call_pipeline_tool(args: dict[str, Any]) -> dict[str, Any]:
    action = args.get("action") or "list"
    if action == "list":
        return {"success": True, "result": ws_result({"type": "assist_pipeline/pipeline/list"})}
    pipeline_id = args.get("pipeline_id") or args.get("id") or args.get("identifier")
    if action == "get":
        result = ws_result({"type": "assist_pipeline/pipeline/list"})
        pipelines = result.get("pipelines", []) if isinstance(result, dict) else []
        if pipeline_id == "preferred":
            pipeline_id = result.get("preferred_pipeline")
        match = next((pipeline for pipeline in pipelines if pipeline.get("id") == pipeline_id), None)
        if not match:
            raise ValueError(f"Pipeline not found: {pipeline_id}")
        return {"success": True, "pipeline": match, "preferred_pipeline": result.get("preferred_pipeline")}
    if action == "set_preferred":
        if not pipeline_id:
            raise ValueError("pipeline_id is required")
        return ws_success({"type": "assist_pipeline/pipeline/set_preferred", "pipeline": pipeline_id})
    message = {"type": f"assist_pipeline/pipeline/{action}"}
    if pipeline_id:
        message["pipeline"] = pipeline_id
    if args.get("base_pipeline_id"):
        message["copy_from"] = args["base_pipeline_id"]
    for field in ("name", "conversation_engine", "conversation_language", "language", "stt_engine", "stt_language", "tts_engine", "tts_language", "tts_voice", "wake_word_entity", "wake_word_id", "prefer_local_intents"):
        if field in args:
            message[field] = args[field] if args[field] != "" else None
    result = ws_result(message)
    if args.get("make_preferred"):
        new_id = result.get("id") or result.get("pipeline") or pipeline_id
        if new_id:
            ws_result({"type": "assist_pipeline/pipeline/set_preferred", "pipeline": new_id})
    return {"success": True, "action": action, "result": result}


def load_saved_tools() -> dict[str, dict[str, Any]]:
    if not SAVED_TOOLS_PATH.exists():
        return {}
    try:
        data = json.loads(SAVED_TOOLS_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


def save_saved_tools(data: dict[str, dict[str, Any]]) -> None:
    SAVED_TOOLS_PATH.parent.mkdir(parents=True, exist_ok=True)
    SAVED_TOOLS_PATH.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
    SAVED_TOOLS_PATH.chmod(0o600)


def validate_saved_tool_name(name: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9_]{1,64}", name):
        raise ValueError("saved tool names must be 1-64 chars: letters, numbers, underscores")
    return name


def custom_tool_source_result(code: str) -> Any:
    tree = ast.parse(code, mode="exec")
    body = list(tree.body)
    if body and isinstance(body[-1], ast.Expr):
        body[-1] = ast.Return(value=body[-1].value)
        ast.fix_missing_locations(tree)

    async def api_get(endpoint: str) -> Any:
        return ha_request("GET", endpoint)

    async def api_post(endpoint: str, data: Any | None = None) -> Any:
        return ha_request("POST", endpoint, data)

    async def ws_send(message: dict[str, Any]) -> Any:
        return ws_result(message)

    async def call_registered_tool(tool_name: str, tool_args: dict[str, Any] | None = None) -> Any:
        return call_tool(tool_name, tool_args or {})

    def delete_saved_tool(name: str) -> dict[str, Any]:
        saved = load_saved_tools()
        removed = saved.pop(validate_saved_tool_name(name), None)
        save_saved_tools(saved)
        return {"deleted": removed is not None, "name": name}

    async_src = "async def __ha_admin_custom_main():\n" + textwrap.indent(ast.unparse(ast.Module(body=body, type_ignores=[])), "    ")
    namespace: dict[str, Any] = {
        "api_get": api_get,
        "api_post": api_post,
        "ws_send": ws_send,
        "call_tool": call_registered_tool,
        "delete_saved_tool": delete_saved_tool,
        "json": json,
        "re": re,
        "datetime": datetime,
        "timedelta": timedelta,
    }
    exec(compile(async_src, "<ha_manage_custom_tool>", "exec"), namespace, namespace)
    return asyncio.run(namespace["__ha_admin_custom_main"]())


def manage_custom_tool(args: dict[str, Any]) -> dict[str, Any]:
    modes = [bool(args.get("code")), bool(args.get("run_saved")), bool(args.get("list_saved"))]
    if sum(modes) != 1:
        raise ValueError("Use exactly one mode: code, run_saved, or list_saved")
    saved = load_saved_tools()
    if bool(args.get("list_saved")):
        return {
            "success": True,
            "saved_tools_path": str(SAVED_TOOLS_PATH),
            "tools": [{"name": name, "justification": item.get("justification")} for name, item in sorted(saved.items())],
        }
    if args.get("run_saved"):
        name = validate_saved_tool_name(str(args["run_saved"]))
        if name not in saved:
            raise ValueError(f"saved custom tool not found: {name}")
        result = custom_tool_source_result(str(saved[name].get("code") or ""))
        return {"success": True, "mode": "run_saved", "name": name, "result": result}
    code = str(args.get("code") or "")
    justification = str(args.get("justification") or "")
    if not justification:
        raise ValueError("justification is required when executing custom code")
    result = custom_tool_source_result(code)
    response = {"success": True, "mode": "code", "result": result}
    if args.get("save_as"):
        name = validate_saved_tool_name(str(args["save_as"]))
        saved[name] = {"code": code, "justification": justification, "saved_at": datetime.now(timezone.utc).isoformat()}
        save_saved_tools(saved)
        response["saved_as"] = name
        response["saved_tools_path"] = str(SAVED_TOOLS_PATH)
    return response


def install_mcp_tools(args: dict[str, Any]) -> dict[str, Any]:
    hacs = ws_result({"type": "hacs/info"})
    repositories = ws_result({"type": "hacs/repositories/list"})
    repo_id = "homeassistant-ai/ha-mcp-tools"
    installed = False
    if isinstance(repositories, list):
        installed = any(
            str(item.get("full_name") or item.get("repository") or item.get("name") or "").lower() == repo_id
            or str(item.get("domain") or "").lower() == "ha_mcp_tools"
            for item in repositories
            if isinstance(item, dict)
        )
    actions: list[dict[str, Any]] = []
    if not installed:
        try:
            actions.append({"add_repository": ws_result({"type": "hacs/repositories/add", "repository": repo_id, "category": "integration"}, timeout=120)})
        except Exception as err:
            actions.append({"add_repository_error": str(err)})
        actions.append({"download": ws_result({"type": "hacs/repository/download", "repository": repo_id, "category": "integration"}, timeout=300)})
    if bool(args.get("restart")):
        actions.append({"restart": supervisor_request("POST", "/core/restart")})
    return {
        "success": True,
        "hacs": hacs,
        "repository": repo_id,
        "already_installed": installed,
        "actions": actions,
        "restart_requested": bool(args.get("restart")),
    }


def validate_dashboard_path(path: str) -> str:
    clean = path.strip().lstrip("/")
    if not clean or clean in {".", ".."}:
        raise ValueError("dashboard_path must name a Lovelace dashboard/view path")
    parts = clean.split("/")
    if any(part in {"", ".", ".."} or "\\" in part for part in parts):
        raise ValueError("dashboard_path contains an invalid segment")
    return "/".join(urllib.parse.quote(part, safe="") for part in parts)


def discover_screenshot_engine_url() -> str:
    explicit = os.environ.get("HAMCP_DASHBOARD_SCREENSHOT_ENGINE_URL", "").strip()
    if explicit:
        return explicit.rstrip("/")
    addons = supervisor_request("GET", "/addons")
    addon_rows = ((addons.get("data") or {}).get("addons") or []) if isinstance(addons, dict) else []
    matches = [row for row in addon_rows if str(row.get("slug", "")).endswith("_puppet")]
    if not matches:
        raise RuntimeError("Puppet dashboard screenshot engine add-on is not installed")
    last: dict[str, Any] = {}
    for row in matches:
        slug = str(row.get("slug"))
        info = supervisor_request("GET", f"/addons/{slug}/info")
        data = info.get("data", info) if isinstance(info, dict) else {}
        last = {"slug": slug, "state": data.get("state")}
        if data.get("state") != "started":
            continue
        host = data.get("hostname") or data.get("ip_address")
        if not host:
            raise RuntimeError(f"Puppet screenshot engine add-on {slug} is started but has no hostname/ip_address")
        return f"http://{host}:10000"
    raise RuntimeError(f"Puppet dashboard screenshot engine add-on is installed but not started: {last}")


def get_dashboard_screenshot(args: dict[str, Any]) -> dict[str, Any]:
    path = validate_dashboard_path(str(args.get("dashboard_path") or ""))
    width = int(args.get("width") or 1280)
    height = 6000 if bool(args.get("full_page")) else int(args.get("height") or 720)
    zoom = float(args.get("zoom") or 1.0)
    wait_ms = int(args.get("wait_ms") or 1500)
    engine = discover_screenshot_engine_url()
    query = urllib.parse.urlencode({
        "viewport": f"{width}x{height}",
        "zoom": str(zoom),
        "wait": str(wait_ms),
        "format": "png",
    })
    request = urllib.request.Request(f"{engine}/{path}?{query}", method="GET")
    try:
        with urllib.request.urlopen(request, timeout=45) as response:
            data = response.read()
            content_type = response.headers.get("Content-Type", "image/png")
    except urllib.error.HTTPError as err:
        detail = err.read().decode(errors="replace")[:500]
        raise RuntimeError(f"Screenshot engine returned HTTP {err.code} for {path}: {detail}") from err
    if not data:
        raise RuntimeError(f"Screenshot engine returned an empty image for {path}")
    return {
        "content": [{
            "type": "image",
            "data": base64.b64encode(data).decode(),
            "mimeType": content_type if content_type.startswith("image/") else "image/png",
        }],
        "_meta": {"engine_url": engine, "dashboard_path": path, "bytes": len(data)},
    }


def call_upstream_compat_tool(name: str, args: dict[str, Any]) -> Any:
    identifier = compat_identifier(args)
    if name == "ha_get_state":
        if not identifier:
            raise ValueError("entity_id or identifier is required")
        return get_entity({"entity_id": identifier, "fields": args.get("fields"), "detailed": bool(args.get("detailed", True))})
    if name in ("ha_get_entity", "ha_set_entity", "ha_remove_entity"):
        return call_entity_registry_tool(name, args)
    if name == "ha_search":
        query = str(args.get("query") or "")
        return {"entities": search_entities(query, int(args.get("limit") or 20))}
    if name == "ha_search_entities":
        query = str(args.get("query") or args.get("name") or "")
        limit = int(args.get("limit") or 50)
        domain = args.get("domain") or args.get("domain_filter")
        payload = search_entities(query, limit * 2 if domain else limit)
        results = payload.get("entities", [])
        if domain:
            results = [row for row in results if str(row.get("entity_id", "")).split(".", 1)[0] == str(domain)]
        return {"entities": results[:limit], "count": len(results[:limit])}
    if name == "ha_deep_search":
        query = str(args.get("query") or "")
        limit = int(args.get("limit") or 50)
        return {
            "entities": search_entities(query, limit),
            "config": search_active_config({"query": query, "limit": limit}) if query else [],
            "storage": search_common_storage(query, limit) if query else [],
            "files": search_files({"path": str(CONFIG_ROOT), "query": query, "recursive": True, "limit": limit}) if query else [],
            "tools": search_tools(query, 20),
        }
    if name == "ha_search_tools":
        return search_tools(str(args.get("query") or ""), int(args.get("limit") or 20), bool(args.get("include_schema")))
    if name in ("ha_call_read_tool", "ha_call_write_tool", "ha_call_delete_tool"):
        target = args.get("name") or args.get("tool")
        if not target:
            raise ValueError("name is required")
        target_name = str(target)
        lower = target_name.lower()
        if name == "ha_call_read_tool" and not any(hint in lower for hint in READ_ONLY_HINTS):
            raise ValueError(f"{target_name} is not obviously read-only; use ha_call_write_tool or the tool directly")
        if name == "ha_call_delete_tool" and not any(hint in lower for hint in ("delete", "remove")):
            raise ValueError(f"{target_name} is not obviously delete/remove; use ha_call_write_tool or the tool directly")
        return proxy_call_tool({"name": target_name, "arguments": args.get("arguments") or {}}, proxy_name=name)
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
        return get_automation_traces({
            "entity_id": entity_id,
            "run_id": args.get("run_id"),
            "latest": bool(args.get("latest")),
            "include_trace": bool(args.get("include_trace")),
            "limit": int(args.get("limit") or 100),
        })
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
        if is_self_addon_slug(slug) and action in SELF_UPDATE_ACTIONS:
            return self_update_not_supported(str(slug), str(action))
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
    if name in ("ha_get_device", "ha_set_device", "ha_remove_device"):
        return call_device_registry_tool(name, args)
    if name in ("ha_get_integration", "ha_set_integration_enabled"):
        if name == "ha_get_integration":
            domain = args.get("domain") or identifier
            return search_config_entries({"domain": domain, "query": args.get("query"), "limit": int(args.get("limit") or 20)})
        entry_id = args.get("entry_id") or args.get("id") or args.get("identifier")
        if not entry_id:
            raise ValueError("entry_id is required")
        result = ws_result({"type": "config_entries/disable", "entry_id": entry_id, "disabled_by": None if bool(args.get("enabled")) else "user"})
        return {"success": True, "entry_id": entry_id, "enabled": bool(args.get("enabled")), "require_restart": (result or {}).get("require_restart", False), "result": result}
    if name in ("ha_list_floors_areas", "ha_set_area_or_floor", "ha_remove_area_or_floor"):
        return call_area_floor_tool(name, args)
    if name in ("ha_config_get_label", "ha_config_set_label", "ha_config_remove_label", "ha_config_get_category", "ha_config_set_category", "ha_config_remove_category"):
        return call_label_category_tool(name, args)
    if name in ("ha_config_get_automation", "ha_config_get_script", "ha_config_get_scene"):
        domain = {"ha_config_get_automation": "automation", "ha_config_get_script": "script", "ha_config_get_scene": "scene"}[name]
        item_id = config_item_id(domain, args)
        return ha_request("GET", f"/config/{domain}/config/{item_id}") if item_id else list_entities({"domain": domain, "detailed": True, "limit": 10000})
    if name in ("ha_config_set_automation", "ha_config_set_script", "ha_config_set_scene"):
        domain = "automation" if "automation" in name else "script" if "script" in name else "scene"
        return update_config_item(domain, args)
    if name in ("ha_config_remove_automation", "ha_config_remove_script", "ha_config_remove_scene"):
        domain = "automation" if "automation" in name else "script" if "script" in name else "scene"
        item_id = config_item_id(domain, args)
        if not item_id:
            raise ValueError(f"{domain} id, entity_id, or identifier is required")
        return ha_request("DELETE", f"/config/{domain}/config/{item_id}")
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
        return call_zone_tool(name, args)
    if name in ("ha_get_todo", "ha_remove_todo_item", "ha_set_todo_item"):
        if name == "ha_get_todo":
            return ha_request("GET", f"/states/{identifier}") if identifier else list_entities({"domain": "todo", "detailed": True, "limit": 10000})
        return ha_request("POST", f"/services/todo/{'remove_item' if 'remove' in name else 'add_item'}", args.get("data") or {})
    if name == "ha_get_camera_image":
        entity_id = identifier
        if not entity_id:
            raise ValueError("entity_id is required")
        return ha_request("GET", f"/camera_proxy/{entity_id}")
    if name == "ha_get_dashboard_screenshot":
        return get_dashboard_screenshot(args)
    if name == "ha_manage_theme":
        return {"themes": search_files({"path": str(CONFIG_ROOT), "filename": "*.yaml", "query": args.get("query") or "frontend:", "recursive": True, "limit": int(args.get("limit") or 50)})}
    if name == "ha_manage_custom_tool":
        return manage_custom_tool(args)
    if name == "ha_install_mcp_tools":
        return install_mcp_tools(args)
    if name == "ha_report_issue":
        return {"title": args.get("title"), "body": args.get("body") or args.get("content"), "system_overview": system_overview()}
    if name == "ha_manage_pipeline":
        return call_pipeline_tool(args)
    if name == "ha_manage_energy_prefs":
        return call_energy_tool(args)
    if name in ("ha_config_list_groups", "ha_config_set_group", "ha_config_remove_group"):
        return call_group_tool(name, args)
    if name in ("ha_config_list_helpers", "ha_config_set_helper", "ha_remove_helpers_integrations"):
        return call_helper_tool(name, args)
    if name in ("ha_get_blueprint", "ha_import_blueprint"):
        return call_blueprint_tool(name, args)
    if name in ("ha_config_get_calendar_events", "ha_config_set_calendar_event", "ha_config_remove_calendar_event"):
        return call_calendar_tool(name, args)
    if name == "ha_get_entity_exposure":
        exposed = ws_result({"type": "homeassistant/expose_entity/list"}).get("exposed_entities", {})
        assistant = args.get("assistant")
        entity_id = args.get("entity_id") or identifier
        if entity_id:
            settings = exposed.get(entity_id, {})
            return {"success": True, "entity_id": entity_id, "exposed_to": settings, "is_exposed_anywhere": any(settings.values()), "has_custom_settings": entity_id in exposed}
        if assistant:
            exposed = {eid: settings for eid, settings in exposed.items() if settings.get(assistant)}
        return {"success": True, "exposed_entities": exposed, "count": len(exposed), "filters_applied": {"assistant": assistant} if assistant else {}}
    raise ValueError(f"Unhandled upstream compatibility tool: {name}")


def config_item_id(domain: str, args: dict[str, Any]) -> str | None:
    raw = first_present(args, "id", "identifier", "entity_id", "item_id", "name")
    if raw:
        text = str(raw)
        prefix = f"{domain}."
        if text.startswith(prefix):
            try:
                state = ha_request("GET", f"/states/{text}")
                attrs = state.get("attributes") or {}
                if attrs.get("id"):
                    return str(attrs["id"])
            except Exception:
                pass
        return text.removeprefix(prefix)
    query = args.get("query")
    if query:
        matches = list_domain_configs(domain, {"query": query, "limit": 2}).get("items", [])
        if len(matches) == 1:
            match = matches[0]
            return str(match.get("config_id") or match.get("id") or match.get("entity_id", "").removeprefix(f"{domain}."))
        if len(matches) > 1:
            raise ValueError(f"Query matched multiple {domain}s; pass id or entity_id")
    return None


def update_config_item(domain: str, args: dict[str, Any]) -> dict[str, Any]:
    item_id = config_item_id(domain, args)
    if not item_id:
        raise ValueError(f"{domain} id, entity_id, or identifier is required")
    config = args.get("config") if args.get("config") is not None else args.get("data")
    if config is None and args.get("content"):
        config = json.loads(str(args["content"]))
    if not isinstance(config, dict):
        raise ValueError("config or data object is required")
    config = normalize_domain_config(domain, config)
    endpoint = f"/config/{domain}/config/{item_id}"
    if args.get("config_hash"):
        current = ha_request("GET", endpoint)
        if not isinstance(current, dict):
            raise ValueError(f"Current {domain} config is not an object")
        current = normalize_domain_config(domain, current)
        if compute_config_hash(current) != str(args["config_hash"]):
            raise ValueError("config_hash mismatch; fetch the current config and retry with the fresh hash")
    if bool(args.get("dry_run")):
        current = ha_request("GET", endpoint)
        current = normalize_domain_config(domain, current) if isinstance(current, dict) else current
        return {"domain": domain, "id": item_id, "endpoint": endpoint, "dry_run": True, "current": current, "current_hash": compute_config_hash(current) if isinstance(current, dict) else None, "would_write": config, "would_write_hash": compute_config_hash(config)}
    audit_event(f"update_{domain}", {"id": item_id})
    result = ha_request("POST", endpoint, config)
    response: dict[str, Any] = {"domain": domain, "id": item_id, "endpoint": endpoint, "updated": True, "result": result}
    if bool(args.get("check_config")):
        response["check_config"] = run_config_check()
    if bool(args.get("reload")):
        response["reload"] = ha_request("POST", f"/services/{domain}/reload", {})
    return response


def delete_config_item(domain: str, args: dict[str, Any]) -> dict[str, Any]:
    item_id = config_item_id(domain, args)
    if not item_id:
        raise ValueError(f"{domain} id, entity_id, or identifier is required")
    endpoint = f"/config/{domain}/config/{item_id}"
    if bool(args.get("dry_run")):
        current = ha_request("GET", endpoint)
        return {"domain": domain, "id": item_id, "endpoint": endpoint, "dry_run": True, "current": current}
    if not bool(args.get("force")):
        raise ValueError(f"delete_{domain} requires force=true")
    audit_event(f"delete_{domain}", {"id": item_id})
    result = ha_request("DELETE", endpoint)
    return {"domain": domain, "id": item_id, "endpoint": endpoint, "deleted": True, "result": result}


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
    root = visible_path(args.get("path"))
    query = str(args.get("query") or "").lower()
    filename = args.get("filename")
    recursive = bool(args.get("recursive", True))
    limit = int(args.get("limit") or 100)
    max_file_bytes = int(args.get("max_file_bytes") or 2_000_000)
    iterator = [root] if root.is_file() else root.rglob("*") if recursive else root.iterdir()
    matches: list[dict[str, Any]] = []
    for path in iterator:
        if len(matches) >= limit:
            break
        try:
            filename_match = file_matches_pattern(path, root, str(filename)) if filename else False
            if filename and not filename_match:
                continue
            if filename and not query:
                matches.append(file_match_row(path, root, "filename"))
                continue
            if not query or not path.is_file() or path.stat().st_size > max_file_bytes:
                continue
            if path.suffix.lower() not in TEXT_EXTENSIONS:
                continue
            for line_number, line in enumerate(path.read_text(errors="replace").splitlines(), 1):
                if query in line.lower():
                    row = file_match_row(path, root, "content")
                    row.update({"line": line_number, "text": line[:500], "filename_match": filename_match})
                    matches.append(row)
                    break
        except OSError as err:
            matches.append({"path": str(path), "error": str(err)})
    return matches


def file_match_row(path: Path, root: Path, match: str) -> dict[str, Any]:
    row = {"path": str(path), "name": path.name, "match": match}
    try:
        row["relative_path"] = str(path.resolve().relative_to(root.resolve())).replace("\\", "/")
    except ValueError:
        pass
    return row


def file_matches_pattern(path: Path, root: Path, pattern: str) -> bool:
    normalized = pattern.replace("\\", "/").lower()
    try:
        relative = str(path.resolve().relative_to(root.resolve())).replace("\\", "/").lower()
    except ValueError:
        relative = str(path).replace("\\", "/").lower()
    candidates = {
        path.name.lower(),
        relative,
        str(path).replace("\\", "/").lower(),
    }
    patterns = {normalized}
    if "/" not in normalized:
        patterns.add(f"*/{normalized}")
    return any(fnmatch.fnmatch(candidate, test) for candidate in candidates for test in patterns)


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


def visible_path(path: Any = None, *, require: bool = False) -> Path:
    if path in (None, ""):
        if require:
            raise ValueError("path is required")
        return CONFIG_ROOT.resolve()
    candidate = Path(str(path))
    if candidate.is_absolute():
        return candidate.resolve()
    return (CONFIG_ROOT / candidate).resolve()


def config_path(path: str) -> Path:
    if not path or path == ".":
        return CONFIG_ROOT.resolve()
    candidate = Path(path)
    root = CONFIG_ROOT.resolve()
    if candidate.is_absolute():
        target = candidate.resolve()
        if target == root or root in target.parents:
            return target
        raise ValueError("Absolute config paths must stay under /config")
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


def secrets_yaml_path() -> Path:
    return config_path("secrets.yaml")


def parse_secret_lines() -> tuple[Path, list[str]]:
    path = secrets_yaml_path()
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


def search_common_storage(query: str, limit: int) -> dict[str, Any]:
    keys = [
        "core.entity_registry",
        "core.device_registry",
        "core.config_entries",
        "core.area_registry",
        "core.floor_registry",
        "core.label_registry",
        "core.restore_state",
        "lovelace",
        "lovelace_resources",
    ]
    rows = []
    per_key_limit = max(1, min(limit, 20))
    for key in keys:
        if len(rows) >= limit:
            break
        try:
            matches = search_storage_key(key, query, per_key_limit)
        except FileNotFoundError:
            continue
        except Exception as err:
            rows.append({"key": key, "error": str(err)})
            continue
        for match in matches:
            rows.append({"key": key, **match})
            if len(rows) >= limit:
                break
    return {"query": query, "count": len(rows), "matches": rows}


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


def registry_definition(args: dict[str, Any]) -> dict[str, Any]:
    raw = str(args.get("registry") or args.get("key") or "").strip()
    if not raw:
        raise ValueError("registry or key is required")
    normalized = raw.removeprefix("core.").replace("-", "_")
    aliases = {
        "entities": "entity",
        "entity_registry": "entity",
        "device_registry": "device",
        "devices": "device",
        "areas": "area",
        "area_registry": "area",
        "floors": "floor",
        "floor_registry": "floor",
        "labels": "label",
        "label_registry": "label",
        "categories": "category",
        "category_registry": "category",
        "config_entries": "config_entry",
        "config_entry_registry": "config_entry",
        "issues": "issue",
        "issue_registry": "issue",
        "repairs.issue_registry": "issue",
    }
    name = aliases.get(normalized, normalized)
    if raw in REGISTRY_KEY_ALIASES:
        name = REGISTRY_KEY_ALIASES[raw]
    if name not in REGISTRY_DEFINITIONS:
        known = sorted(REGISTRY_DEFINITIONS) + sorted(REGISTRY_KEY_ALIASES)
        raise ValueError(f"Unknown registry: {raw}. Known registries: {', '.join(known)}")
    definition = dict(REGISTRY_DEFINITIONS[name])
    definition["name"] = name
    return definition


def registry_rows(definition: dict[str, Any], data: dict[str, Any]) -> list[dict[str, Any]]:
    rows = data.setdefault("data", {}).setdefault(str(definition["list"]), [])
    if not isinstance(rows, list):
        raise ValueError(f"{definition['key']} data.{definition['list']} is not a list")
    return rows


def list_registries(include_counts: bool = False) -> dict[str, Any]:
    registries = []
    for name, definition in REGISTRY_DEFINITIONS.items():
        row = {"name": name, **definition, "path": str(storage_path(definition["key"])), "exists": storage_path(definition["key"]).exists()}
        if include_counts:
            try:
                row["count"] = len(load_storage_json(definition["key"]).get("data", {}).get(definition["list"], []))
            except Exception as err:
                row["count_error"] = str(err)
        registries.append(row)
    return {"count": len(registries), "registries": registries}


def read_registry(args: dict[str, Any]) -> dict[str, Any]:
    definition = registry_definition(args)
    data = load_storage_json(definition["key"])
    rows = registry_rows(definition, data)
    limit = int(args.get("limit") or 100)
    result = {
        "registry": definition["name"],
        "key": definition["key"],
        "list": definition["list"],
        "path": str(storage_path(definition["key"])),
        "count": len(rows),
        "current_hash": path_hash(storage_path(definition["key"])),
        "version": data.get("version"),
        "minor_version": data.get("minor_version"),
    }
    if bool(args.get("include_entries")):
        result["entries"] = rows[:limit]
        result["truncated"] = len(rows) > limit
    return result


def registry_entry_matches(row: dict[str, Any], filters: dict[str, Any], query: str = "") -> bool:
    for key_name, wanted in filters.items():
        if wanted is None:
            continue
        if str(row.get(str(key_name)) or "") != str(wanted):
            return False
    return not query or contains_text(row, query)


def registry_selector_filters(definition: dict[str, Any], args: dict[str, Any]) -> dict[str, Any]:
    filters = {}
    for selector in definition["selectors"]:
        if args.get(selector) is not None:
            filters[selector] = args[selector]
    return filters


def search_registry(args: dict[str, Any]) -> dict[str, Any]:
    definition = registry_definition(args)
    data = load_storage_json(definition["key"])
    rows = registry_rows(definition, data)
    filters = args.get("filters") or {}
    if not isinstance(filters, dict):
        raise ValueError("filters must be an object")
    query = str(args.get("query") or "").lower()
    limit = int(args.get("limit") or 100)
    matches = []
    for row in rows:
        if len(matches) >= limit:
            break
        if registry_entry_matches(row, filters, query):
            matches.append(row)
    return {"registry": definition["name"], "key": definition["key"], "list": definition["list"], "count": len(matches), "matches": matches}


def find_registry_entries(definition: dict[str, Any], args: dict[str, Any], rows: list[dict[str, Any]]) -> list[tuple[int, dict[str, Any]]]:
    filters = registry_selector_filters(definition, args)
    query = str(args.get("query") or "").lower()
    if not filters and not query:
        raise ValueError("At least one selector or query is required")
    matches = []
    for index, row in enumerate(rows):
        if registry_entry_matches(row, filters, query):
            matches.append((index, row))
    return matches


def get_registry_entry(args: dict[str, Any]) -> dict[str, Any]:
    definition = registry_definition(args)
    data = load_storage_json(definition["key"])
    rows = registry_rows(definition, data)
    matches = find_registry_entries(definition, args, rows)
    if len(matches) != 1:
        raise ValueError(f"Expected exactly one {definition['key']} match, found {len(matches)}")
    index, entry = matches[0]
    return {"registry": definition["name"], "key": definition["key"], "list": definition["list"], "index": index, "entry": entry}


def duplicate_registry_matches(definition: dict[str, Any], entry: dict[str, Any], rows: list[dict[str, Any]]) -> list[tuple[int, dict[str, Any]]]:
    selectors = {selector: entry.get(selector) for selector in definition["selectors"] if entry.get(selector) is not None}
    if not selectors:
        raise ValueError(f"entry must include one of: {', '.join(definition['selectors'])}")
    matches = []
    for index, row in enumerate(rows):
        if any(str(row.get(selector) or "") == str(value) for selector, value in selectors.items()):
            matches.append((index, row))
    return matches


def registry_write_result(definition: dict[str, Any], data: dict[str, Any], args: dict[str, Any], action: str, before: Any, after: Any) -> dict[str, Any]:
    path = storage_path(definition["key"])
    if bool(args.get("dry_run")):
        return {"registry": definition["name"], "key": definition["key"], "dry_run": True, "before": before, "after": after, "current_hash": path_hash(path)}
    backup = backup_path(path, args.get("label") or definition["key"]) if bool(args.get("backup", True)) and path.exists() else None
    info = dump_storage_json(definition["key"], data)
    audit_event(action, {"key": definition["key"], "backup": backup})
    return {"registry": definition["name"], "key": definition["key"], "before": before, "after": after, "backup": backup, "storage": info}


def create_registry_entry(args: dict[str, Any]) -> dict[str, Any]:
    definition = registry_definition(args)
    path = storage_path(definition["key"])
    require_expected_hash(path, args.get("expected_hash"))
    entry = args.get("entry")
    if not isinstance(entry, dict):
        raise ValueError("entry must be an object")
    data = load_storage_json(definition["key"])
    rows = registry_rows(definition, data)
    matches = duplicate_registry_matches(definition, entry, rows)
    before = None
    if matches:
        if not bool(args.get("upsert")):
            raise ValueError(f"Registry entry already exists; found {len(matches)} match(es)")
        if len(matches) != 1:
            raise ValueError(f"Upsert expected exactly one existing entry, found {len(matches)}")
        index, before_entry = matches[0]
        before = json.loads(json.dumps(before_entry, default=str))
        rows[index] = entry
    else:
        rows.append(entry)
    return registry_write_result(definition, data, args, "create_registry_entry", before, entry)


def replace_registry_entry(args: dict[str, Any]) -> dict[str, Any]:
    definition = registry_definition(args)
    path = storage_path(definition["key"])
    require_expected_hash(path, args.get("expected_hash"))
    entry = args.get("entry")
    if not isinstance(entry, dict):
        raise ValueError("entry must be an object")
    data = load_storage_json(definition["key"])
    rows = registry_rows(definition, data)
    matches = find_registry_entries(definition, args, rows)
    if len(matches) != 1:
        raise ValueError(f"Expected exactly one {definition['key']} match, found {len(matches)}")
    index, before_entry = matches[0]
    before = json.loads(json.dumps(before_entry, default=str))
    rows[index] = entry
    return registry_write_result(definition, data, args, "replace_registry_entry", before, entry)


def patch_any_registry_entry(args: dict[str, Any]) -> dict[str, Any]:
    definition = registry_definition(args)
    path = storage_path(definition["key"])
    require_expected_hash(path, args.get("expected_hash"))
    data = load_storage_json(definition["key"])
    rows = registry_rows(definition, data)
    matches = find_registry_entries(definition, args, rows)
    if len(matches) != 1:
        raise ValueError(f"Expected exactly one {definition['key']} match, found {len(matches)}")
    _index, entry = matches[0]
    before = json.loads(json.dumps(entry, default=str))
    for key_name in args.get("remove_keys") or []:
        entry.pop(str(key_name), None)
    patch = args.get("patch") or {}
    if patch:
        if not isinstance(patch, dict):
            raise ValueError("patch must be an object")
        entry.update(patch)
    after = json.loads(json.dumps(entry, default=str))
    return registry_write_result(definition, data, args, "patch_registry_entry", before, after)


def delete_registry_entry(args: dict[str, Any]) -> dict[str, Any]:
    definition = registry_definition(args)
    path = storage_path(definition["key"])
    require_expected_hash(path, args.get("expected_hash"))
    data = load_storage_json(definition["key"])
    rows = registry_rows(definition, data)
    matches = find_registry_entries(definition, args, rows)
    if len(matches) != 1:
        raise ValueError(f"Expected exactly one {definition['key']} match, found {len(matches)}")
    index, entry = matches[0]
    before = json.loads(json.dumps(entry, default=str))
    if bool(args.get("dry_run")):
        return {"registry": definition["name"], "key": definition["key"], "index": index, "dry_run": True, "would_delete": before, "current_hash": path_hash(path)}
    if not bool(args.get("force")):
        raise ValueError("delete_registry_entry requires force=true")
    del rows[index]
    return registry_write_result(definition, data, args, "delete_registry_entry", before, None)


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


def get_config_entry(args: dict[str, Any]) -> dict[str, Any]:
    result = search_config_entries(args | {"limit": 100})
    if len(result["matches"]) != 1:
        raise ValueError(f"Expected exactly one config entry, found {len(result['matches'])}")
    return {"key": "core.config_entries", "entry": result["matches"][0]}


def patch_config_entry(args: dict[str, Any]) -> dict[str, Any]:
    return patch_registry_entry("core.config_entries", "entries", args, ["entry_id", "domain", "title", "source"])


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
        if args.get("scope") and str(row.get("scope") or "") != str(args["scope"]):
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
        for row in iter_live_lovelace_view_cards(view, view_index):
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
        for row in iter_live_lovelace_view_cards(view, view_index):
            if card_matches(row, args):
                matches.append(row)
                if len(matches) >= limit:
                    return matches
    return matches


def iter_live_lovelace_view_cards(view: Any, view_index: int) -> list[dict[str, Any]]:
    view_path = f"$.views[{view_index}]"
    rows = iter_lovelace_cards(view, view_path)
    section_container = re.compile(rf"^{re.escape(view_path)}\.sections\[\d+\]$")
    return [row for row in rows if row["path"] != view_path and not section_container.match(row["path"])]


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


def is_mcp_path(path: str) -> bool:
    return urllib.parse.urlsplit(path).path == MCP_PATH


class Handler(BaseHTTPRequestHandler):
    server_version = "HAAdminMCP/0.1"

    def do_GET(self) -> None:
        if self.path == "/health":
            self.write_json({"ok": True, "dangerous": True})
            return
        if self.path in {"/icon.png", "/logo.png", "/icon.svg", "/logo.svg"}:
            self.write_asset(APP_ROOT / self.path.lstrip("/"))
            return
        if is_mcp_path(self.path):
            if not self.authorized():
                self.write_json({"error": "unauthorized"}, status=401)
                return
            self.send_error(405, "SSE streams are not implemented")
            return
        self.send_error(404)

    def do_POST(self) -> None:
        if not is_mcp_path(self.path):
            self.send_error(404)
            return
        if not self.authorized():
            self.write_json({"error": "unauthorized"}, status=401)
            return
        protocol_header = self.headers.get("MCP-Protocol-Version")
        if protocol_header and protocol_header not in SUPPORTED_PROTOCOL_VERSIONS:
            self.write_json(
                {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32600, "message": f"Unsupported MCP-Protocol-Version: {protocol_header}"},
                },
                status=400,
            )
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
        if is_mcp_path(self.path):
            if not self.authorized():
                self.write_json({"error": "unauthorized"}, status=401)
                return
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
                    "serverInfo": app_server_info(self.headers),
                    "capabilities": {
                        "tools": {"listChanged": True},
                        "resources": {"subscribe": False, "listChanged": True},
                        "prompts": {"listChanged": True},
                        "completions": {},
                        "logging": {},
                    },
                    "_meta": {
                        "endpointPath": MCP_PATH,
                        "port": MCP_PORT,
                        "dangerous": True,
                        "supportedProtocolVersions": sorted(SUPPORTED_PROTOCOL_VERSIONS),
                    },
                }
            elif method == "tools/list":
                result = paginated(TOOLS, request.get("params") or {}, "tools")
            elif method == "prompts/list":
                result = paginated(PROMPTS, request.get("params") or {}, "prompts")
            elif method == "prompts/get":
                params = request.get("params") or {}
                result = get_prompt(params["name"], params.get("arguments") or {})
            elif method == "resources/list":
                result = paginated(RESOURCES, request.get("params") or {}, "resources")
            elif method == "resources/read":
                params = request.get("params") or {}
                result = read_resource(params["uri"])
            elif method == "resources/templates/list":
                result = paginated(RESOURCE_TEMPLATES, request.get("params") or {}, "resourceTemplates")
            elif method in ("resources/subscribe", "resources/unsubscribe"):
                result = {}
            elif method == "tools/call":
                params = request.get("params") or {}
                tool_name = params.get("name")
                if not tool_name:
                    return self.rpc_error(request_id, -32602, "Tool name is required")
                known_tool_names = {tool["name"] for tool in TOOLS}
                if tool_name not in known_tool_names:
                    return self.rpc_error(request_id, -32602, f"Unknown tool: {tool_name}")
                try:
                    tool_value = call_tool(tool_name, params.get("arguments") or {})
                    result = tool_value if is_mcp_content_result(tool_value) else text_result(tool_value)
                except Exception as err:
                    result = tool_error_result(str(err), {"tool": tool_name})
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
        data = json.dumps(payload, default=str, ensure_ascii=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(data)

    def write_asset(self, path: Path) -> None:
        if not path.exists() or path.parent != APP_ROOT:
            self.send_error(404)
            return
        mime = "image/svg+xml" if path.suffix == ".svg" else "image/png"
        data = path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", mime)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, fmt: str, *args: Any) -> None:
        print(f"[ha-admin-mcp] {self.address_string()} {fmt % args}", flush=True)


def main() -> None:
    host = str(OPTIONS.get("bind_host") or "0.0.0.0")
    print(
        "[ha-admin-mcp] EXTREMELY DANGEROUS server listening on "
        f"{host}:{MCP_PORT}{MCP_PATH}; installing and starting this app grants admin MCP access",
        flush=True,
    )
    ThreadingHTTPServer((host, MCP_PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()
