from __future__ import annotations

import fnmatch
import base64
import json
import os
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
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

ADDON_OPTIONS = Path("/data/options.json")
APP_VERSION = "0.1.17"
CONFIG_ROOT = Path("/config")
DEFAULT_BACKUP_DIR = Path("/backup/ha-admin-mcp")
MAX_READ_BYTES = 20_000_000
SUPPORTED_PROTOCOL_VERSIONS = {"2025-06-18", "2025-03-26", "2024-11-05"}
S6_ENV_DIR = Path("/run/s6/container_environment")
MCP_PATH = "/api/mcp"
LOG_LEVEL = "info"
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


def tool_schema(name: str, description: str, properties: dict[str, Any], required: list[str] | None = None) -> dict[str, Any]:
    return {
        "name": name,
        "description": description,
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
        "read_file_base64",
        "Read any visible file as base64 for binary-safe transfer",
        {"path": {"type": "string"}, "max_bytes": {"type": "integer", "minimum": 1, "maximum": 100000000}},
        ["path"],
    ),
    tool_schema(
        "write_file_base64",
        "Write a visible file from base64 content, creating parent directories if needed",
        {"path": {"type": "string"}, "content_base64": {"type": "string"}, "mode": {"type": "string"}},
        ["path", "content_base64"],
    ),
    tool_schema(
        "write_file",
        "Write a file visible to the app, creating parent directories if needed",
        {"path": {"type": "string"}, "content": {"type": "string"}, "mode": {"type": "string"}},
        ["path", "content"],
    ),
    tool_schema(
        "delete_path",
        "Delete any visible file or directory",
        {"path": {"type": "string"}, "recursive": {"type": "boolean"}},
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
    tool_schema("restart_core", "Restart Home Assistant Core through Supervisor", {}, []),
    tool_schema("stop_core", "Stop Home Assistant Core through Supervisor", {}, []),
    tool_schema("start_core", "Start Home Assistant Core through Supervisor", {}, []),
    tool_schema("reload_core_config", "Reload Home Assistant core config through REST API", {}, []),
    tool_schema(
        "check_reload_readiness",
        "Run a config check and report common reload/restart options available through services",
        {},
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
        "write_config_file",
        "Write a text file under /config, optionally backing up to /backup/ha-admin-mcp and running config check",
        {
            "path": {"type": "string"},
            "content": {"type": "string"},
            "mode": {"type": "string"},
            "backup": {"type": "boolean"},
            "check_config": {"type": "boolean"},
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
        "read_lovelace_dashboards",
        "List or read Lovelace dashboard storage files",
        {"include_content": {"type": "boolean"}, "max_bytes": {"type": "integer", "minimum": 1, "maximum": 100000000}},
        [],
    ),
    tool_schema(
        "list_lovelace_dashboards",
        "List Lovelace dashboards from HA's dashboard registry with matching storage keys",
        {"include_config": {"type": "boolean"}, "max_bytes": {"type": "integer", "minimum": 1, "maximum": 100000000}},
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
        },
        [],
    ),
    tool_schema(
        "delete_lovelace_dashboard",
        "Delete a Lovelace dashboard registry entry and storage file by id, url_path, or key",
        {"id": {"type": "string"}, "url_path": {"type": "string"}, "key": {"type": "string"}, "backup": {"type": "boolean"}},
        [],
    ),
    tool_schema(
        "write_storage_key",
        "Write a Home Assistant .storage key from JSON data or raw content",
        {"key": {"type": "string"}, "data": {"type": "object"}, "content": {"type": "string"}, "mode": {"type": "string"}},
        ["key"],
    ),
    tool_schema(
        "delete_storage_key",
        "Delete a Home Assistant .storage key",
        {"key": {"type": "string"}},
        ["key"],
    ),
    tool_schema(
        "backup_storage_key",
        "Copy a Home Assistant .storage key into /backup/ha-admin-mcp",
        {"key": {"type": "string"}, "label": {"type": "string"}},
        ["key"],
    ),
]


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
    if name == "run_command":
        timeout = int(args.get("timeout") or OPTIONS.get("command_timeout_seconds") or 300)
        max_output = int(args.get("max_output_bytes") or 20000)
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
    if name == "read_file_base64":
        data, truncated = read_bytes_limited(Path(args["path"]), int(args.get("max_bytes") or MAX_READ_BYTES))
        return {"path": args["path"], "content_base64": base64.b64encode(data).decode(), "truncated": truncated}
    if name == "write_file":
        path = Path(args["path"])
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(args["content"])
        if args.get("mode"):
            path.chmod(int(str(args["mode"]), 8))
        return path_info(path)
    if name == "write_file_base64":
        path = Path(args["path"])
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(base64.b64decode(args["content_base64"]))
        if args.get("mode"):
            path.chmod(int(str(args["mode"]), 8))
        return path_info(path)
    if name == "delete_path":
        path = Path(args["path"])
        if path.is_dir() and not path.is_symlink():
            if not args.get("recursive"):
                path.rmdir()
            else:
                shutil.rmtree(path)
        else:
            path.unlink()
        return {"path": str(path), "deleted": True}
    if name == "search_files":
        return search_files(args)
    if name == "glob_paths":
        return glob_paths(args["pattern"], int(args.get("limit") or 500))
    if name == "hash_file":
        return hash_file(Path(args["path"]), args.get("algorithm") or "sha256")
    if name == "ha_api":
        return ha_request(args.get("method", "GET"), args["endpoint"], args.get("data"))
    if name == "supervisor_api":
        return supervisor_request(args.get("method", "GET"), args["endpoint"], args.get("data"))
    if name == "http_request":
        return http_request(args)
    if name == "check_config":
        return supervisor_request("POST", "/core/check")
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
        return supervisor_request("POST", f"/addons/{args['slug']}/{args['action']}")
    if name == "restart_core":
        return supervisor_request("POST", "/core/restart")
    if name == "stop_core":
        return supervisor_request("POST", "/core/stop")
    if name == "start_core":
        return supervisor_request("POST", "/core/start")
    if name == "reload_core_config":
        return ha_request("POST", "/services/homeassistant/reload_core_config")
    if name == "check_reload_readiness":
        return check_reload_readiness()
    if name == "reload_domain_config":
        return ha_request("POST", f"/services/{args['domain']}/reload", args.get("data") or {})
    if name == "call_service":
        return ha_request("POST", f"/services/{args['domain']}/{args['service']}", args.get("data") or {})
    if name == "get_states":
        entity_id = args.get("entity_id")
        return ha_request("GET", f"/states/{entity_id}" if entity_id else "/states")
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
    if name == "render_template":
        return ha_request("POST", "/template", {"template": args["template"]})
    if name == "fire_event":
        return ha_request("POST", f"/events/{args['event_type']}", args.get("event_data") or {})
    if name == "backup_path":
        return backup_path(Path(args["path"]), args.get("label"))
    if name == "list_config_files":
        return list_config_files(args)
    if name == "read_config_file":
        content, truncated = read_limited(config_path(args["path"]), int(args.get("max_bytes") or MAX_READ_BYTES))
        return {"path": str(config_path(args["path"])), "relative_path": args["path"], "content": content, "truncated": truncated}
    if name == "write_config_file":
        return write_config_file(args)
    if name == "search_config":
        search_args = dict(args)
        search_args["path"] = str(config_path(search_args.get("path") or "."))
        return search_files(search_args)
    if name == "tail_log":
        return tail_log(args)
    if name == "list_storage_keys":
        return list_storage_keys(bool(args.get("include_backups")))
    if name == "list_storage_keys_filtered":
        return list_storage_keys_filtered(args)
    if name == "read_storage_key":
        return read_storage_key(args["key"], int(args.get("max_bytes") or MAX_READ_BYTES))
    if name == "search_storage_key":
        return search_storage_key(args["key"], args["query"], int(args.get("limit") or 50))
    if name == "search_storage_json":
        return search_storage_json(args)
    if name == "read_storage_json_path":
        return read_storage_json_path(args["key"], args["path"])
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
    if name == "sqlite_query":
        return sqlite_query(args)
    if name == "read_lovelace_dashboards":
        return read_lovelace_dashboards(bool(args.get("include_content")), int(args.get("max_bytes") or MAX_READ_BYTES))
    if name == "list_lovelace_dashboards":
        return list_lovelace_dashboards(bool(args.get("include_config")), int(args.get("max_bytes") or MAX_READ_BYTES))
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
    if name == "save_lovelace_dashboard":
        return save_lovelace_dashboard(args)
    if name == "delete_lovelace_dashboard":
        return delete_lovelace_dashboard(args)
    if name == "write_storage_key":
        return write_storage_key(args["key"], args)
    if name == "delete_storage_key":
        path = storage_path(args["key"])
        path.unlink()
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
    return result


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
    check = supervisor_request("POST", "/core/check")
    services = ha_request("GET", "/services")
    reloads = []
    for domain in services:
        domain_name = domain.get("domain")
        for service in domain.get("services", {}):
            if service.startswith("reload"):
                reloads.append({"domain": domain_name, "service": service})
    return {"check_config": check, "reload_services": reloads}


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
    path.parent.mkdir(parents=True, exist_ok=True)
    if "content" in args and args["content"] is not None:
        path.write_text(str(args["content"]))
    else:
        path.write_text(json.dumps(args.get("data"), indent=2, default=str))
    if args.get("mode"):
        path.chmod(int(str(args["mode"]), 8))
    return path_info(path) | {"key": key}


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


def patch_storage_json_path(args: dict[str, Any]) -> dict[str, Any]:
    key = args["key"]
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
    backup = backup_path(storage_path(key), args.get("label") or key) if bool(args.get("backup", True)) and storage_path(key).exists() else None
    info = dump_storage_json(key, data)
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
    backups: dict[str, Any] = {}
    if bool(args.get("backup", True)):
        backups["dashboard"] = backup_path(storage_path(key), args.get("label") or key)
    info = dump_storage_json(key, storage)
    return {"changed": True, "item": item, "key": key, "path": target_path, "before": before, "after": after, "dashboard": info, "backups": backups}


def lovelace_storage_path(key: str) -> Path:
    if not (key == "lovelace_dashboards" or key == "lovelace_resources" or key.startswith("lovelace.")):
        raise ValueError("Lovelace dashboard keys must be lovelace.*, lovelace_dashboards, or lovelace_resources")
    return storage_path(key)


def save_lovelace_dashboard(args: dict[str, Any]) -> dict[str, Any]:
    if args.get("key") and not any(args.get(name) is not None for name in ("id", "url_path", "title", "config", "views")):
        path = lovelace_storage_path(args["key"])
        backup = backup_path(path, args.get("label") or args["key"]) if bool(args.get("backup", True)) and path.exists() else None
        if "content" in args and args["content"] is not None:
            path.write_text(str(args["content"]))
        else:
            path.write_text(json.dumps(args.get("data"), indent=2, default=str))
        if args.get("mode"):
            path.chmod(int(str(args["mode"]), 8))
        return path_info(path) | {"key": args["key"], "backup": backup, "mode": "raw_storage_key"}

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
    backups: dict[str, Any] = {}
    if bool(args.get("backup", True)):
        if path.exists():
            backups["dashboard"] = backup_path(path, args.get("label") or key)
        registry_path = storage_path("lovelace_dashboards")
        if registry_path.exists():
            backups["registry"] = backup_path(registry_path, args.get("label") or "lovelace_dashboards")

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
    dashboard_info = dump_storage_json(key, dashboard_storage, args.get("mode"))
    registry_info = dump_storage_json("lovelace_dashboards", registry)
    return {"item": item, "key": key, "dashboard": dashboard_info, "registry": registry_info, "backups": backups}


def delete_lovelace_dashboard(args: dict[str, Any]) -> dict[str, Any]:
    registry, item = resolve_lovelace_dashboard(args)
    if item is None:
        raise ValueError("Dashboard not found")
    key = dashboard_item_key(item)
    path = storage_path(key)
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
    return {"item": item, "key": key, "deleted_storage": deleted, "registry": registry_info, "backups": backups}


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
            "find_lovelace_cards/get_lovelace_card to locate exactly one card, then patch_lovelace_card with "
            "expected_matches=1. Do not full-save a dashboard unless the targeted patch tools cannot express the change."
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
