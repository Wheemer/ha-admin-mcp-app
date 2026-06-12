from __future__ import annotations

import fnmatch
import base64
import json
import os
import shutil
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
APP_VERSION = "0.1.9"
DEFAULT_BACKUP_DIR = Path("/backup/ha-admin-mcp")
MAX_READ_BYTES = 20_000_000
SUPPORTED_PROTOCOL_VERSIONS = {"2025-03-26", "2024-11-05"}
S6_ENV_DIR = Path("/run/s6/container_environment")
MCP_PATH = "/api/mcp"
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
    tool_schema("list_storage_keys", "List Home Assistant .storage keys", {"include_backups": {"type": "boolean"}}, []),
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
        "read_lovelace_dashboards",
        "List or read Lovelace dashboard storage files",
        {"include_content": {"type": "boolean"}, "max_bytes": {"type": "integer", "minimum": 1, "maximum": 100000000}},
        [],
    ),
    tool_schema(
        "save_lovelace_dashboard",
        "Save a Lovelace dashboard storage key, optionally backing up the previous file under /backup/ha-admin-mcp",
        {
            "key": {"type": "string"},
            "data": {"type": "object"},
            "content": {"type": "string"},
            "backup": {"type": "boolean"},
            "label": {"type": "string"},
            "mode": {"type": "string"},
        },
        ["key"],
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
    if name == "list_storage_keys":
        return list_storage_keys(bool(args.get("include_backups")))
    if name == "read_storage_key":
        return read_storage_key(args["key"], int(args.get("max_bytes") or MAX_READ_BYTES))
    if name == "search_storage_key":
        return search_storage_key(args["key"], args["query"], int(args.get("limit") or 50))
    if name == "read_lovelace_dashboards":
        return read_lovelace_dashboards(bool(args.get("include_content")), int(args.get("max_bytes") or MAX_READ_BYTES))
    if name == "save_lovelace_dashboard":
        return save_lovelace_dashboard(args["key"], args)
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


def lovelace_storage_path(key: str) -> Path:
    if not (key == "lovelace_dashboards" or key == "lovelace_resources" or key.startswith("lovelace.")):
        raise ValueError("Lovelace dashboard keys must be lovelace.*, lovelace_dashboards, or lovelace_resources")
    return storage_path(key)


def save_lovelace_dashboard(key: str, args: dict[str, Any]) -> dict[str, Any]:
    path = lovelace_storage_path(key)
    backup = None
    if bool(args.get("backup", True)) and path.exists():
        backup = backup_path(path, args.get("label") or key)
    if "content" in args and args["content"] is not None:
        path.write_text(str(args["content"]))
    else:
        path.write_text(json.dumps(args.get("data"), indent=2, default=str))
    if args.get("mode"):
        path.chmod(int(str(args["mode"]), 8))
    return path_info(path) | {"key": key, "backup": backup}


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
        message = json.loads(self.rfile.read(length) or b"{}")
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
            self.send_error(405, "Session termination is not implemented")
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
                    "capabilities": {"tools": {"listChanged": True}},
                }
            elif method == "tools/list":
                result = {"tools": TOOLS}
            elif method == "prompts/list":
                result = {"prompts": []}
            elif method == "resources/list":
                result = {"resources": []}
            elif method == "resources/templates/list":
                result = {"resourceTemplates": []}
            elif method == "tools/call":
                params = request.get("params") or {}
                result = text_result(call_tool(params["name"], params.get("arguments") or {}))
            elif method == "ping":
                result = {}
            elif method == "notifications/initialized":
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
