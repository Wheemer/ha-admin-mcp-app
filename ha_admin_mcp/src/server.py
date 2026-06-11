from __future__ import annotations

import fnmatch
import json
import os
import shutil
import subprocess
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

ADDON_OPTIONS = Path("/data/options.json")
DEFAULT_BACKUP_DIR = Path("/backup/ha-admin-mcp")
MAX_READ_BYTES = 20_000_000
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
        "port": int(os.environ.get("PORT", "8099")),
        "command_timeout_seconds": int(os.environ.get("COMMAND_TIMEOUT_SECONDS", "300")),
    }


OPTIONS = load_options()


def text_result(value: Any) -> dict[str, Any]:
    text = value if isinstance(value, str) else json.dumps(value, indent=2, default=str)
    return {"content": [{"type": "text", "text": text}]}


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


def supervisor_request(method: str, endpoint: str, data: Any | None = None) -> Any:
    token = os.environ.get("SUPERVISOR_TOKEN")
    if not token:
        raise RuntimeError("SUPERVISOR_TOKEN is not available")
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
            return json.loads(payload) if payload else {"status": response.status}
    except urllib.error.HTTPError as err:
        payload = err.read().decode(errors="replace")
        raise RuntimeError(f"Supervisor API {err.code}: {payload}") from err


def ha_request(method: str, endpoint: str, data: Any | None = None) -> Any:
    token = os.environ.get("SUPERVISOR_TOKEN")
    if not token:
        raise RuntimeError("SUPERVISOR_TOKEN is not available")
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
            return json.loads(payload) if payload else {"status": response.status}
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
    tool_schema("restart_core", "Restart Home Assistant Core through Supervisor", {}, []),
    tool_schema("reload_core_config", "Reload Home Assistant core config through REST API", {}, []),
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
    if name == "write_file":
        path = Path(args["path"])
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(args["content"])
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
    if name == "ha_api":
        return ha_request(args.get("method", "GET"), args["endpoint"], args.get("data"))
    if name == "supervisor_api":
        return supervisor_request(args.get("method", "GET"), args["endpoint"], args.get("data"))
    if name == "check_config":
        return supervisor_request("POST", "/core/check")
    if name == "restart_core":
        return supervisor_request("POST", "/core/restart")
    if name == "reload_core_config":
        return ha_request("POST", "/services/homeassistant/reload_core_config")
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
    raise ValueError(f"Unknown tool: {name}")


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
    if "/" in key or "\\" in key or key in {"secrets", "auth"}:
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


class Handler(BaseHTTPRequestHandler):
    server_version = "HAAdminMCP/0.1"

    def do_GET(self) -> None:
        if self.path == "/health":
            self.write_json({"ok": True, "dangerous": True})
            return
        self.send_error(404)

    def do_POST(self) -> None:
        if self.path != "/mcp":
            self.send_error(404)
            return
        if not self.authorized():
            self.write_json({"error": "unauthorized"}, status=401)
            return
        length = int(self.headers.get("Content-Length", "0"))
        request = json.loads(self.rfile.read(length) or b"{}")
        response = self.handle_rpc(request)
        self.write_json(response)

    def authorized(self) -> bool:
        token = OPTIONS.get("admin_token") or ""
        if not token:
            return True
        return self.headers.get("Authorization") == f"Bearer {token}"

    def handle_rpc(self, request: dict[str, Any]) -> dict[str, Any]:
        request_id = request.get("id")
        method = request.get("method")
        try:
            if method == "initialize":
                result = {
                    "protocolVersion": "2024-11-05",
                    "serverInfo": {"name": "ha-admin-mcp", "version": "0.1.0"},
                    "capabilities": {"tools": {}},
                }
            elif method == "tools/list":
                result = {"tools": TOOLS}
            elif method == "tools/call":
                params = request.get("params") or {}
                result = call_tool(params["name"], params.get("arguments") or {})
            elif method in {"ping", "notifications/initialized"}:
                result = {}
            else:
                raise ValueError(f"Unsupported method: {method}")
            return {"jsonrpc": "2.0", "id": request_id, "result": result}
        except Exception as err:
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -32000, "message": str(err)},
            }

    def write_json(self, payload: Any, status: int = 200) -> None:
        data = json.dumps(payload, default=str).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, fmt: str, *args: Any) -> None:
        print(f"[ha-admin-mcp] {self.address_string()} {fmt % args}", flush=True)


def main() -> None:
    host = str(OPTIONS.get("bind_host") or "0.0.0.0")
    port = int(OPTIONS.get("port") or 8099)
    print(
        "[ha-admin-mcp] EXTREMELY DANGEROUS server listening on "
        f"{host}:{port}; installing and starting this app grants admin MCP access",
        flush=True,
    )
    ThreadingHTTPServer((host, port), Handler).serve_forever()


if __name__ == "__main__":
    main()
