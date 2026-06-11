# HA Admin MCP App

## EXTREMELY DANGEROUS

This app gives MCP clients root-level administrative control over your Home Assistant system.

If enabled, an MCP client can read secrets, edit configuration, delete files, run shell commands, call the Supervisor API, restart Home Assistant, modify Lovelace storage, inspect registries, create or restore backups, and break your system so badly that Home Assistant may not boot.

Install this only if you intentionally want a remote automation client such as Codex to have broad administrative control.

## Endpoint

The app exposes a JSON-RPC MCP endpoint:

```text
POST http://HOME_ASSISTANT_HOST:8124/api/mcp
```

If `admin_token` is set, pass it as:

```text
Authorization: Bearer YOUR_TOKEN
```

There is no extra safety checkbox. Installing and starting this app is the explicit danger acceptance.

## Main Tools

- `run_command`
- `read_file`
- `write_file`
- `delete_path`
- `list_dir`
- `stat_path`
- `search_files`
- `ha_api`
- `supervisor_api`
- `check_config`
- `restart_core`
- `reload_core_config`
- `backup_path`
- `list_storage_keys`
- `read_storage_key`
- `search_storage_key`
- `read_lovelace_dashboards`

## Backup Policy

Backups created by this app are written under `/backup/ha-admin-mcp` by default, not inside live `/config` folders.
