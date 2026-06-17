<div align="center">

<img src="icon.png" width="112" alt="HA Admin MCP icon">

# HA Admin MCP App

### Privileged MCP control surface for Home Assistant

[![Validate](https://img.shields.io/github/actions/workflow/status/Wheemer/ha-admin-mcp-app/validate.yml?branch=master&style=for-the-badge&logo=github&logoColor=white&label=VALIDATE&labelColor=555555)](https://github.com/Wheemer/ha-admin-mcp-app/actions/workflows/validate.yml)

</div>

## EXTREMELY DANGEROUS

This app gives MCP clients root-level administrative control over your Home Assistant system.

If enabled, an MCP client can read secrets, edit configuration, delete files, run shell commands, call the Supervisor API, restart Home Assistant, modify Lovelace storage, inspect registries, create or restore backups, and break your system so badly that Home Assistant may not boot.

Install this only if you intentionally want a remote automation client such as Codex to have broad administrative control.

Do not expose this app to the internet. Do not run it on a shared or untrusted Home Assistant instance. Treat access to this endpoint like root access to Home Assistant.

The container includes the same pinned FastMCP runtime used by `homeassistant-ai/ha-mcp` and mirrors its Home Assistant app-mode port and secret-path behavior.

## Installation

[![Open your Home Assistant instance and add this app repository.](https://my.home-assistant.io/badges/supervisor_add_addon_repository.svg)](https://my.home-assistant.io/redirect/supervisor_add_addon_repository/?repository_url=https%3A%2F%2Fgithub.com%2FWheemer%2Fha-admin-mcp-app)

If the button does not work, add this repository manually:

```text
https://github.com/Wheemer/ha-admin-mcp-app
```

Install **HA Admin MCP** from the app store, review the options, then start it manually.

## Endpoint

The app exposes a JSON-RPC MCP endpoint:

```text
POST http://HOME_ASSISTANT_HOST:9583/private_<generated-token>
```

Like `homeassistant-ai/ha-mcp` app mode, this app uses a persisted `secret_path`.
If `secret_path` is empty, the app generates `/private_<22-char-urlsafe-token>` and stores it in `/data/secret_path.txt`.

Standalone FastMCP mode in the upstream repo uses `/mcp`; Home Assistant app mode uses the secret path above.

If `admin_token` is set, pass it as:

```text
Authorization: Bearer YOUR_TOKEN
```

There is no extra safety checkbox. Installing and starting this app is the explicit danger acceptance.

## Main Tool Groups

- Shell and host control: `run_command`, `run_shell`, `ha_cli`, `get_environment`, `batch_call_tools`
- Upstream compatibility and discovery: `get_version`, `search_tools`, `get_entity`, `entity_action`, `list_entities`, `search_entities`, `get_entities_by_area`, `domain_summary`, `system_overview`, `diagnostic_bundle`, `list_automations`, `list_traces`, `get_trace`, `list_trace_contexts`, `get_automation_traces`
- `homeassistant-ai/ha-mcp` compatibility shims: the upstream `ha_*` tool names are exposed and routed through this app's full-access primitives where a direct equivalent exists.
- Filesystem control: `stat_path`, `list_dir`, `read_file`, `read_file_window`, `read_file_lines`, `read_file_base64`, `write_file`, `write_file_base64`, `delete_path`, `search_files`, `glob_paths`, `hash_file`
- Home Assistant APIs: `ha_api`, `supervisor_api`, `http_request`, `call_service`, `get_states`, `get_events`, `get_services`, `get_history`, `render_template`, `fire_event`
- Supervisor/Core operations: `check_config`, `check_reload_readiness`, `check_config_and_reload`, `core_info`, `host_info`, `supervisor_info`, `store_info`, `app_info`, `app_logs`, `app_control`, `restart_core`, `stop_core`, `start_core`, `reload_core_config`, `reload_domain_config`
- Config files, packages, blueprints, templates, recorder config, and secrets: `active_config_index`, `search_active_config`, `list_config_files`, `read_config_file`, `read_config_lines`, `write_config_file`, `patch_config_text`, `ensure_config_block`, `list_packages`, `read_package`, `write_package`, `patch_package_text`, `list_template_configs`, `get_template_config`, `list_blueprints`, `read_blueprint`, `search_blueprints`, `get_recorder_config`, `write_recorder_package`, `list_secrets`, `get_secret`, `set_secret`, `delete_secret`, `search_config`, `tail_log`
- Storage and registries: `list_storage_keys`, `list_storage_keys_filtered`, `read_storage_key`, `read_storage_key_window`, `search_storage_key`, `search_storage_json`, `read_storage_json_path`, `read_storage_json_paths`, `patch_storage_json_path`, `write_storage_key`, `delete_storage_key`, `backup_storage_key`, `search_entity_registry`, `get_entity_registry_entry`, `search_device_registry`, `search_config_entries`, `get_config_entry`, `patch_config_entry`, `search_area_registry`, `search_floor_registry`, `search_label_registry`, `patch_entity_registry_entry`, `patch_device_registry_entry`
- Lovelace dashboards: `live_lovelace_get_config`, `live_lovelace_get_outline`, `live_lovelace_find_cards`, `live_lovelace_get_card`, `live_lovelace_patch_card`, `live_lovelace_save_config`, `live_lovelace_resources`, `read_lovelace_dashboards`, `list_lovelace_dashboards`, `get_lovelace_dashboard`, `get_lovelace_dashboard_outline`, `get_lovelace_view`, `get_lovelace_card`, `find_lovelace_cards`, `patch_lovelace_card`, `patch_lovelace_json_path`, `insert_lovelace_card`, `delete_lovelace_card`, `move_lovelace_card`, `save_lovelace_dashboard`, `delete_lovelace_dashboard`
- Recorder/database: `sqlite_query`, `recorder_get_db_info`, `recorder_purge`, `recorder_purge_entities`, `get_history_range`, `get_statistics`, `get_statistics_range`, `get_error_log`
- Backups: `backup_path`, `list_backups`, `create_backup`, `get_backup_info`, `delete_backup`, `restore_backup`

## Tool Refresh Workflow

Some MCP clients cache the native tool list when they connect. After updating this app, new first-class tool names may not appear in that client's native tool picker until the client reconnects.

Use `list_tools` to read the app's current live tool catalog, then use `call_tool` or `mcp_call_tool` to call any current tool by name:

```json
{
  "name": "update_automation",
  "arguments": {
    "entity_id": "automation.example",
    "config": {},
    "dry_run": true
  }
}
```

The router tool names are intended to stay stable so newly added tools can still be used immediately after the app updates.

## MCP Protocol Surface

The app supports normal MCP discovery and reads for tools, resources, resource templates, prompts, completion, logging level changes, pings, batches, notifications, cursor pagination, and resource subscribe/unsubscribe probes. Useful resources include HA core/supervisor/host info, states, services, events, config files, storage keys, registries, and Lovelace dashboards/views.

`mcp_protocol_status` reports the live protocol methods, negotiated endpoint metadata, supported protocol versions, stable router tools, and parity against the default `homeassistant-ai/ha-mcp` tool names.

## Backup Policy

Backups created by this app are written under `/backup/ha-admin-mcp` by default, not inside live `/config` folders.

## Guardrails

This app is still intentionally dangerous. The guardrails are there to prevent accidental damage while preserving full administrative access when explicitly requested:

- Dashboard UI changes should use `live_lovelace_get_outline`, `live_lovelace_find_cards`, `live_lovelace_get_card`, `live_lovelace_patch_card`, `live_lovelace_save_config`, or the Home Assistant UI path. Storage-backed Lovelace mutation tools return a warning because storage edits are not a reliable proof that the active rendered UI changed.
- Destructive tools advertise MCP annotations where supported by the client.
- High-blast operations such as deleting root/config directories, deleting storage keys, deleting dashboards, stopping Core, and restarting Core require `force: true`.
- Write/delete/dashboard/storage tools support `dry_run` where practical, so clients can inspect the exact target before mutating it.
- Write and patch tools can require an `expected_hash` to avoid overwriting something that changed after it was read.
- `get_target_identity` reports the app, Core, Supervisor, and host identity so clients can confirm which Home Assistant instance is being controlled.
- Mutating operations append JSON lines to `/backup/ha-admin-mcp/audit.log`.
