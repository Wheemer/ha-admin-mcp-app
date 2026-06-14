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

## Main Tool Groups

- Shell and host control: `run_command`, `run_shell`, `ha_cli`, `get_environment`, `batch_call_tools`
- Upstream compatibility and discovery: `get_version`, `search_tools`, `get_entity`, `entity_action`, `list_entities`, `search_entities`, `get_entities_by_area`, `domain_summary`, `system_overview`, `diagnostic_bundle`, `list_automations`
- `homeassistant-ai/ha-mcp` compatibility shims: the upstream `ha_*` tool names are exposed and routed through this app's full-access primitives where a direct equivalent exists.
- Filesystem control: `stat_path`, `list_dir`, `read_file`, `read_file_window`, `read_file_lines`, `read_file_base64`, `write_file`, `write_file_base64`, `delete_path`, `search_files`, `glob_paths`, `hash_file`
- Home Assistant APIs: `ha_api`, `supervisor_api`, `http_request`, `call_service`, `get_states`, `get_events`, `get_services`, `get_history`, `render_template`, `fire_event`
- Supervisor/Core operations: `check_config`, `check_reload_readiness`, `check_config_and_reload`, `core_info`, `host_info`, `supervisor_info`, `store_info`, `app_info`, `app_logs`, `app_control`, `restart_core`, `stop_core`, `start_core`, `reload_core_config`, `reload_domain_config`
- Config files, packages, and secrets: `list_config_files`, `read_config_file`, `read_config_lines`, `write_config_file`, `patch_config_text`, `ensure_config_block`, `list_packages`, `read_package`, `write_package`, `patch_package_text`, `list_secrets`, `get_secret`, `set_secret`, `delete_secret`, `search_config`, `tail_log`
- Storage and registries: `list_storage_keys`, `list_storage_keys_filtered`, `read_storage_key`, `read_storage_key_window`, `search_storage_key`, `search_storage_json`, `read_storage_json_path`, `read_storage_json_paths`, `patch_storage_json_path`, `write_storage_key`, `delete_storage_key`, `backup_storage_key`, `search_entity_registry`, `get_entity_registry_entry`, `search_device_registry`, `search_config_entries`, `search_area_registry`, `search_floor_registry`, `search_label_registry`, `patch_entity_registry_entry`, `patch_device_registry_entry`
- Lovelace dashboards: `read_lovelace_dashboards`, `list_lovelace_dashboards`, `get_lovelace_dashboard`, `get_lovelace_dashboard_outline`, `get_lovelace_view`, `get_lovelace_card`, `find_lovelace_cards`, `patch_lovelace_card`, `patch_lovelace_json_path`, `insert_lovelace_card`, `delete_lovelace_card`, `move_lovelace_card`, `save_lovelace_dashboard`, `delete_lovelace_dashboard`
- Recorder/database: `sqlite_query`, `recorder_get_db_info`, `recorder_purge`, `recorder_purge_entities`, `get_history_range`, `get_statistics`, `get_statistics_range`, `get_error_log`
- Backups: `backup_path`, `list_backups`, `create_backup`, `get_backup_info`, `delete_backup`, `restore_backup`

## MCP Protocol Surface

The app supports normal MCP discovery and reads for tools, resources, resource templates, prompts, completion, logging level changes, pings, batches, and notifications. Useful resources include HA core/supervisor/host info, states, services, events, config files, storage keys, registries, and Lovelace dashboards/views.

## Backup Policy

Backups created by this app are written under `/backup/ha-admin-mcp` by default, not inside live `/config` folders.

## Guardrails

This app is still intentionally dangerous. The guardrails are there to prevent accidental damage while preserving full administrative access when explicitly requested:

- Destructive tools advertise MCP annotations where supported by the client.
- High-blast operations such as deleting root/config directories, deleting storage keys, deleting dashboards, stopping Core, and restarting Core require `force: true`.
- Write/delete/dashboard/storage tools support `dry_run` where practical, so clients can inspect the exact target before mutating it.
- Write and patch tools can require an `expected_hash` to avoid overwriting something that changed after it was read.
- `get_target_identity` reports the app, Core, Supervisor, and host identity so clients can confirm which Home Assistant instance is being controlled.
- Mutating operations append JSON lines to `/backup/ha-admin-mcp/audit.log`.
