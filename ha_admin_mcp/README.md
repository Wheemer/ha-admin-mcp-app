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

- Shell and host control: `run_command`, `run_shell`, `get_environment`
- Upstream compatibility and discovery: `get_version`, `search_tools`, `get_entity`, `entity_action`, `list_entities`, `search_entities`, `get_entities_by_area`, `domain_summary`, `system_overview`, `list_automations`
- `homeassistant-ai/ha-mcp` compatibility shims: the upstream `ha_*` tool names are exposed and routed through this app's full-access primitives where a direct equivalent exists.
- Filesystem control: `stat_path`, `list_dir`, `read_file`, `read_file_base64`, `write_file`, `write_file_base64`, `delete_path`, `search_files`, `glob_paths`, `hash_file`
- Home Assistant APIs: `ha_api`, `supervisor_api`, `http_request`, `call_service`, `get_states`, `get_events`, `get_services`, `get_history`, `render_template`, `fire_event`
- Supervisor/Core operations: `check_config`, `check_reload_readiness`, `core_info`, `host_info`, `supervisor_info`, `store_info`, `app_info`, `app_logs`, `app_control`, `restart_core`, `stop_core`, `start_core`, `reload_core_config`, `reload_domain_config`
- Config files: `list_config_files`, `read_config_file`, `write_config_file`, `search_config`, `tail_log`
- Storage and registries: `list_storage_keys`, `list_storage_keys_filtered`, `read_storage_key`, `search_storage_key`, `search_storage_json`, `read_storage_json_path`, `patch_storage_json_path`, `write_storage_key`, `delete_storage_key`, `backup_storage_key`, `search_entity_registry`, `get_entity_registry_entry`, `search_device_registry`, `search_config_entries`, `search_area_registry`, `search_floor_registry`, `search_label_registry`
- Lovelace dashboards: `read_lovelace_dashboards`, `list_lovelace_dashboards`, `get_lovelace_dashboard`, `get_lovelace_view`, `get_lovelace_card`, `find_lovelace_cards`, `patch_lovelace_card`, `save_lovelace_dashboard`, `delete_lovelace_dashboard`
- Recorder/database: `sqlite_query`, `get_history_range`, `get_statistics`, `get_statistics_range`, `get_error_log`
- Backups: `backup_path`

## MCP Protocol Surface

The app supports normal MCP discovery and reads for tools, resources, resource templates, prompts, completion, logging level changes, pings, batches, and notifications. Useful resources include HA core/supervisor/host info, states, services, events, config files, storage keys, registries, and Lovelace dashboards/views.

## Backup Policy

Backups created by this app are written under `/backup/ha-admin-mcp` by default, not inside live `/config` folders.
