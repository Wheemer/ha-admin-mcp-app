<div align="center">

<img src="ha_admin_mcp/icon.png" width="112" alt="HA Admin MCP icon">

# HA Admin MCP App

### Privileged MCP control surface for Home Assistant

[![Validate](https://img.shields.io/github/actions/workflow/status/Wheemer/ha-admin-mcp-app/validate.yml?branch=master&style=for-the-badge&logo=github&logoColor=white&label=VALIDATE&labelColor=555555)](https://github.com/Wheemer/ha-admin-mcp-app/actions/workflows/validate.yml)

</div>

> EXTREMELY DANGEROUS Home Assistant app that exposes broad MCP control over your Home Assistant instance.

This is not a normal Home Assistant convenience app. It is a privileged MCP server intended for a trusted local automation client such as Codex. If you install and start it, you are intentionally giving that client administrative control over Home Assistant.

## Danger

Do not install this unless you understand and accept the risk.

This app can expose tools that:

- read secrets and private configuration
- edit or delete files under Home Assistant paths
- run shell commands from the app container
- call Home Assistant and Supervisor APIs
- restart or stop Home Assistant Core
- edit registries, packages, automations, scripts, scenes, dashboards, and storage keys
- create, delete, or restore backups
- break your Home Assistant install badly enough that it may not boot

There is no safety checkbox. Installing and starting the app is the warning.

## Why this exists

This repository is for direct administrative MCP access to a Home Assistant instance. It is intentionally powerful so an MCP client can inspect live state, read active config, run config checks, reload services, inspect traces, query recorder data, and perform targeted repairs without constantly falling back to SSH.

The container includes the same pinned FastMCP runtime used by `homeassistant-ai/ha-mcp` and mirrors its Home Assistant app-mode port and secret-path behavior.

It is not meant for shared servers, untrusted networks, public exposure, or casual experimentation.

## Installation

**Via My Home Assistant:**

[![Open your Home Assistant instance and add this app repository.](https://my.home-assistant.io/badges/supervisor_add_addon_repository.svg)](https://my.home-assistant.io/redirect/supervisor_add_addon_repository/?repository_url=https%3A%2F%2Fgithub.com%2FWheemer%2Fha-admin-mcp-app)

After adding the repository, install **HA Admin MCP** from the app store, review the options, then start it manually.

**Manual:**

Add this repository to Home Assistant Supervisor as an app repository:

```text
https://github.com/Wheemer/ha-admin-mcp-app
```

Install **HA Admin MCP** from the repository, review the options, then start it manually.

Default endpoint:

```text
POST http://HOME_ASSISTANT_HOST:9583/private_<generated-token>
```

Like `homeassistant-ai/ha-mcp` app mode, this app uses a persisted `secret_path`.
If `secret_path` is empty, the app generates `/private_<22-char-urlsafe-token>` and stores it in `/data/secret_path.txt`.

Standalone FastMCP mode in the upstream repo uses `/mcp`; Home Assistant app mode uses the secret path above.

If `admin_token` is configured, send it as:

```text
Authorization: Bearer YOUR_TOKEN
```

## Configuration

```yaml
admin_token: ""
bind_host: 0.0.0.0
secret_path: ""
command_timeout_seconds: 300
```

- `admin_token`: optional bearer token for MCP requests. Leaving this empty means no app-level token is required.
- `bind_host`: interface to bind. The default listens on all interfaces available to the app.
- `secret_path`: optional MCP path override. Leave empty to auto-generate and persist an upstream-style `/private_...` path.
- `command_timeout_seconds`: default timeout for command execution tools.

## Backup Policy

Backups created by this app are written under:

```text
/backup/ha-admin-mcp
```

They are not kept in live `/config` folders.

## Tool Refresh Workflow

Some MCP clients cache the native tool list when they connect. After updating this app, new first-class tool names may not appear in that client's native tool picker until the client reconnects.

To avoid relaunching the client for every app update, use the stable router tools:

- `list_tools`: shows the app's current live tool catalog
- `call_tool`: calls any current tool by name with an `arguments` object
- `mcp_call_tool`: alias for `call_tool`

Those router names are intended to stay stable so newly added tools can still be used immediately after the app updates.

## Protocol Surface

The app supports the expected MCP server avenues for Codex-style HTTP clients: initialize, tools list/call, resources list/read/templates, prompts list/get, completion, logging level changes, ping, notifications, cursor pagination, and resource subscribe/unsubscribe probes. `mcp_protocol_status` reports the live protocol method coverage and upstream `homeassistant-ai/ha-mcp` tool-name parity.

## Notes

Dashboard UI changes should prefer the live Lovelace tools or the Home Assistant UI path. Storage-backed Lovelace edits are intentionally warned against because changing `.storage` is not good proof that the rendered UI changed.

For the full tool list and implementation details, see [ha_admin_mcp/README.md](ha_admin_mcp/README.md).
