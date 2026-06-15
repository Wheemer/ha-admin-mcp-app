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
POST http://HOME_ASSISTANT_HOST:8124/api/mcp
```

The app also accepts the standard upstream-compatible path:

```text
POST http://HOME_ASSISTANT_HOST:8124/mcp
```

If `admin_token` is configured, send it as:

```text
Authorization: Bearer YOUR_TOKEN
```

## Configuration

```yaml
admin_token: ""
bind_host: 0.0.0.0
port: 8124
command_timeout_seconds: 300
```

- `admin_token`: optional bearer token for MCP requests. Leaving this empty means no app-level token is required.
- `bind_host`: interface to bind. The default listens on all interfaces available to the app.
- `port`: host port for the MCP endpoint.
- `command_timeout_seconds`: default timeout for command execution tools.

## Backup Policy

Backups created by this app are written under:

```text
/backup/ha-admin-mcp
```

They are not kept in live `/config` folders.

## Notes

Dashboard UI changes should prefer the live Lovelace tools or the Home Assistant UI path. Storage-backed Lovelace edits are intentionally warned against because changing `.storage` is not good proof that the rendered UI changed.

For the full tool list and implementation details, see [ha_admin_mcp/README.md](ha_admin_mcp/README.md).
