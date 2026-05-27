# Redash MCP Server

Model Context Protocol (MCP) server for integrating Redash with AI assistants like Claude.

<a href="https://glama.ai/mcp/servers/j9bl90s3tw">
  <img width="380" height="200" src="https://glama.ai/mcp/servers/j9bl90s3tw/badge" alt="Redash Server MCP server" />
</a>

## Features

- Connect to Redash instances using **OIDC + PKCE browser login** (no long-lived API keys)
- List available queries and dashboards as resources
- Execute queries and retrieve results
- Execute saved parameterized queries with typed values and saved defaults
- Create and manage queries (create, update, archive)
- Manage query parameters, dashboard parameters, and widget parameter mappings
- Inspect and update dashboard widget layouts and grid positions
- List data sources for query creation
- Get dashboard details and visualizations
- Update chart visualization options with Redash chart-specific settings

## Authentication model

This server **no longer accepts a Redash API key**. All API requests are
authenticated with a short-lived OIDC access token obtained from your IdP
(Authentik, Auth0, Keycloak, Okta, …) using the **Authorization Code + PKCE**
flow.

Why this change:

- The MCP server runs as a stdio subprocess of Claude Desktop / your IDE; it
  shouldn't hold a long-lived credential that grants full Redash API access.
- OIDC tokens are bound to a real user and expire quickly. Revoking a user at
  the IdP immediately revokes this MCP server's access.
- Redash-side support for verifying these tokens is documented in
  [`Buzzvil/redash-custom`](https://github.com/Buzzvil/redash-custom)
  (`docs/oidc-pkce-api-access.md`).

Login is a separate one-time CLI command. The MCP server itself never opens
a browser — instead, it reads the cached tokens left behind by
`redash-mcp login` and refreshes them silently when they near expiry.

## Prerequisites

- Node.js (v18 or later)
- npm or yarn
- A Redash instance with OIDC Bearer API auth enabled (see
  [`Buzzvil/redash-custom/docs/oidc-pkce-api-access.md`](https://github.com/Buzzvil/redash-custom/blob/main/docs/oidc-pkce-api-access.md))
- An OIDC client registered as **public** with **PKCE required** and a
  loopback redirect URI like `http://127.0.0.1:*/callback`

## Environment Variables

| Variable | Required | Purpose |
| --- | --- | --- |
| `REDASH_URL` | yes | Your Redash instance URL (e.g. `https://redash.example.com`). |
| `REDASH_OIDC_ISSUER` | yes | OIDC issuer URL. Discovery hits `<issuer>/.well-known/openid-configuration`. |
| `REDASH_OIDC_CLIENT_ID` | yes | Public OIDC client identifier. |
| `REDASH_OIDC_AUDIENCE` | no | Override the `audience` PKCE parameter. Defaults to `REDASH_OIDC_CLIENT_ID`. |
| `REDASH_OIDC_SCOPES` | no | Scopes to request. Default: `openid email offline_access`. Drop `offline_access` only if your IdP doesn't issue refresh tokens. |
| `REDASH_OIDC_TOKEN_CACHE_PATH` | no | Override the path of the token cache file. Default: `$XDG_STATE_HOME/redash-mcp/tokens.json` (or `~/.local/state/redash-mcp/tokens.json`). |
| `REDASH_TIMEOUT` | no | API request timeout in ms (default `30000`). |
| `REDASH_MAX_RESULTS` | no | Max results to return (default `1000`). |
| `REDASH_EXTRA_HEADERS` | no | Extra HTTP headers as JSON object or `k=v;k2=v2` pairs. The `Authorization` header is reserved. |
| `REDASH_SOCKS_PROXY` | no | SOCKS proxy URL (e.g. `socks5h://localhost:1080`). |

## Installation

1. Clone this repository:
   ```bash
   git clone https://github.com/Buzzvil/redash-mcp.git
   cd redash-mcp
   ```
2. Install dependencies:
   ```bash
   npm install
   ```
3. Create a `.env` file with your Redash + OIDC configuration:
   ```env
   REDASH_URL=https://redash-dev.buzzvil.com
   REDASH_OIDC_ISSUER=https://authentik.buzzvil.com/application/o/redash-cli/
   REDASH_OIDC_CLIENT_ID=redash-cli
   REDASH_OIDC_AUDIENCE=redash-cli
   # Optional: Cloudflare Access (or other gateway) headers
   # REDASH_EXTRA_HEADERS='{"CF-Access-Client-Id":"<client_id>","CF-Access-Client-Secret":"<client_secret>"}'
   ```
4. Build the project:
   ```bash
   npm run build
   ```
5. **Log in once** — opens your browser, completes PKCE, writes tokens to the cache:
   ```bash
   npm start -- login
   # or, after publish: npx @suthio/redash-mcp login
   ```
6. Start the server:
   ```bash
   npm start
   ```

## Subcommands

```
redash-mcp [serve]    Start the MCP server (default). Requires a prior `login`.
redash-mcp login      Run the OIDC PKCE browser flow and cache tokens.
redash-mcp logout     Clear the cached tokens.
redash-mcp status     Show cached token info (email, expiry).
redash-mcp help       Show help.
```

## Usage with Claude for Desktop

To use this MCP server with Claude for Desktop, configure it in your Claude for Desktop configuration file:

**macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
**Windows**: `%APPDATA%\Claude\claude_desktop_config.json`

**Step 1.** Run `redash-mcp login` once in your terminal to cache the tokens.

**Step 2.** Add the following configuration (edit paths as needed):

```json
{
  "mcpServers": {
    "redash": {
      "command": "npx",
      "args": ["-y", "@suthio/redash-mcp"],
      "env": {
        "REDASH_URL": "https://redash.example.com",
        "REDASH_OIDC_ISSUER": "https://authentik.example.com/application/o/redash-cli/",
        "REDASH_OIDC_CLIENT_ID": "redash-cli"
      }
    }
  }
}
```

When the cached access token expires, the server uses the cached
`refresh_token` automatically. If the refresh token itself expires (e.g. 7
days later), run `redash-mcp login` again.

## Available Tools

### Query Management
- `list-queries`: List all available queries in Redash
- `get-query`: Get details of a specific query
- `create-query`: Create a new query in Redash
- `update-query`: Update an existing query in Redash
- `get-query-parameters`: Inspect saved query parameter definitions
- `update-query-parameters`: Update saved query parameter definitions
- `archive-query`: Archive (soft-delete) a query
- `list-data-sources`: List all available data sources

### Query Execution
- `execute-query`: Execute a query and return results, with optional `maxAge`
- `execute-parameterized-query`: Execute a saved parameterized query with type-aware value coercion, saved defaults, and optional `maxAge`
- `execute-adhoc-query`: Execute an ad-hoc query without saving it to Redash
- `get-query-results-csv`: Get query results in CSV format (supports optional refresh for latest data)

### Dashboard Management
- `list-dashboards`: List all available dashboards
- `get-dashboard`: Get dashboard details and visualizations
- `get-dashboard-layout`: Inspect widget positions, sizes, and visibility on a dashboard
- `get-visualization`: Get details of a specific visualization
- `get-dashboard-parameters`: Inspect dashboard parameter values and widget mappings
- `update-dashboard-parameters`: Update dashboard parameter values and order
- `update-dashboard-layout`: Move or resize multiple widgets in one call
- `update-widget-layout`: Move or resize a single widget
- `get-widget-parameter-mappings`: Inspect a widget's parameter mappings
- `update-widget-parameter-mappings`: Update a widget's parameter mappings

### Visualization Management
- `create-visualization`: Create a new visualization for a query
- `update-visualization`: Update an existing visualization
- `update-chart-visualization`: Patch chart-specific options like `globalSeriesType`, `columnMapping`, `seriesOptions`, `legend`, and axis settings
- `delete-visualization`: Delete a visualization

## Development

Run in development mode:
```bash
npm run dev
```

## Testing

### Unit Tests

```bash
npm test
```

### E2E Tests

```bash
npm run e2e:test
```

E2E tests need a valid cached OIDC token; point the harness at the cache via
`REDASH_OIDC_TOKEN_CACHE_PATH` (and the matching `REDASH_OIDC_ISSUER` /
`REDASH_OIDC_CLIENT_ID` used to mint it).

### Manual Testing

```bash
npm run inspector
```

## Migration from v0.0.x (API key) to v0.1.x (OIDC PKCE)

Breaking changes:

- `REDASH_API_KEY` is no longer read. The Authorization header is generated
  per-request from a cached OIDC access token.
- The server now requires `REDASH_OIDC_ISSUER` and `REDASH_OIDC_CLIENT_ID`.
- The package now exposes subcommands (`login`, `logout`, `status`, `serve`).
  Existing wrappers that just run `redash-mcp` continue to work and default
  to `serve`.

To migrate:

1. Configure the OIDC client on the IdP side (public, PKCE-required, loopback
   redirect URI). For Buzzvil's setup see
   [`buzz-k8s-resources/argo-cd/buzzvil-eks-ops/manifests/authentik/blueprint-redash-cli.yaml`](https://github.com/Buzzvil/buzz-k8s-resources).
2. Drop `REDASH_API_KEY` from your `.env` / Claude Desktop config.
3. Add `REDASH_OIDC_ISSUER` and `REDASH_OIDC_CLIENT_ID`.
4. Run `redash-mcp login` once.

## Version History

- v0.1.0: **Breaking** — replace API key auth with OIDC PKCE browser login.
- v0.0.13: parameterized query execution, dashboard layout tools, chart visualization config.
- v0.0.12: Zod-driven tool schemas.
- v0.0.11: dashboard by-slug lookup.
- v1.0.0: Initial release (legacy numbering).

## License

MIT
