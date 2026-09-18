# Okta TEA AI Assistant

Ask plain-English questions about your Okta tenant's security posture and get actionable remediation guidance for your Threat Exposure Assessment (TEA) findings, including Terraform, log queries, and admin console steps.

The app runs a local Node.js server that serves a browser-based chat UI and orchestrates a cloud LLM (Anthropic or OpenAI) with a local Okta TEA MCP server. The MCP server calls the Okta Management API, evaluates your tenant's configuration, and returns structured findings that the LLM uses to generate remediation guidance.

---

## Prerequisites

- Node.js 18+
- At least one AI provider key — Anthropic or OpenAI instance (see [Environment variables](#environment-variables) below)

---

## Setup

### 1. Install dependencies

```bash
npm install
```

This installs both the web UI dependencies and the MCP server dependencies (`mcp/`) in one step.

### 2. Create an Okta Native Application

In your Okta Admin Console:

1. Go to **Applications → Create App Integration**
2. Choose **OIDC - OpenID Connect** → **Native Application**
3. Under **General Settings**:
   - App name: `Okta TEA AI Assistant`
   - Grant type: check **Authorization Code** only
   - Sign-in redirect URI: `http://localhost:9876/callback`
   - Controlled access: check **Skip group assignment for now**
4. Save the app. Copy the **Client ID** (there is no client secret for PKCE apps)
5. Go to the app's **Okta API Scopes** tab and grant the scopes for your intended mode:

   **Read-only scopes (required for both dev and prod modes):**
   - `okta.logs.read` — query System Log events (`/api/v1/logs`)
   - `okta.policies.read` — read all policies (session, authentication, password, enrollment)
   - `okta.authenticators.read` — read authenticator settings
   - `okta.apps.read` — look up the Admin Console app by label (required for admin console policy audit)
   - `okta.deviceAssurance.read` — read Device Assurance policies
   - `okta.idps.read` — read Identity Providers (identity proofing and IdP auto-link audit)
   - `okta.features.read` — read org feature flags (ITP, suspicious activity reporting)
   - `okta.securityEventsProviders.read` — read Shared Signals Framework providers (EDR integrations)
   - `okta.behaviors.read` — read Behavior Detection rules
   - `okta.logStreams.read` — read Log Streaming configuration
   - `okta.captchas.read` — read CAPTCHA integrations
   - `okta.authorizationServers.read` — read Authorization Server configuration
   - `okta.roles.read` — read per-user role assignment records (`/api/v1/users/{id}/roles`) for super admin audit
   - `okta.users.read` — enumerate all users (`/api/v1/users`) for super admin audit
   - `okta.apiTokens.read` — read API token metadata: count, zone restriction status, and expiry

   **Write scopes (dev mode only — omit for production tenants):**
   - `okta.threatInsights.manage` — read and write ThreatInsight configuration
   - `okta.networkZones.manage` — read and write network zones
   - `okta.policies.manage` — read and write password and session policies
   - `okta.authenticators.manage` — read and write authenticator settings (Okta Verify number challenge)
   - `okta.orgs.manage` — read and write org-level security settings
   - `okta.apps.manage` — read and update app OAuth grant types (OAuth grant audit and remediation)
   - `okta.deviceAssurance.manage` — create/update Device Assurance policies
   - `okta.features.manage` — enable org features (ITP Universal Logout, suspicious activity reporting)

6. Assign yourself to this application.

### 3. Configure environment variables

cp .env.example .env

```env
# =============================================================================
# AI providers — configure at least one
# =============================================================================

# Anthropic (Claude)
ANTHROPIC_API_KEY=sk-ant-...
# Optional: override the default model (default: claude-sonnet-4-6)
ANTHROPIC_MODEL=claude-sonnet-4-6

# OpenAI
OPENAI_API_KEY=sk-...
# Optional: override the default model (default: gpt-4o)
OPENAI_MODEL=gpt-4o


# =============================================================================
# Okta credentials - configure at least one (DEV or PROD)
# =============================================================================

# dev / prod mode both work with the same .env.
# Use mode-specific keys and the correct one will be selected at startup.

# Development tenant
OKTA_TEA_DEV_DOMAIN=dev-12345678.okta.com
OKTA_TEA_DEV_CLIENT_ID=0oa...

# Production tenant
OKTA_TEA_PROD_DOMAIN=mycompany.okta.com
OKTA_TEA_PROD_CLIENT_ID=0oa...


# =============================================================================
# Server
# =============================================================================

# Path to the MCP server entry point
# Defaults to ./mcp/src/index.js (relative to the repo root)
# MCP_SERVER_PATH=/absolute/path/to/mcp/src/index.js

# Port for the web UI (default: 3000)
PORT=3000

# Show raw tool call input/result cards in the chat UI (default: false)
# Set to true to see the JSON API responses as tools run.
DEBUG=false
```

---

## Running the server

### Offline mode (no Okta tenant required)

No `.env` Okta credentials needed. Remediation guidance — Terraform HCL, Admin Console steps, log queries, and Change Risk &amp; Blast Radius assessments — is fully available. Live tenant verification and automatic fixes are not available.

```bash
npm start          # same as npm run offline
npm run offline
```

This is the best starting point if you want to explore the tool's guidance or review a TEA report without connecting to a tenant.

### Development mode

Loads `OKTA_TEA_DEV_DOMAIN` / `OKTA_TEA_DEV_CLIENT_ID` from your `.env`:

```bash
npm run dev
```

### Production mode

Loads `OKTA_TEA_PROD_DOMAIN` / `OKTA_TEA_PROD_CLIENT_ID` from your `.env`:

```bash
npm run prod
```

Production mode is **read-only**. Write operations (applying fixes, creating policies, updating rules) are disabled at every layer: the AI is never offered write tools, the MCP handlers reject write calls, and the login flow only requests read scopes — so the issued access token cannot authorize mutations regardless of anything else. The Okta app for your production tenant only needs the read-only scopes listed above.

Expected output (dev/prod modes):

```
MCP connected. Tools available: okta_login, okta_get_threatinsight_config, ...

Okta Security Chat → http://localhost:3000
Mode: DEV | Okta domain: dev-12345678.okta.com
```

Open **http://localhost:3000** in your browser.

### AI provider selection

If multiple provider keys are set, the UI shows a provider picker. Priority order when no provider is explicitly selected: **Anthropic → OpenAI **.

---

## What you can do

| Feature | Dev (online + write) | Prod (online, read-only) | Offline |
|---|---|---|---|
| **Chat** | Claude inspects live tenant | Claude inspects live tenant | Claude returns static remediation guidance |
| **Example prompts** | Click any suggestion card to auto-send | Same | Same |
| **TEA report review** | Upload HTML/PDF → Claude verifies each finding against your tenant | Same | Upload HTML/PDF → Claude lists findings + presents remediation guidance |
| **Terraform snippets** | Generated from your live tenant config | Same | Generated from defaults; replace placeholder IDs before applying |
| **Admin Console steps** | Available | Available | Available |
| **Log queries** | Available | Available | Available |
| **Risk & blast radius** | Available | Available | Available |
| **Apply fix automatically** | Available (requires confirmation) | Disabled | Disabled |
| **New chat** | Click "New chat" in the header to reset | Same | Same |

### Available security checks

| Tool | What it checks |
|---|---|
| ThreatInsight | Detection mode (none/audit/block), exclusion zones, 7-day volume |
| Network zones | IP and country blocklists, Tor/proxy blocklists |
| Password policies | Length, brute force protection, lockout, change notifications |
| Session policies | MFA requirements, session lifetime, idle timeout (vs NIST 720-min) |
| Authenticators | Five checks: WebAuthn/FIDO2 and FastPass present (phishing-resistant, AiTM-immune), Number Challenge enabled (push bombing), SMS/Phone absent (SIM swap risk), Security Questions absent (spearphishing risk) |
| Security General | Unknown device blocking, suspicious activity email reporting |
| Security notification emails | Suspicious activity, new device, password change, factor enrollment emails |
| Admin Console sign-on policy | MFA enforcement, re-authentication cap for admin sessions |
| OAuth grant types | Apps using deprecated Password or Implicit grants (RFC 9700) |
| Super admins / admin roles | Count of users with standing SUPER_ADMIN role; service accounts with super admin; zero standing privileges guidance |
| API tokens | Count of active SSWS tokens; flags unrestricted tokens (no zone) and tokens with no expiry; recommends OAuth2 migration |

### Example questions

- *Is ThreatInsight enabled and blocking?*
- *Check my network zone configurations.*
- *Do my password policies meet security standards?*
- *Are my GSP session lifetimes & idle timeouts within NIST guidelines?*
- *Are high assurance authenticators enabled?*
- *Is my Admin Console sign-on policy secure?*
- *Are security notification emails configured?*
- *Do any apps use deprecated OAuth grant types (Password or Implicit)?*

---

## Architecture

```
Browser (index.html)
    │  POST /api/chat       (SSE stream)
    │  POST /api/tea-review (SSE stream)
    ▼
server.js  (Express)
    │  Anthropic SDK  →  claude-sonnet-4-6  (adaptive thinking)
    │  OpenAI SDK     →  gpt-4o  (or any compatible model)
    │  OpenAI SDK     →  Ollama  (local, via baseURL)
    │  @modelcontextprotocol/sdk  →  StdioClientTransport
    ▼
mcp/src/index.js
    │  Okta REST API
```

The server runs an agentic loop: the AI calls MCP tools, results are streamed back to the browser in real time via Server-Sent Events. Terraform HCL and System Log filter strings are extracted from tool results *before* the model sees them and rendered directly as artifact cards — preventing reformatting.

---

## API endpoints

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/chat` | Send a chat message; streams SSE events |
| `POST` | `/api/tea-review` | Upload or reference a TEA report; streams SSE events |
| `POST` | `/api/clear` | Reset conversation history |
| `GET` | `/api/status` | Returns MCP connection status and available tool names |

---

## Troubleshooting

**`MCP server failed to start`** — The web UI still loads but tool calls will fail. Check that `MCP_SERVER_PATH` points to the correct file (default: `./mcp/src/index.js`) and that `mcp/` dependencies are installed.

**`ANTHROPIC_API_KEY is not set`** — Add your key to `.env` and restart the server.

**Status badge shows "MCP offline"** — The MCP server process exited. Check the terminal for error output from `server.js`.

**Tool returns `403 Forbidden`** — The Okta app used for authentication is missing API scope grants. The server console will print a specific hint when this happens. To fix:

1. In the Okta Admin Console go to **Applications → Applications → [Your App] → Okta API Scopes**
2. Grant the missing scope (e.g. `okta.apps.read` for the OAuth grants audit)
3. Run `okta_login` again to get a new access token with the updated scopes

After a successful login, the server console prints the full list of granted scopes and flags any that are missing — useful for diagnosing which tool will fail before you try it.

> **Note:** In `npm run prod`, the `*.manage` scopes are intentionally absent from the token. The console will confirm _"Write scopes intentionally omitted in production mode"_ rather than warning about missing scopes. This is expected — production mode is read-only by design and the Okta app for your production tenant only needs the read scopes.

**Tool returns `401 Unauthorized`** — The stored access token is expired or missing. Run `okta_login` to re-authenticate.

**Terraform output shows `<POLICY_ID>` or `<RULE_ID>` placeholders** — You are running in offline mode. The HCL structure is correct but IDs cannot be populated without a live tenant. Replace the placeholder values with your actual Okta resource IDs before running `terraform apply`. Switch to `npm run dev` or `npm run prod` to get tenant-specific IDs automatically.


This project is licensed under the Apache License 2.0. See the LICENSE file for more info.