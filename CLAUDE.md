# CLAUDE.md — okta-tea-ai-assistant

## What this project is

An MCP server that audits Okta tenant security configurations against the **Okta TEA (Tenant Evaluation Assessment)** findings and returns structured remediation guidance. The server exposes tools that call the Okta Management API, evaluate tenant state, and return findings with Terraform, log queries, and admin console steps.

## Project layout

```
mcp/src/
  index.js            — registers all tools on the McpServer instance
  auth/
    okta-client.js    — createOktaClient() — authenticated axios instance
    pkce.js           — PKCE auth flow
    token-store.js    — token persistence
  tools/
    resolver-utils.js — buildMcpOk() / buildMcpError() / buildMcpOffline() + remediation contract
    *.js              — one file per security domain
```

## Adding a new tool

1. Create `mcp/src/tools/<domain>.js` following the pattern below.
2. Export `register<Domain>Tools(server)`.
3. Import and call it in `mcp/src/index.js`.

### Tool file pattern

Every tool file should have these named builder functions:

```js
function build<Domain>Payload(params)        // builds the Okta API request body
function build<Domain>Terraform()            // returns HCL string
function build<Domain>LogQueries()           // returns logQueries array (see below)
function build<Domain>AdminSteps()           // returns string[]
function build<Domain>RiskAssessment()       // returns Change Risk & Blast Radius object (see Remediation contract)
function register<Domain>Tools(server)       // wires tools to the McpServer
```

Tools return via `buildMcpOk(payload)`, `buildMcpError(err)`, or `buildMcpOffline(payload)` from `resolver-utils.js`.

### Remediation contract

Every diagnostic tool must include a `remediation` key:

```js
remediation: {
  terraform:         string | null,   // ready-to-apply HCL
  logQueries:        array  | null,   // see Log Queries section below
  adminConsoleSteps: array  | null,   // string[] of manual steps
  riskAssessment:    object | null,   // Change Risk & Blast Radius — see shape below
}
```

The client automatically extracts `terraform` and `logQueries` and emits them as SSE artifact events — Claude never reformats them. This prevents hallucination of exact technical content (HCL syntax, filter strings, attribute names).

### Change Risk & Blast Radius — `riskAssessment` shape

Every `build<Domain>RiskAssessment()` must return this object (the UI renders it under a **## Change Risk & Blast Radius** heading):

```js
{
  teaSeverity: 'INFO' | 'LOW' | 'MODERATE' | 'HIGH',  // TEA validator security_impact — severity of NOT fixing this
  changeRisk:  'INFO' | 'LOW' | 'MODERATE' | 'HIGH',  // risk of applying the fix — independent of teaSeverity
  summary:             string,    // why this finding matters
  preChangeChecks:     string[],  // things to verify BEFORE making the change
  blastRadius:         string,    // what could break and who is affected
  rolloutSteps:        string[],  // safe rollout sequence (renamed from recommendedOrder)
  postChangeMonitoring: {         // what to watch AFTER making the change
    description: string,
    logQueries:  Array<{ description, filter, timeWindow, note }>,
  },
  rollback:            string,    // how to undo if something breaks
}
```

`teaSeverity` reflects the TEA generator's `security_impact` for the corresponding validator. `changeRisk` reflects how disruptive it is to apply the fix — these are independent. A finding can be HIGH severity to leave unfixed (e.g. ThreatInsight) but LOW change risk to fix (enable a toggle, no user impact).

## Offline mode

The app supports an offline mode (`npm run offline` / `npm start`) where no Okta tenant connection exists. Tools must still work in offline mode — they just skip the live API call and return static remediation content instead.

### How offline mode is signalled

`server.js` sets `process.env.OFFLINE_MODE=true` before spawning the MCP subprocess. This env var propagates automatically via `...process.env` in the subprocess spawn options.

### Required convention for every new tool handler

**Every** `server.tool(...)` handler must check `OFFLINE_MODE` as its **first statement**, before any `try/catch` or `createOktaClient()` call.

**Read / diagnostic tools** — return full static remediation using the domain's builder functions:

```js
async (params) => {
  if (process.env.OFFLINE_MODE === 'true') {
    return buildMcpOffline({
      remediation: {
        terraform:         build<Domain>Terraform(/* safe defaults */),
        logQueries:        build<Domain>LogQueries(),
        adminConsoleSteps: build<Domain>AdminSteps(),
        riskAssessment:    build<Domain>RiskAssessment(),
      },
    });
  }
  try {
    const client = await createOktaClient();
    // ... live logic
  } catch (err) {
    return buildMcpError(err);
  }
},
```

**Write / mutation tools** — return a disabled message; do not call any Okta API:

```js
async (params) => {
  if (process.env.OFFLINE_MODE === 'true') {
    return buildMcpOffline({ skipped: true, message: 'Write operations are not available in offline mode.' });
  }
  try {
    const client = await createOktaClient();
    // ... write logic
  } catch (err) {
    return buildMcpError(err);
  }
},
```

### `buildMcpOffline(payload)`

Defined in `resolver-utils.js`. Wraps the payload in the standard MCP content envelope with `ok: true, offlineMode: true, liveData: null` always present. The UI and system prompts key off `offlineMode: true` to suppress live-check markers and show remediation-only output.

### Builder function defaults for offline mode

Builder functions are pure — they take configuration values and return strings/arrays. In offline mode, call them with placeholder objects that produce well-formed but clearly template output:

```js
// Typical safe defaults
{ id: '<POLICY_ID>', name: 'Default Policy', status: 'ACTIVE', settings: {} }
{ id: '<RULE_ID>',   name: 'Default Rule',   actions: {} }
{ id: '<AUTHENTICATOR_ID>', settings: {} }
```

For builders that accept live zone arrays or app lists, pass `[]` — they will produce a "no entries found" or template-only result, which is correct for offline mode.

Do **not** add conditional branches inside builder functions themselves. The offline guard lives entirely in the tool handler, keeping builders pure and fully testable.

## Documentation — source of truth

### OIE vs Classic

**Always use the OIE (Identity Engine) version of Okta documentation.** The OIE and Classic product lines have meaningfully different policy models, enforcement timing, and feature availability. Classic docs describe a deprecated architecture.

- OIE help docs base URL: `https://help.okta.com/oie/en-us/content/topics/`
- Classic docs base URL: `https://help.okta.com/en-us/content/topics/` ← **do not use**

When writing or updating `riskAssessment`, `adminConsoleSteps`, `logQueries`, or any behavioral claim about how Okta enforces a setting, **fetch the relevant OIE help page and verify the claim against it.** Never rely on memory for enforcement timing, session behavior, or policy scope.

### Behavioral reference — key OIE help pages

| Topic | OIE doc URL |
|---|---|
| Global session policy (session lifetime, MFA, LDAP gap) | https://help.okta.com/oie/en-us/content/topics/identity-engine/policies/about-okta-sign-on-policies.htm |
| Authentication policies (app sign-on, shared policy blast radius) | https://help.okta.com/oie/en-us/content/topics/identity-engine/policies/about-app-sign-on-policies.htm |
| Password policy enforcement timing | https://help.okta.com/oie/en-us/content/topics/identity-engine/authenticators/configure-password.htm |
| Device Assurance | https://help.okta.com/oie/en-us/content/topics/identity-engine/devices/device-assurance.htm |
| Identity Threat Protection | https://help.okta.com/oie/en-us/content/topics/identity-engine/itp/itp-overview.htm |

### API documentation — source of truth

**Always fetch and verify against the live OpenAPI spec before writing any API request body.** Never guess field names, enum values, or request structure from memory.

| What | URL |
|---|---|
| Okta Management API root (browse by tag) | https://developer.okta.com/docs/api/openapi/okta-management/management/tags/application |
| Device Assurance policies | https://developer.okta.com/docs/api/openapi/okta-management/management/tags/deviceassurance/other/createdeviceassurancepolicy |
| Policies (sign-on, password, MFA) | https://developer.okta.com/docs/api/openapi/okta-management/management/tags/Policy |
| Authenticators | https://developer.okta.com/docs/api/openapi/okta-management/management/tags/Authenticator |
| Network Zones | https://developer.okta.com/docs/api/openapi/okta-management/management/tags/NetworkZone |

The base URL pattern for any resource tag is:
`https://developer.okta.com/docs/api/openapi/okta-management/management/tags/<Tag>`

## Log queries — source of truth

**All `logQueries` event type names must be verified against the official Okta event types catalog before being written into any tool.**

- **Browsable reference:** https://developer.okta.com/docs/reference/api/event-types/
- **Downloadable CSV (complete, 1000+ events):** https://developer.okta.com/docs/okta-event-types.csv

Grep the CSV for any event type before using it. Common mistakes to avoid:

| Wrong (does not exist) | Correct |
|---|---|
| `security.risk.change` | `user.risk.change` |
| `security.risk.detect` | `user.risk.detect` |
| `system.ssf.*` | `security.events.provider.*` |
| `system.security_events_provider.*` | `security.events.provider.*` |
| `system.device_assurance.*` | `device.assurance.*` |
| `device.lifecycle.update` | `device.lifecycle.activate` |
| `user.credentials.forgot_password` | `user.account.reset_password` |
| `user.registration.create` | `user.lifecycle.create` |
| `user.verification.*` | `user.identity_verification.*` |
| `policy.continuous_access.action` | `policy.auth_reevaluate.action` (deprecated alias) |

### logQueries array shape

```js
{
  description: string,   // human label shown in the UI
  filter:      string,   // exact Okta System Log filter expression
  timeWindow:  string,   // e.g. "last 30 days"
  note:        string,   // when/why to use this query
}
```

## TEA findings

Tools are mapped to TEA findings by number. Reference these when writing `finding.teaFinding` and tool descriptions:

| Finding | Topic |
|---|---|
| #11 | ITP Session Protection / Continuous Access Evaluation |
| #12 | Device Assurance policies |
| #16 | ITP Universal Logout |
| #17 | ITP Workflow detections |

## Key platform-specific constraints

These have caused 400 errors in the past — always check the OpenAPI spec for the platform you're targeting:

- **macOS / Windows** `diskEncryptionType.include`: only `["ALL_INTERNAL_VOLUMES"]` is valid
- **Android** `diskEncryptionType.include`: valid values are `"USER"` and/or `"FULL"`
- **iOS**: no `diskEncryptionType` field at all
- **Android** `osVersion.minimum`: use major-only format e.g. `"12"`, not `"12.0.0"`
- **iOS** `osVersion.minimum`: use major.minor format e.g. `"16.0"`, not `"16.0.0"`
- **macOS** `osVersion.minimum`: three-component format e.g. `"13.0.0"` ✓
- **Windows** `osVersion.minimum`: four-component build format e.g. `"10.0.22000.0"` (Win 11 GA)
