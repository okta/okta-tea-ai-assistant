# okta-tea-ai-assistant-mcp

MCP server for Okta TEA audit and remediation. Exposes tools for ThreatInsight configuration, network zone management, password policy hardening, session policy management, authenticator settings and others — all authenticated via PKCE (no client secret required). Tools are aligned to Okta's Threat Exposure Assessment (TEA) report findings.


## Authentication
To authenticate, call the `okta_login` tool — for example, ask Claude "login to Okta" or use the chat client. Your browser will open to the Okta login page. After you sign in, the callback is received on `localhost:9876` and tokens are stored automatically.

Tokens are auto-refreshed before they expire. You should only need to re-authenticate if your refresh token is revoked or expires (Okta default: 24 hours of inactivity, configurable).

## Available MCP Tools

Every read/audit tool returns a `remediation` block containing Terraform HCL, Okta System Log queries, manual admin console steps, and a **Change Risk &amp; Blast Radius** assessment — ready to paste or apply.

### Authentication

| Tool | Description |
|---|---|
| `okta_get_auth_status` | Check whether the current token is valid |
| `okta_login` | Start the PKCE browser login flow; waits up to 90 s for completion |

### ThreatInsight  

| Tool | Description |
|---|---|
| `okta_get_threatinsight_config` | Read ThreatInsight mode (none/audit/block), 7-day detection stats, excluded network zones, and full remediation guidance |
| `okta_set_threatinsight_blocking` | Enable ThreatInsight blocking mode *(write)* |

### Network Zones  

| Tool | Description |
|---|---|
| `okta_list_network_zones` | List all zones with 7-day blocked-request stats and Terraform/log-query remediation |
| `okta_get_network_zone` | Get full details of a specific zone by ID |
| `okta_block_countries` | Add countries to a DYNAMIC BLOCKLIST zone; creates the zone if absent *(write)* |
| `okta_configure_security_blocklist` | Idempotent upsert of a DYNAMIC_V2 BLOCKLIST zone for Tor/anonymizer proxies and a DYNAMIC BLOCKLIST zone for OFAC-sanctioned countries and Russian-administered regions *(write)* |

### Password Policies  

| Tool | Description |
|---|---|
| `okta_list_password_policies` | Audit all password policies — flags minimum length < 15, brute force gaps (username/common-password exclusion, lockout count), minimum age not set, and lockout notifications disabled |
| `okta_update_password_policy` | Patch a password policy: `minLength`, `excludeUsername`, `excludeCommonPasswords`, `maxAttempts`, `autoUnlockMinutes`, `showLockoutFailures`, `minAgeMinutes` *(write)* |

### Session Policies 

| Tool | Description |
|---|---|
| `okta_list_session_policies` | Audit all Global Session Policies (OKTA_SIGN_ON) — flags rules missing MFA, session lifetimes > 720 min or unlimited, and idle timeouts > 120 min |
| `okta_update_session_policy_rule` | Patch a session policy rule: `requireFactor`, `factorPromptMode`, `maxSessionLifetimeMinutes`, `maxSessionIdleMinutes`, `usePersistentCookie` *(write)* |

### Authenticators  

| Tool | Description |
|---|---|
| `okta_list_authenticators` | List all authenticators; flags Okta Verify when Number Challenge is disabled (push bombing / MFA fatigue defence) |
| `okta_update_okta_verify_settings` | Enable `numberChallenge: ENABLED` on Okta Verify to require users to match a displayed number — prevents MFA fatigue attacks *(write)* |
| `okta_activate_webauthn` | Activate the WebAuthn/FIDO2 (Security Key or Biometric) authenticator if present but inactive *(write)* |
| `okta_deactivate_weak_authenticator` | Deactivate an insecure authenticator — Phone (SMS/voice call, HIGH: SIM swap / SS7 vulnerable) or Security Question *(write)* |

### Admin Console Policy

| Tool | Description |
|---|---|
| `okta_list_admin_console_policy` | Audit the Admin Console sign-on policy (ACCESS_POLICY type) — flags rules with no MFA, no re-authentication cap, or an open catch-all ALLOW rule |
| `okta_update_admin_console_policy_rule` | Patch an Admin Console policy rule: `factorMode` (enforce 2FA) and `reauthenticateInMinutes` (cap session re-use) *(write)* |

### Security General  

| Tool | Description |
|---|---|
| `okta_get_security_general_settings` | Audit Security > General settings: unknown device blocking and suspicious activity email reporting. Reads from attack protection and features APIs with graceful fallback when unavailable |
| `okta_enable_suspicious_device_blocking` | Enable "Block suspicious password attempts from unknown devices" via attack protection API; falls back to manual steps if endpoint is unavailable *(write)* |
| `okta_enable_suspicious_activity_reporting` | Enable "Report suspicious activity via email" via features lifecycle API; falls back to manual steps if unavailable *(write)* |

### Identity Threat Protection (ITP)

| Tool | Description |
|---|---|
| `okta_get_itp_config` | Audit ITP configuration for Findings #11, #16, and #17. Checks ITP Session Protection / Continuous Access Evaluation (TERMINATE_SESSION action), Universal Logout (cross-app session termination), and Workflow detections |
| `okta_enable_itp_session_protection` | Set high-risk Continuous Access Evaluation rules to TERMINATE_SESSION to prevent session hijacking (Finding #11) *(write)* |
| `okta_enable_itp_universal_logout` | Enable ITP Universal Logout to automatically terminate sessions across all apps on suspicious activity detection (Finding #16) *(write)* |

### Identity Proofing

| Tool | Description |
|---|---|
| `okta_get_identity_proofing_config` | Audit Identity Verification (IDV) configuration for Finding #15. Checks whether an IDV provider (Persona, Incode, Clear, etc.) is configured and whether enrollment/recovery policies enforce identity proofing |

### Device Assurance

| Tool | Description |
|---|---|
| `okta_list_device_assurance_policies` | Audit Device Assurance policies against TEA Appendix B recommendations (Finding #12). Returns a per-check coverage matrix across Android, iOS, macOS, and Windows |
| `okta_create_device_assurance_policy` | Create a Device Assurance policy for a given platform with all Appendix B recommended checks (jailbreak, disk encryption, screen lock, secure hardware, OS version) *(write)* |

### Device Integration (EDR)

| Tool | Description |
|---|---|
| `okta_get_device_integration_config` | Audit EDR / Shared Signals Framework (SSF) provider configuration for Findings #13 and #14. Checks whether an EDR vendor is connected and whether Authentication Policy rules consume device risk signals |


### Security Notifications

| Tool | Description |
|---|---|
| `okta_get_security_notification_emails` | Audit Security Notification Email settings — checks opt-out of communications, suspicious activity reporting, new device sign-in notifications, password change notifications, and factor enrollment notifications |

### OAuth Grants

| Tool | Description |
|---|---|
| `okta_list_apps_insecure_grants` | Audit all active applications for insecure OAuth 2.0 grant types: Resource Owner Password Credentials, Implicit, and Device Authorization Grant |
| `okta_remove_insecure_grants` | Remove Password and/or Implicit grant types from a specific application — run `okta_list_apps_insecure_grants` first to confirm *(write)* |

### Account Management Policy

| Tool | Description |
|---|---|
| `okta_list_account_management_policy` | Audit the Account Management Policy — checks whether self-service password reset and recovery rules require phishing-resistant possession factors (Okta Verify or WebAuthn/FIDO2) |
| `okta_update_account_management_policy_rule` | Update an Account Management Policy rule to require phishing-resistant possession factors for self-service reset and recovery flows *(write)* |

### Authentication Policies

| Tool | Description |
|---|---|
| `okta_list_authentication_policies` | Audit all app sign-on policies (ACCESS_POLICY type) — flags rules that allow access without MFA and catch-all rules that do not DENY |
| `okta_update_authentication_policy_rule` | Update an authentication policy rule: `factorMode`, `reauthenticateInMinutes`, `requirePhishingResistantPossession` *(write)* |

### Behavior Detection

| Tool | Description |
|---|---|
| `okta_get_behavior_detection` | Audit Behavior Detection rules (New Device, New IP, Velocity) — checks whether rules are active and referenced in authentication policies |

### Log Streaming

| Tool | Description |
|---|---|
| `okta_get_log_streaming_config` | Audit Log Streaming configuration — checks whether SIEM forwarding is active |

### CAPTCHA

| Tool | Description |
|---|---|
| `okta_get_captcha_config` | Audit CAPTCHA integration — checks whether CAPTCHA is configured for self-service registration, recovery, and unlock flows |

### Authorization Servers

| Tool | Description |
|---|---|
| `okta_list_authorization_servers` | Audit Authorization Server configuration — checks audiences, access policies, and unused servers |

### Attack Protection

| Tool | Description |
|---|---|
| `okta_get_attack_protection` | Audit attack protection settings — checks breached password detection and username enumeration protection |

### IdP Configuration

| Tool | Description |
|---|---|
| `okta_get_idp_config` | Audit Identity Provider configuration — checks for IdP auto-link enabled without appropriate JIT provisioning controls |

### Default Policy Audit

| Tool | Description |
|---|---|
| `okta_audit_default_policies` | Audit policies whose names contain "default" across five policy types (OKTA_SIGN_ON, PASSWORD, ACCESS_POLICY, MFA_ENROLL, PROFILE_ENROLLMENT) — identifies unreviewed default policies that may be overly permissive |

### Admin Roles

| Tool | Description |
|---|---|
| `okta_audit_super_admins` | Count users holding a standing SUPER_ADMIN role; flags counts > 1 and identifies apparent service accounts with super admin access. Recommends zero standing privileges via Okta Govern Admin Roles (Okta Identity Governance subscription required) |

### API Tokens

| Tool | Description |
|---|---|
| `okta_audit_api_tokens` | Audit all active SSWS API tokens — reports count, flags tokens without network zone restriction (HIGH) and tokens with no expiry (LOW). Recommends migrating to OAuth2 client credentials. Read-only. |

### System Log

| Tool | Description |
|---|---|
| `okta_get_phishing_resistant_usage` | Calculate recent phishing-resistant MFA usage from System Log — counts successful MFA authentications by factor type and reports the percentage of phishing-resistant methods |
| `okta_query_syslogs` | Run an ad-hoc query against the Okta System Log with any valid SCIM filter expression — returns events with timestamp, eventType, actor, target, outcome, client IP, and factor type |

## TEA Finding Coverage

| Finding | Severity | Tool(s) |
|---|---|---|
| Global Session Policies require MFA | High | `okta_list_session_policies`, `okta_update_session_policy_rule` |
| Reduce session lifetime to 720 min | High | `okta_list_session_policies`, `okta_update_session_policy_rule` |
| Block Tor / anonymizer proxies | High | `okta_configure_security_blocklist` |
| Password brute force protection | High | `okta_list_password_policies`, `okta_update_password_policy` |
| Password minimum length ≥ 15 | High | `okta_list_password_policies`, `okta_update_password_policy` |
| Country blocklists | Moderate | `okta_block_countries`, `okta_configure_security_blocklist` |
| Reduce network zone IP addresses | Moderate | `okta_list_network_zones` |
|  Okta Verify Number Challenge | Moderate | `okta_list_authenticators`, `okta_update_okta_verify_settings` |
| Idle session timeout ≤ 120 min | Moderate | `okta_list_session_policies`, `okta_update_session_policy_rule` |
| Block suspicious unknown-device attempts | Low | `okta_get_security_general_settings`, `okta_enable_suspicious_device_blocking` |
| Password minimum age 1440 min | Low | `okta_list_password_policies`, `okta_update_password_policy` |
| Suspicious activity email reporting | Low | `okta_get_security_general_settings`, `okta_enable_suspicious_activity_reporting` |
|  Remove unused network zones | Info | `okta_list_network_zones` |
| Lockout notification emails | Info | `okta_list_password_policies`, `okta_update_password_policy` |
| Review ThreatInsight exempt zones | Info | `okta_get_threatinsight_config` |
| Admin Console requires MFA + re-auth cap | High | `okta_list_admin_console_policy`, `okta_update_admin_console_policy_rule` |
| ITP Session Protection (TERMINATE_SESSION) | Moderate | `okta_get_itp_config`, `okta_enable_itp_session_protection` |
| ITP Universal Logout | Moderate | `okta_get_itp_config`, `okta_enable_itp_universal_logout` |
| ITP Workflow detections | Moderate | `okta_get_itp_config` |
| Identity Proofing Provider (IDV) | Moderate | `okta_get_identity_proofing_config` |
| Device Assurance policies (Appendix B) | Moderate | `okta_list_device_assurance_policies`, `okta_create_device_assurance_policy` |
| EDR / endpoint security integration | Moderate | `okta_get_device_integration_config` |
| Super admin count > 1 (zero standing privileges) | High | `okta_audit_super_admins` |
| Service accounts with SUPER_ADMIN role | High | `okta_audit_super_admins` |
| Active SSWS API tokens (OAuth2 preferred) | Moderate | `okta_audit_api_tokens` |
| API token without network zone restriction | High | `okta_audit_api_tokens` |
| API token with no expiry | Low | `okta_audit_api_tokens` |
| Auth policies using EDR device signals | Moderate | `okta_get_device_integration_config` |

## API Scopes

The PKCE login flow requests the following OAuth scopes. All scopes are required for full tool coverage:

| Scope | Purpose |
|---|---|
| `openid` | OIDC authentication |
| `okta.threatInsights.manage` | ThreatInsight read/write |
| `okta.networkZones.manage` | Network zone read/write |
| `okta.logs.read` | System Log queries |
| `okta.policies.read` | Read all policies (session, authentication, password, enrollment, ITP continuous access) |
| `okta.policies.manage` | Write all policies |
| `okta.authenticators.read` | Read authenticators (Okta Verify settings) |
| `okta.authenticators.manage` | Update authenticators |
| `okta.apps.read` | Read application configurations |
| `okta.apps.manage` | Update application grant types |
| `okta.orgs.manage` | Org-level settings (org configuration, security general, attack protection) |
| `okta.features.read` | Read org feature flags — ITP Universal Logout, ITP Workflows, suspicious activity reporting, breached password detection, enumeration protection |
| `okta.features.manage` | Enable org features — used by `okta_enable_itp_universal_logout` and `okta_enable_suspicious_activity_reporting` *(write)* |
| `okta.deviceAssurance.read` | Read Device Assurance policies |
| `okta.deviceAssurance.manage` | Create/update Device Assurance policies *(write)* |
| `okta.idps.read` | Read Identity Providers — used for identity proofing detection and IdP auto-link audit |
| `okta.securityEventsProviders.read` | Read Shared Signals Framework (SSF) providers — used to detect EDR integrations |
| `okta.behaviors.read` | Read Behavior Detection rules (New Device, New IP, Velocity) |
| `okta.logStreams.read` | Read Log Streaming configuration — checks whether SIEM forwarding is active |
| `okta.captchas.read` | Read CAPTCHA integrations — checks whether CAPTCHA is configured for self-service flows |
| `okta.authorizationServers.read` | Read Authorization Server configuration — checks audiences, access policies, and unused servers |
| `okta.roles.read` | Read per-user role assignment records (`/api/v1/users/{id}/roles`) — required for `okta_audit_super_admins` |
| `okta.users.read` | Enumerate all users (`/api/v1/users`) — required for `okta_audit_super_admins` |
| `okta.apiTokens.read` | Read API token metadata (count, restriction status, expiry) — required for `okta_audit_api_tokens` |

> **Note:** `okta.features.read` and `okta.features.manage` are separate scopes from `okta.orgs.manage` — the `/api/v1/features` endpoint requires its own dedicated scopes. `okta.deviceAssurance.*` requires the Device Assurance feature to be enabled on your tenant. `okta.securityEventsProviders.read` requires the SSF feature to be provisioned. `okta.behaviors.read`, `okta.logStreams.read`, `okta.captchas.read`, and `okta.authorizationServers.read` each require the corresponding feature to be provisioned on the tenant — tools fall back gracefully with a `CANNOT VERIFY` finding if the endpoint is unavailable.

## Notes

**Country and proxy blocking** (`okta_block_countries`, `okta_configure_security_blocklist`) require **Okta ThreatInsight Advanced** or **Adaptive MFA** for DYNAMIC network zones. If your tenant does not have this feature these tools return a clear error. Contact your Okta account team to enable it.

Country codes must be ISO 3166-1 alpha-2 (two uppercase letters, e.g. `CN`, `RU`, `KP`).

**Security General write tools** (`okta_enable_suspicious_device_blocking`, `okta_enable_suspicious_activity_reporting`) apply changes via the Okta attack protection API and the features lifecycle API respectively. The features API requires `okta.features.manage` (separate from `okta.orgs.manage`). If an endpoint is not available on the tenant, the tools return `apiAvailable: false` with full manual admin console steps — no error is thrown.

**ITP tools** (`okta_get_itp_config`, `okta_enable_itp_session_protection`, `okta_enable_itp_universal_logout`) read ITP Session Protection policies (`/api/v1/policies?type=POST_AUTH_SESSION`, current name) with automatic fallback to the deprecated `CONTINUOUS_ACCESS` type alias for older tenants. Feature checks (Universal Logout, Workflows) use `/api/v1/features` which requires `okta.features.read`. If ITP is not provisioned on the tenant, all tools fall back to manual admin console steps — contact your Okta account team to enable ITP.

**Identity Proofing** (`okta_get_identity_proofing_config`) reads `/api/v1/idps` using `okta.idps.read` scope. IDV providers appear as Okta Identity Providers with vendor-specific type strings. If the scope is missing, the tool returns a clear scope error.

**Device Assurance tools** (`okta_list_device_assurance_policies`, `okta_create_device_assurance_policy`) require the Device Assurance feature and `okta.deviceAssurance.read`/`okta.deviceAssurance.manage` scopes. If not available, tools return a clear error with manual steps. After creating policies, they must be assigned in Authentication Policy rules to be enforced — creation alone does not block non-compliant devices.

**Device Integration / EDR** (`okta_get_device_integration_config`) reads the Shared Signals Framework providers API (`/api/v1/ssf/providers`) and risk providers API (`/api/v1/risk/providers`). Both endpoints fall back gracefully if not available. EDR configuration itself must be done in the Admin Console — the tool surfaces findings and guidance but does not write EDR provider settings.

**Behavior Detection** (`okta_get_behavior_detection`) reads `/api/v1/behaviors` and requires `okta.behaviors.read`. Returns a `CANNOT VERIFY` finding if the endpoint is unavailable.

**Log Streaming** (`okta_get_log_streaming_config`) reads `/api/v1/logStreams` and requires `okta.logStreams.read`. Returns a `CANNOT VERIFY` finding if unavailable.

**CAPTCHA** (`okta_get_captcha_config`) reads `/api/v1/captchas` and `/api/v1/org/captcha`. Requires `okta.captchas.read`. The org CAPTCHA endpoint may return 404 on some tenants — the tool reports findings based on whatever is available.

**Authorization Servers** (`okta_list_authorization_servers`) reads `/api/v1/authorizationServers` and requires `okta.authorizationServers.read`. Only available on tenants with API Access Management provisioned.

**Attack Protection** (`okta_get_attack_protection`) reads `/api/v1/attack_protection` (requires `okta.orgs.manage`) and `/api/v1/features` (requires `okta.features.read`). Checks for breached password detection and username enumeration protection. Falls back to feature flag detection when the attack protection endpoint is unavailable.

**Authentication Policies** (`okta_list_authentication_policies`) reads `ACCESS_POLICY` type policies — these are the OIE app sign-on policies, distinct from the global `OKTA_SIGN_ON` policy covered by `okta_list_session_policies`. Requires `okta.policies.read`. Available on OIE tenants only.

**IdP Auto-Link** (`okta_get_idp_config`) reads `/api/v1/idps` using `okta.idps.read`. Returns no findings if no IdPs are configured.

**Default Policy Audit** (`okta_audit_default_policies`) reads policies across five types: `OKTA_SIGN_ON`, `PASSWORD`, `ACCESS_POLICY`, `MFA_ENROLL`, `PROFILE_ENROLLMENT`. Flags any policy whose name contains "default" (case-insensitive). Requires `okta.policies.read`.

**API Tokens** (`okta_audit_api_tokens`) calls `GET /api/v1/api-tokens` and requires `okta.apiTokens.read` scope. Reports only token metadata — the Okta API never returns the raw token value after creation. Zone restriction field name (`networkCondition`) is handled defensively; verify against a live tenant response if unexpected results appear. Cross-references active IP-type network zones (uses existing `okta.networkZones.manage` scope) to surface candidates for restriction. No write tool — token revocation and zone assignment must be done via the Admin Console. Offline mode returns representative counts matching a typical TEA finding (13 tokens, 11 unrestricted).

**Super Admins / Admin Roles** (`okta_audit_super_admins`) enumerates all users via `GET /api/v1/users` (`okta.users.read`) and checks each user's roles via `GET /api/v1/users/{id}/roles` (`okta.roles.read`). Reports only direct user role assignments — SUPER_ADMIN assigned via a group is not counted; check group role assignments separately. Service account classification is heuristic. Implementing zero standing privileges requires an **Okta Identity Governance subscription** — the tool returns full guidance in offline mode if the subscription is not active.

## Development

```bash
npm test              # run Jest tests (154 tests)
npm run test:coverage # test with coverage report
npm run lint          # ESLint (src + tests)
```
