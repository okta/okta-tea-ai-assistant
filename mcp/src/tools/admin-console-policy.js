'use strict';

const { z } = require('zod');
const { buildMcpOk, buildMcpError, buildMcpOffline, buildMcpReadOnly } = require('./resolver-utils');
const { createOktaClient } = require('../auth/okta-client');

const ADMIN_CONSOLE_APP_NAME = 'okta_admin_console';
const ACCESS_POLICY_TYPE = 'ACCESS_POLICY';

function hasPhishingResistantConstraint(constraints) {
  return Array.isArray(constraints) &&
    constraints.some(
      (c) => c.possession?.phishingResistant === true || c.possession?.phishingResistant === 'REQUIRED',
    );
}

// Name patterns used to identify the Admin Console policy when discovered via
// the policies API (fallback path that needs only okta.policies.read).
const ADMIN_CONSOLE_POLICY_PATTERNS = [
  'admin console',
  'okta admin console',
  'okta_admin_console',
  'adminconsole',
];

// TEA recommendation: admin re-authentication must be capped at 4 hours
const MAX_REAUTH_MINUTES_RECOMMENDED = 240; // PT4H

// ── ISO 8601 duration helpers ──────────────────────────────────────────────────

/**
 * Parse an ISO 8601 duration string (PT4H, PT30M, PT1H30M, PT0S) into minutes.
 * Returns 0 for PT0S, absent, or unparseable values — all treated as "never".
 */
function parseIso8601ToMinutes(duration) {
  if (!duration || duration === 'PT0S') return 0;
  const match = duration.match(/^PT(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?$/);
  if (!match) return 0;
  return (parseInt(match[1] || 0, 10) * 60) +
    parseInt(match[2] || 0, 10) +
    Math.ceil(parseInt(match[3] || 0, 10) / 60);
}

/**
 * Convert minutes to an ISO 8601 duration string for the Okta API.
 * 0 → "PT0S", 240 → "PT4H", 90 → "PT1H30M"
 */
function minutesToIso8601(minutes) {
  if (!minutes) return 'PT0S';
  const h = Math.floor(minutes / 60);
  const m = minutes % 60;
  if (h > 0 && m > 0) return `PT${h}H${m}M`;
  if (h > 0) return `PT${h}H`;
  return `PT${m}M`;
}

// ── App + policy discovery ────────────────────────────────────────────────────
//
// Discovery strategy (most reliable → least reliable):
//
//  Path A — Policies API only (okta.policies.read — always available)
//    1. GET /api/v1/policies?type=ACCESS_POLICY  — scan all access policies
//    2. Match by name pattern against ADMIN_CONSOLE_POLICY_PATTERNS
//    Returns { policy, app: null } — app is enriched separately.
//
//  Path B — Apps API → policy link (okta.apps.read — may be unavailable
//    for platform apps or if the scope was added after the token was issued)
//    1. GET /api/v1/apps?filter=name eq "okta_admin_console"
//    2. Follow app._links.accessPolicy.href
//    Returns { policy, app }
//
// Path A is attempted first to avoid the 403s that `okta.apps.read` can
// produce for Okta built-in platform apps on some tenants.

async function discoverAdminConsolePolicy(client) {
  const diagnostics = { pathAttempted: null, errors: [] };

  // ── Path A: policies API (needs only okta.policies.read) ──────────────────
  diagnostics.pathAttempted = 'policies-api';
  try {
    const { data: allPolicies } = await client.get('/api/v1/policies', {
      params: { type: ACCESS_POLICY_TYPE, limit: 200 },
    });

    const match = allPolicies.find((p) => {
      const name = (p.name || '').toLowerCase();
      return ADMIN_CONSOLE_POLICY_PATTERNS.some((pat) => name.includes(pat));
    });

    if (match) {
      // Best-effort: enrich with app object for Terraform label (non-fatal if it fails)
      let app = null;
      try {
        const { data: apps } = await client.get('/api/v1/apps', {
          params: { filter: `name eq "${ADMIN_CONSOLE_APP_NAME}"`, limit: 5 },
        });
        app = apps[0] || null;
      } catch (_) { /* apps API unavailable — continue without it */ }

      return { policy: match, app, diagnostics };
    }

    diagnostics.errors.push(
      `Policies API returned ${allPolicies.length} ACCESS_POLICYs — none matched ` +
      `patterns: ${ADMIN_CONSOLE_POLICY_PATTERNS.join(', ')}. ` +
      `Policy names found: ${allPolicies.map((p) => `"${p.name}"`).join(', ')}`,
    );
  } catch (err) {
    const detail = err.response?.data ? JSON.stringify(err.response.data) : err.message;
    diagnostics.errors.push(`Policies API (Path A) failed: ${detail}`);
  }

  // ── Path B: apps API → policy link ────────────────────────────────────────
  diagnostics.pathAttempted = 'apps-api';
  try {
    // Try name filter first
    let app = null;
    try {
      const { data: byName } = await client.get('/api/v1/apps', {
        params: { filter: `name eq "${ADMIN_CONSOLE_APP_NAME}"`, limit: 5 },
      });
      app = byName[0] || null;
    } catch (err) {
      const status = err.response?.status;
      const detail = err.response?.data ? JSON.stringify(err.response.data) : err.message;
      diagnostics.errors.push(
        `Apps API name-filter (Path B) failed with ${status ?? 'unknown'}: ${detail}. ` +
        'Likely cause: token lacks okta.apps.read scope, or scope was granted after ' +
        'the current token was issued — delete ~/.okta-tea-ai-assistant/tokens.json and re-login.',
      );
    }

    // Label search fallback
    if (!app) {
      try {
        const { data: byLabel } = await client.get('/api/v1/apps', {
          params: { q: 'Okta Admin Console', limit: 10 },
        });
        app = byLabel.find((a) =>
          a.name === ADMIN_CONSOLE_APP_NAME ||
          a.label?.toLowerCase().includes('admin console'),
        ) || null;
      } catch (err) {
        const detail = err.response?.data ? JSON.stringify(err.response.data) : err.message;
        diagnostics.errors.push(`Apps API label-search (Path B) failed: ${detail}`);
      }
    }

    if (app) {
      const policyHref = app._links?.accessPolicy?.href;
      if (policyHref) {
        const policyId = policyHref.split('/').pop();
        const { data: policy } = await client.get(`/api/v1/policies/${policyId}`);
        return { policy, app, diagnostics };
      }

      const { data: appPolicies } = await client.get(`/api/v1/apps/${app.id}/policies`);
      const accessPolicy = (appPolicies || []).find((p) => p.type === ACCESS_POLICY_TYPE);
      if (accessPolicy) return { policy: accessPolicy, app, diagnostics };

      diagnostics.errors.push(
        `App "${app.id}" found but no ACCESS_POLICY link in _links or /policies response.`,
      );
    }
  } catch (err) {
    const detail = err.response?.data ? JSON.stringify(err.response.data) : err.message;
    diagnostics.errors.push(`Apps API (Path B) unexpected error: ${detail}`);
  }

  return { policy: null, app: null, diagnostics };
}

// ── Audit helpers ──────────────────────────────────────────────────────────────

function auditAdminConsoleRule(policyName, rule, isLowestPriority) {
  const appSignOn = rule.actions?.appSignOn || {};
  const vm = appSignOn.verificationMethod || {};
  const findings = [];

  const factorMode = vm.factorMode ?? '1FA';
  const reauthStr = vm.reauthenticateIn ?? 'PT0S';
  const reauthMinutes = parseIso8601ToMinutes(reauthStr);
  const constraints = vm.constraints || [];
  const phishingResistantPresent = hasPhishingResistantConstraint(constraints);

  // TEA: admin console must require MFA
  if (factorMode !== '2FA') {
    findings.push({
      id: 'ADMIN_CONSOLE_NO_MFA',
      severity: 'HIGH',
      description:
        `Rule "${rule.name}" in policy "${policyName}" allows admin console access with only ` +
        `a password (factorMode: "${factorMode}") — stolen credentials give full org access.`,
      recommendation: 'Set factorMode to "2FA" (password + another factor).',
    });
  } else if (!phishingResistantPresent) {
    findings.push({
      id: 'ADMIN_CONSOLE_NO_PHISHING_RESISTANT',
      severity: 'HIGH',
      description:
        `Rule "${rule.name}" requires MFA but does not restrict to phishing-resistant factors. ` +
        'SMS OTP, TOTP, and basic push notifications are susceptible to real-time phishing ' +
        'and AiTM attacks — a particularly high risk for admin accounts.',
      recommendation:
        'Add a possession constraint with phishingResistant: "REQUIRED" to restrict admin ' +
        'authentication to Okta Verify (biometric / number challenge) or WebAuthn/FIDO2. ' +
        'Use okta_update_admin_console_policy_rule with requirePhishingResistantPossession: true.',
    });
  }

  // TEA: re-authentication must be capped so stolen sessions expire
  if (reauthMinutes === 0) {
    findings.push({
      id: 'ADMIN_CONSOLE_REAUTH_NEVER',
      severity: 'HIGH',
      description:
        `Rule "${rule.name}" never requires re-authentication ` +
        `(reauthenticateIn: "${reauthStr}") — a compromised admin session is valid indefinitely.`,
      recommendation: `Set reauthenticateIn to "PT4H" (${MAX_REAUTH_MINUTES_RECOMMENDED} min).`,
    });
  } else if (reauthMinutes > MAX_REAUTH_MINUTES_RECOMMENDED) {
    findings.push({
      id: 'ADMIN_CONSOLE_REAUTH_TOO_LONG',
      severity: 'MODERATE',
      description:
        `Rule "${rule.name}" re-authenticates every ${reauthMinutes} min — ` +
        `should be ≤ ${MAX_REAUTH_MINUTES_RECOMMENDED} min for admin sessions.`,
      recommendation: `Set reauthenticateIn to "PT4H" (${MAX_REAUTH_MINUTES_RECOMMENDED} min).`,
      current: reauthMinutes,
      recommended: MAX_REAUTH_MINUTES_RECOMMENDED,
    });
  }

  // TEA: lowest-priority rule should be DENY, not open ALLOW
  if (isLowestPriority && appSignOn.access === 'ALLOW') {
    findings.push({
      id: 'ADMIN_CONSOLE_CATCH_ALL_ALLOWS',
      severity: 'MODERATE',
      description:
        `The catch-all rule "${rule.name}" (priority ${rule.priority}) is ALLOW — ` +
        'should be DENY with explicit ALLOW rules for known admin groups/networks.',
      recommendation:
        'Add explicit ALLOW rules for known admin groups/corporate network zones, ' +
        'then set this catch-all rule to DENY.',
    });
  }

  return {
    policyId: rule._policyId,
    policyName,
    ruleId: rule.id,
    ruleName: rule.name,
    rulePriority: rule.priority,
    findingCount: findings.length,
    highCount: findings.filter((f) => f.severity === 'HIGH').length,
    findings,
    current: {
      access: appSignOn.access,
      factorMode,
      reauthenticateIn: reauthStr,
      reauthenticateInMinutes: reauthMinutes,
      phishingResistant: phishingResistantPresent,
      networkConnection: rule.conditions?.network?.connection ?? null,
    },
  };
}

// ── Terraform builder ──────────────────────────────────────────────────────────

function buildAdminConsoleTerraform(app, policy, ruleAudits) {
  const policyLabel = (policy.name || 'admin_console_policy')
    .toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_+|_+$/g, '');

  const rulesHcl = ruleAudits.map((r) => {
    const ruleLabel = r.ruleName
      .toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_+|_+$/g, '');
    const phishingConstraints = r.current?.phishingResistant ? '' : `

  #  — phishing-resistant possession required for admin access
  constraints = jsonencode([
    {
      possession = {
        required          = true
        phishingResistant = "REQUIRED"
        userPresence      = "OPTIONAL"
      }
    }
  ])`;
    return `# Rule ID: ${r.ruleId}
resource "okta_app_signon_policy_rule" "${ruleLabel}_hardened" {
  policy_id                   = okta_app_signon_policy.${policyLabel}.id
  name                        = "${r.ruleName}"
  factor_mode                 = "2FA"
  re_authentication_frequency = "PT4H"
  network_connection          = "ANYWHERE"
  status                      = "ACTIVE"
  priority                    = ${r.rulePriority}${phishingConstraints}
}`;
  }).join('\n\n');

  return `# Terraform — Okta Admin Console sign-on policy (TEA hardening)
#
# Provider setup:
#   https://developer.okta.com/docs/guides/terraform-enable-org-access/main/
# Resource reference:
#   https://registry.terraform.io/providers/okta/okta/latest/docs/resources/app_signon_policy
#   https://registry.terraform.io/providers/okta/okta/latest/docs/resources/app_signon_policy_rule

terraform {
  required_providers {
    okta = {
      source  = "okta/okta"
      version = "~> 4.0"
    }
  }
}

provider "okta" {
  org_name    = "<YOUR_OKTA_ORG>"
  base_url    = "okta.com"
  client_id   = "<YOUR_CLIENT_ID>"
  scopes      = ["okta.policies.manage", "okta.apps.read"]
  private_key = "<PATH_OR_CONTENT_OF_PRIVATE_KEY>"
}

# App ID: ${app.id}  Label: ${app.label}
# Policy ID: ${policy.id}
resource "okta_app_signon_policy" "${policyLabel}" {
  name        = "${policy.name}"
  description = "Hardened Admin Console sign-on policy — TEA aligned"
}

${rulesHcl}
`;
}

// ── Log queries ────────────────────────────────────────────────────────────────

function buildAdminConsoleLogQueries() {
  return [
    {
      description: 'Admin Console access events — verify MFA is being required',
      filter: 'eventType eq "user.session.access_admin_app"',
      timeWindow: 'last 7 days',
      note: 'Every admin console login attempt. After enforcing 2FA, all entries should show MFA authentication.',
    },
    {
      description: 'Admin Console sign-on policy rule changes — audit trail',
      filter: 'eventType eq "policy.rule.update"',
      timeWindow: 'last 90 days',
      note: 'Tracks all changes to the Admin Console sign-on policy rules and who made them.',
    },
    {
      description: 'Admin Console password-only access — detect 1FA sessions',
      filter: 'eventType eq "user.session.access_admin_app" AND outcome.reason co "Password"',
      timeWindow: 'last 30 days',
      note: 'Identifies admin sessions authenticated with password only — should be zero after enforcing 2FA.',
    },
    {
      description: 'Admin role grants — high-value privilege escalation events',
      filter: 'eventType eq "user.account.privilege.grant"',
      timeWindow: 'last 30 days',
      note: 'Monitor alongside policy hardening — admin role grants are the highest-value events in the org.',
    },
  ];
}

// ── Admin console steps ────────────────────────────────────────────────────────

function buildAdminConsoleAdminSteps(policyName) {
  return [
    'Sign in to the Okta Admin Console.',
    'Go to Security > Authentication Policies.',
    `Find the policy named "${policyName}" (linked to the Okta Admin Console app).`,
    'For each rule that allows access:',
    '  a. Click the rule name to edit it.',
    '  b. Under "User must authenticate with", select "Password + Another factor".',
    '  c. Set "Re-authentication frequency" to "Every session" or a specific interval (recommended: 4 hours).',
    '  d. Click Save.',
    '(Recommended) Add a DENY catch-all rule at priority 99 — place explicit ALLOW rules above it scoped to known admin groups or corporate network zones.',
    'Add phishing-resistant factor constraints (restricts to Okta FastPass / WebAuthn only):',
    '  — Via API: call okta_update_admin_console_policy_rule with requirePhishingResistantPossession: true for each ALLOW rule.',
    '  — Via Admin Console: edit each rule → "Authentication methods" → set possession to "Phishing-resistant".',
    '  Note: enroll all admins in FastPass or WebAuthn BEFORE applying this constraint.',
    'Verify in Reports > System Log: filter eventType eq "user.session.access_admin_app" to confirm MFA prompts are appearing.',
  ];
}

// ── Risk assessment ────────────────────────────────────────────────────────────

function buildAdminConsoleRiskAssessment() {
  return {
    teaSeverity: 'HIGH',
    changeRisk:  'LOW',
    summary:
      'Requiring MFA for Admin Console access eliminates the highest-impact attack path — ' +
      'stolen admin credentials giving full org control. Capping re-authentication at 4 hours ' +
      'bounds the window for session theft. These are the two most impactful controls for admin access.',
    preChangeChecks: [
      'Go to Directory > People, filter by admin role, and confirm every admin user has at least one active MFA factor enrolled.',
      'Use okta_list_authenticators to verify Okta Verify enrollment status for admin accounts.',
      'Identify any service accounts or automation users with Admin Console access — they cannot satisfy interactive MFA.',
      'Note that reauthenticateIn changes take effect at the next Admin Console access attempt, not immediately.',
    ],
    blastRadius:
      'Admins without an enrolled MFA factor will be unable to access the Admin Console after ' +
      'factorMode is set to "2FA". The blast radius is limited to admin users only — end users are not affected. ' +
      'The reauthenticateIn window is evaluated at the next access attempt — admins whose session ' +
      'age exceeds the configured window (e.g. PT4H) will be challenged on their next request.',
    rolloutSteps: [
      'Step 1 — Audit admin users: confirm all have MFA enrolled (Directory > People, filter by role).',
      'Step 2 — Set reauthenticateIn to "PT4H" on all ALLOW rules (safe — no lockout risk).',
      'Step 3 — Set factorMode to "2FA" last — this is the step that could lock out admins without a factor.',
      'Step 4 — Monitor System Log: filter user.session.access_admin_app to confirm MFA prompts are appearing.',
      'Step 5 — (Advanced) Add phishing-resistant factor constraints (FastPass / WebAuthn only).',
    ],
    postChangeMonitoring: {
      description:
        'After enabling 2FA on the Admin Console policy, verify that admins are being prompted for MFA ' +
        'and that no admins are being locked out due to missing factor enrollment.',
      logQueries: [
        {
          description: 'Admin Console access events with MFA (confirms 2FA is enforced)',
          filter: 'eventType eq "user.session.access_admin_app"',
          timeWindow: 'first 24 hours post-change',
          note: 'Confirm these events include MFA in the authentication context. If admins are accessing without MFA, the policy may not have been applied correctly.',
        },
        {
          description: 'Admin sign-in failures post-change (possible lockout indicator)',
          filter: 'eventType eq "user.session.start" AND outcome.result eq "DENY" AND target.type eq "AppInstance"',
          timeWindow: 'first 24 hours post-change',
          note: 'A spike here targeting admin users could mean some admins lack an enrolled factor.',
        },
      ],
    },
    rollback:
      'Policy rule changes are immediately reversible — revert factorMode and reauthenticateIn ' +
      'to their previous values to restore prior behaviour. ' +
      'Rolling back to a longer reauthenticateIn window does not invalidate active sessions.',
  };
}

// ── Tool registration ──────────────────────────────────────────────────────────

function registerAdminConsolePolicyTools(server) {
  server.tool(
    'okta_list_admin_console_policy',
    'Audit the Okta Admin Console sign-on policy (ACCESS_POLICY type). ' +
    'Flags rules that do not require MFA (factorMode != "2FA"), never require ' +
    're-authentication (reauthenticateIn = "PT0S"), or allow sessions longer than 4 hours. ' +
    'Admin Console access without MFA is a critical TEA finding — stolen credentials give ' +
    'full org control. Returns per-rule findings with severity, Terraform HCL, System Log ' +
    'queries, admin console remediation steps, and a risk assessment.',
    {},
    async () => {
      if (process.env.OFFLINE_MODE === 'true') {
        const app    = { id: '<APP_ID>', label: 'Okta Admin Console' };
        const policy = { id: '<POLICY_ID>', name: 'Admin Console Policy' };
        const ruleAudits = [{ ruleId: '<RULE_ID>', ruleName: 'Default Rule', rulePriority: 1 }];
        return buildMcpOffline({
          remediation: {
            terraform:         buildAdminConsoleTerraform(app, policy, ruleAudits),
            logQueries:        buildAdminConsoleLogQueries(),
            adminConsoleSteps: buildAdminConsoleAdminSteps('Admin Console Policy'),
            riskAssessment:    buildAdminConsoleRiskAssessment(),
          },
        });
      }
      try {
        const client = await createOktaClient();

        const { policy, app, diagnostics } = await discoverAdminConsolePolicy(client);

        if (!policy) {
          return buildMcpError(new Error(
            'Could not locate the Okta Admin Console sign-on policy. ' +
            'Both the policies API and apps API were tried. ' +
            'diagnostics: ' + JSON.stringify(diagnostics, null, 2),
          ));
        }

        const { data: rules } = await client.get(`/api/v1/policies/${policy.id}/rules`);

        // Identify catch-all: only meaningful when there are multiple rules.
        // A single-rule policy doesn't have a catch-all problem — flag only the
        // lowest-priority rule when it sits below at least one other rule.
        const sorted = [...rules].sort((a, b) => (a.priority ?? 99) - (b.priority ?? 99));
        const catchAllId = rules.length > 1 ? sorted[sorted.length - 1]?.id : null;

        const ruleAudits = rules.map((rule) => {
          rule._policyId = policy.id;
          return auditAdminConsoleRule(policy.name, rule, rule.id === catchAllId);
        });

        const totalFindings = ruleAudits.reduce((n, r) => n + r.findingCount, 0);
        const highFindings = ruleAudits.reduce((n, r) => n + r.highCount, 0);

        return buildMcpOk({
          summary: {
            appId: app?.id ?? null,
            appLabel: app?.label ?? 'Okta Admin Console',
            policyId: policy.id,
            policyName: policy.name,
            totalRules: rules.length,
            totalFindings,
            highFindings,
            discoveryDiagnostics: diagnostics,
          },
          rules: ruleAudits,
          remediation: {
            terraform: buildAdminConsoleTerraform(
              app ?? { id: '(resolved via policies API)', label: 'Okta Admin Console' },
              policy,
              ruleAudits,
            ),
            logQueries: buildAdminConsoleLogQueries(),
            adminConsoleSteps: buildAdminConsoleAdminSteps(policy.name),
            riskAssessment: buildAdminConsoleRiskAssessment(),
          },
        });
      } catch (err) {
        return buildMcpError(err);
      }
    },
  );

  server.tool(
    'okta_update_admin_console_policy_rule',
    'Update a rule in the Okta Admin Console sign-on policy. Supports: factorMode (require 2FA), ' +
    'reauthenticateInMinutes (cap admin session re-use), and requirePhishingResistantPossession ' +
    '(restrict to Okta Verify / WebAuthn — eliminates SMS OTP and TOTP for admin access). ' +
    'All three parameters are optional and can be combined in one call. ' +
    'Get policyId and ruleId from okta_list_admin_console_policy. ' +
    'Write operation — confirm with the admin before calling.',
    {
      policyId: z.string()
        .describe('Admin Console sign-on policy ID (from okta_list_admin_console_policy).'),
      ruleId: z.string()
        .describe('Policy rule ID to update (from okta_list_admin_console_policy).'),
      factorMode: z.enum(['1FA', '2FA']).optional()
        .describe('"2FA" requires password + another factor (recommended). "1FA" allows password only.'),
      reauthenticateInMinutes: z.number().int().min(0).optional()
        .describe('Minutes before re-auth is required. 0 = never (not recommended). TEA recommendation: 240 (4 hours = PT4H).'),
      requirePhishingResistantPossession: z.boolean().optional()
        .describe(
          'true: add a possession constraint requiring phishing-resistant factors (Okta Verify biometric/number challenge or WebAuthn/FIDO2). ' +
          'false: remove the phishing-resistant constraint. ' +
          'Ensure all admins have FastPass or WebAuthn enrolled before setting true.',
        ),
    },
    async ({ policyId, ruleId, factorMode, reauthenticateInMinutes, requirePhishingResistantPossession }) => {
      if (process.env.OFFLINE_MODE === 'true') {
        return buildMcpOffline({ skipped: true, message: 'Write operations are not available in offline mode.' });
      }
      if (process.env.PROD_MODE === 'true') {
        return buildMcpReadOnly();
      }
      if (factorMode === undefined && reauthenticateInMinutes === undefined && requirePhishingResistantPossession === undefined) {
        return buildMcpError(new Error(
          'Provide at least one setting: factorMode, reauthenticateInMinutes, or requirePhishingResistantPossession.',
        ));
      }

      try {
        const client = await createOktaClient();

        const [{ data: policy }, { data: rule }] = await Promise.all([
          client.get(`/api/v1/policies/${policyId}`),
          client.get(`/api/v1/policies/${policyId}/rules/${ruleId}`),
        ]);

        if (policy.type !== ACCESS_POLICY_TYPE) {
          return buildMcpError(new Error(
            `Policy "${policyId}" is type "${policy.type}", not ${ACCESS_POLICY_TYPE}. ` +
            'Use okta_list_admin_console_policy to get the correct IDs.',
          ));
        }

        // Deep clone, then patch only the verificationMethod fields.
        // All conditions and other rule fields are preserved as-is.
        const updated = JSON.parse(JSON.stringify(rule));
        if (!updated.actions) updated.actions = {};
        if (!updated.actions.appSignOn) updated.actions.appSignOn = {};
        if (!updated.actions.appSignOn.verificationMethod) {
          updated.actions.appSignOn.verificationMethod = {};
        }
        const vm = updated.actions.appSignOn.verificationMethod;

        if (factorMode !== undefined) vm.factorMode = factorMode;
        if (reauthenticateInMinutes !== undefined) {
          vm.reauthenticateIn = minutesToIso8601(reauthenticateInMinutes);
        }

        if (requirePhishingResistantPossession !== undefined) {
          // Okta requires verificationMethod.type = 'ASSURANCE' when constraints are present.
          if (!vm.type) vm.type = 'ASSURANCE';
          if (requirePhishingResistantPossession) {
            const nonPossession = (vm.constraints || []).filter((c) => c.possession === undefined);
            vm.constraints = [
              ...nonPossession,
              {
                possession: {
                  required: true,
                  phishingResistant: 'REQUIRED',
                  userPresence: 'OPTIONAL',
                },
              },
            ];
          } else {
            vm.constraints = (vm.constraints || []).filter(
              (c) => !(c.possession?.phishingResistant === true || c.possession?.phishingResistant === 'REQUIRED'),
            );
          }
        }

        const { data: savedRule } = await client.put(
          `/api/v1/policies/${policyId}/rules/${ruleId}`,
          updated,
        );

        rule._policyId = policyId;
        savedRule._policyId = policyId;

        // Audit without catch-all context (we don't have all rules here)
        const auditBefore = auditAdminConsoleRule(policy.name, rule, false);
        const auditAfter = auditAdminConsoleRule(policy.name, savedRule, false);

        const appliedChanges = {};
        if (factorMode !== undefined) appliedChanges.factorMode = factorMode;
        if (requirePhishingResistantPossession !== undefined) {
          appliedChanges.requirePhishingResistantPossession = requirePhishingResistantPossession;
        }
        if (reauthenticateInMinutes !== undefined) {
          appliedChanges.reauthenticateInMinutes = reauthenticateInMinutes;
          appliedChanges.reauthenticateIn = minutesToIso8601(reauthenticateInMinutes);
        }

        // Best-effort app lookup for Terraform output — don't fail the update if it errors
        let app;
        try {
          const discovery = await discoverAdminConsolePolicy(client);
          app = discovery.app;
        } catch (_) { /* ok */ }

        return buildMcpOk({
          message: `Admin Console policy rule "${savedRule.name}" updated in policy "${policy.name}".`,
          policyId,
          ruleId,
          appliedChanges,
          findingsBefore: auditBefore.findingCount,
          findingsAfter: auditAfter.findingCount,
          remainingFindings: auditAfter.findings,
          remediation: {
            terraform: app
              ? buildAdminConsoleTerraform(app, policy, [auditAfter])
              : null,
            logQueries: buildAdminConsoleLogQueries(),
            adminConsoleSteps: buildAdminConsoleAdminSteps(policy.name),
            riskAssessment: buildAdminConsoleRiskAssessment(),
          },
        });
      } catch (err) {
        return buildMcpError(err);
      }
    },
  );
}

module.exports = {
  registerAdminConsolePolicyTools,
  parseIso8601ToMinutes,
  minutesToIso8601,
  auditAdminConsoleRule,
  buildAdminConsoleTerraform,
  buildAdminConsoleLogQueries,
  buildAdminConsoleRiskAssessment,
};
