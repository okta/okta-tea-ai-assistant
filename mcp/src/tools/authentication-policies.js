'use strict';

const { z } = require('zod');
const { buildMcpOk, buildMcpError, buildMcpOffline, buildMcpReadOnly } = require('./resolver-utils');
const { createOktaClient } = require('../auth/okta-client');

// OIE app sign-on policy type (distinct from OKTA_SIGN_ON global session policy)
const ACCESS_POLICY_TYPE = 'ACCESS_POLICY';

// ── Fetchers ───────────────────────────────────────────────────────────────────

async function fetchAccessPolicies(client) {
  try {
    const { data } = await client.get(`/api/v1/policies?type=${ACCESS_POLICY_TYPE}`);
    return { available: true, policies: Array.isArray(data) ? data : [] };
  } catch (err) {
    const status = err.response?.status;
    if (status === 404 || status === 403) {
      return {
        available: false,
        reason: `API returned ${status} — Access Policies may require OIE or okta.policies.read scope.`,
        policies: [],
      };
    }
    return { available: false, reason: err.message, policies: [] };
  }
}

async function fetchPolicyRules(client, policyId) {
  try {
    const { data } = await client.get(`/api/v1/policies/${policyId}/rules`);
    return Array.isArray(data) ? data : [];
  } catch (err) {
    return [];
  }
}

async function fetchPolicyApps(client, policyId) {
  try {
    const { data } = await client.get(`/api/v1/policies/${policyId}/app`);
    return Array.isArray(data) ? data : [];
  } catch (err) {
    return [];
  }
}

// ── Audit helpers ──────────────────────────────────────────────────────────────

// Okta API returns phishingResistant as a string enum ("REQUIRED") or boolean true.
function hasPhishingResistantPossession(constraints) {
  return constraints.some((c) => {
    const val = c.possession?.phishingResistant;
    return val === true || val === 'REQUIRED';
  });
}

function auditRule(policyName, rule, isLastRule) {
  const findings = [];
  const access = rule.actions?.appSignOn?.access;
  const verificationMethod = rule.actions?.appSignOn?.verificationMethod;

  // Catch-all rule (last rule) should deny access
  if (isLastRule) {
    if (access !== 'DENY') {
      findings.push({
        id: 'CATCH_ALL_RULE_NOT_DENY',
        severity: 'HIGH',
        description:
          `The catch-all rule "${rule.name}" in policy "${policyName}" does not DENY access. ` +
          'The last rule in an authentication policy acts as a catch-all for any request not ' +
          'matched by earlier rules. If it allows access without MFA, unmatched scenarios ' +
          'may bypass authentication requirements.',
        recommendation:
          `Set the catch-all rule "${rule.name}" action to DENY in policy "${policyName}". ` +
          'Ensure all legitimate sign-in scenarios are covered by earlier, more specific rules.',
      });
    }
    return findings;
  }

  // Non-catch-all rules: check MFA and phishing resistance
  if (access === 'ALLOW') {
    const factorMode = verificationMethod?.factorMode;
    const constraints = verificationMethod?.constraints || [];

    // factorMode "1FA" means no MFA, or constraints empty means no factor required
    const requiresMfa =
      factorMode === '2FA' ||
      factorMode === 'REQUIRED' ||
      constraints.length > 0;

    if (!requiresMfa) {
      findings.push({
        id: 'AUTH_POLICY_RULE_NO_MFA',
        severity: 'HIGH',
        description:
          `Rule "${rule.name}" in policy "${policyName}" allows access without requiring MFA. ` +
          'Authentication policy rules that permit sign-in without a second factor are vulnerable ' +
          'to credential stuffing and phishing attacks.',
        recommendation:
          `Update rule "${rule.name}" to require a second factor. ` +
          'Set factorMode to "2FA" and add phishing-resistant factor constraints (Okta Verify or FIDO2/WebAuthn).',
      });
    } else if (!hasPhishingResistantPossession(constraints)) {
      findings.push({
        id: 'AUTH_POLICY_RULE_NO_PHISHING_RESISTANT',
        severity: 'MODERATE',
        description:
          `Rule "${rule.name}" in policy "${policyName}" requires MFA but does not enforce ` +
          'phishing-resistant factors. Rules without phishingResistant: REQUIRED on the ' +
          'possession constraint allow weaker second factors (e.g. SMS OTP, TOTP) that are ' +
          'susceptible to real-time phishing and AiTM attacks.',
        recommendation:
          `Update the possession constraint on rule "${rule.name}" to set ` +
          'phishingResistant: "REQUIRED". This limits eligible factors to Okta Verify ' +
          '(with biometric/PIN) and FIDO2/WebAuthn authenticators.',
      });
    }
  }

  return findings;
}

async function auditPolicy(client, policy) {
  const policyFindings = [];

  const [rules, apps] = await Promise.all([
    fetchPolicyRules(client, policy.id),
    fetchPolicyApps(client, policy.id),
  ]);

  // Unused policies — no apps assigned
  if (apps.length === 0 && policy.status === 'ACTIVE') {
    policyFindings.push({
      id: 'AUTH_POLICY_NO_APPS',
      severity: 'LOW',
      description:
        `Authentication policy "${policy.name}" is ACTIVE but has no applications assigned. ` +
        'Unused policies increase management overhead and may create confusion about which ' +
        'policy applies to newly created apps.',
      recommendation:
        `Review "${policy.name}" — assign applications to it or deactivate/delete it if unused.`,
    });
  }

  // Audit each rule
  for (let i = 0; i < rules.length; i++) {
    const rule = rules[i];
    const isLast = i === rules.length - 1;
    const ruleFindings = auditRule(policy.name, rule, isLast);
    policyFindings.push(...ruleFindings);
  }

  const mappedRules = rules.map((r, i) => ({
    id: r.id,
    name: r.name,
    priority: r.priority,
    status: r.status,
    isCatchAll: i === rules.length - 1,
    access: r.actions?.appSignOn?.access,
    factorMode: r.actions?.appSignOn?.verificationMethod?.factorMode,
    phishingResistant: hasPhishingResistantPossession(
      r.actions?.appSignOn?.verificationMethod?.constraints || []
    ),
  }));

  const allowRules = mappedRules.filter((r) => !r.isCatchAll && r.access === 'ALLOW');
  const phishingResistantRuleCount = allowRules.filter((r) => r.phishingResistant).length;

  return {
    policyId: policy.id,
    policyName: policy.name,
    status: policy.status,
    ruleCount: rules.length,
    appCount: apps.length,
    allowRuleCount: allowRules.length,
    phishingResistantRuleCount,
    findings: policyFindings,
    rules: mappedRules,
  };
}

// ── Terraform ──────────────────────────────────────────────────────────────────

function buildAuthPolicyTerraform() {
  return `# Terraform — Okta Authentication Policies (Access Policies)
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
  scopes      = ["okta.policies.manage"]
  private_key = "<PATH_OR_CONTENT_OF_PRIVATE_KEY>"
}

# Example: Update an existing app sign-on policy rule to require MFA
resource "okta_app_signon_policy_rule" "require_mfa" {
  policy_id = "<POLICY_ID>"
  name      = "Require phishing-resistant MFA"
  priority  = 1
  status    = "ACTIVE"

  factor_mode           = "2FA"
  re_authentication_frequency = "PT12H"

  constraints = jsonencode([
    {
      possession = {
        required          = true
        phishingResistant = "REQUIRED"
        userPresence      = "OPTIONAL"
      }
    }
  ])
}

# Catch-all rule — always DENY for unmatched requests
resource "okta_app_signon_policy_rule" "catch_all" {
  policy_id = "<POLICY_ID>"
  name      = "Catch-all Rule"
  priority  = 99  # Must be the last rule
  status    = "ACTIVE"

  access = "DENY"
}
`;
}

// ── Log queries ────────────────────────────────────────────────────────────────

function buildAuthPolicyLogQueries() {
  return [
    {
      description: 'Authentication policy evaluations',
      filter: 'eventType eq "policy.evaluate_sign_on"',
      timeWindow: 'last 7 days',
      note: 'All sign-on policy evaluations — review outcome.result for ALLOW/CHALLENGE/DENY distribution.',
    },
    {
      description: 'Sign-ins allowed without MFA (single factor)',
      filter: 'eventType eq "user.authentication.sso" AND debugContext.debugData.factor eq "PASSWORD_AS_FACTOR"',
      timeWindow: 'last 30 days',
      note: 'Sign-ins where only a password was verified — indicates rules not requiring a second factor.',
    },
    {
      description: 'Authentication policy configuration changes',
      filter: 'eventType eq "policy.lifecycle.update" OR eventType eq "policy.rule.update"',
      timeWindow: 'last 90 days',
      note: 'Audit trail of authentication policy and rule changes.',
    },
    {
      description: 'Access denied by catch-all rule',
      filter: 'eventType eq "policy.evaluate_sign_on" AND outcome.result eq "DENY"',
      timeWindow: 'last 7 days',
      note: 'Requests denied by authentication policy rules — confirms catch-all DENY is working.',
    },
  ];
}

// ── Admin console steps ────────────────────────────────────────────────────────

function buildAuthPolicyAdminSteps() {
  return [
    'Sign in to the Okta Admin Console.',
    'Go to Security > Authentication Policies.',
    'For each policy, review the rules:',
    '',
    'To require MFA on a rule:',
    '  1. Click the policy name, then click Edit on the rule.',
    '  2. Set "User must authenticate with" to "Password + Another factor".',
    '  3. Under "Additional factor types", select "Okta Verify" and/or "FIDO2 (WebAuthn)" for phishing resistance.',
    '  4. Set a re-authentication frequency (e.g. "Every 12 hours").',
    '  5. Click Save.',
    '',
    'To set a catch-all DENY rule:',
    '  1. Click the policy, then click the last rule (usually "Catch-all Rule").',
    '  2. Click Edit.',
    '  3. Set the action to "Denied".',
    '  4. Click Save.',
    '',
    'To remove unused policies:',
    '  1. Click the policy name.',
    '  2. Confirm there are no apps assigned under the "Applications" tab.',
    '  3. Click "Deactivate" or "Delete" from the policy actions menu.',
  ];
}

// ── Risk assessment ────────────────────────────────────────────────────────────

function buildAuthPolicyRiskAssessment() {
  return {
    teaSeverity: 'HIGH',
    changeRisk:  'MODERATE',
    summary:
      'Authentication policy rules that do not require MFA expose applications to credential ' +
      'stuffing and phishing. A catch-all rule that ALLOWS rather than DENIES means any ' +
      'authentication scenario not explicitly covered by a rule will silently succeed without ' +
      'the intended security controls. ' +
      'Policies can be shared across multiple apps — edits to a shared policy take effect ' +
      'for every app assigned to it, not just the app being audited.',
    preChangeChecks: [
      'Check MFA enrollment coverage for the user population affected by this policy before adding factorMode: 2FA — unenrolled users will be locked out.',
      'Check how many apps are assigned to the policy before changing rules — shared policies have org-wide blast radius.',
      'Use policy.evaluate_sign_on System Log events to understand which rules are being hit and by which users.',
      'Test catch-all DENY changes with a non-admin account first to confirm earlier rules cover all legitimate sign-in scenarios.',
    ],
    blastRadius:
      'Adding MFA requirements to existing rules will challenge users who do not have a ' +
      'second factor enrolled — they will be locked out until they enroll. ' +
      'Changing a catch-all ALLOW to DENY may block legitimate sign-ins if earlier rules ' +
      'do not cover all valid scenarios. ' +
      'If a policy is shared, the change applies simultaneously across every app assigned to it — ' +
      'confirm the full list of assigned apps before tightening rules.',
    rolloutSteps: [
      'Step 1 — Audit all authentication policies with this tool to identify gaps.',
      'Step 2 — Set catch-all rules to DENY first (lowest blast radius — only affects unmatched scenarios).',
      'Step 3 — Add MFA requirements to rules with significant user populations (verify enrollment first).',
      'Step 4 — Add phishing-resistant factor requirements to rules covering high-value apps.',
      'Step 5 — Remove or deactivate unused policies.',
      'Step 6 — Monitor for sign-in failures (see postChangeMonitoring queries).',
    ],
    postChangeMonitoring: {
      description:
        'After tightening authentication policies, watch for unexpected sign-in failures. ' +
        'The key signal is policy.evaluate_sign_on DENY outcomes on users who should have access.',
      logQueries: [
        {
          description: 'Authentication policy evaluations — all outcomes',
          filter: 'eventType eq "policy.evaluate_sign_on"',
          timeWindow: 'first 48 hours post-change',
          note: 'Look for DENY outcomes on known users. Each DENY is a user blocked by a policy rule change.',
        },
        {
          description: 'MFA challenges triggered by new factorMode requirements',
          filter: 'eventType eq "user.authentication.auth_via_mfa"',
          timeWindow: 'first 48 hours post-change',
          note: 'Volume increase after adding factorMode: 2FA is expected and confirms the rule is working.',
        },
        {
          description: 'Sign-in failures from missing factor enrollment',
          filter: 'eventType eq "user.session.start" AND outcome.result eq "DENY" AND outcome.reason co "factor"',
          timeWindow: 'first 48 hours post-change',
          note: 'These are users blocked because they have no enrolled factor. Assist them to enroll or exempt them from the policy.',
        },
      ],
    },
    rollback:
      'Policy rule changes take effect immediately but are reversible — revert factorMode, ' +
      'constraints, and catch-all rule actions via the Admin Console or Terraform plan/apply.',
  };
}

// ── Tool registration ─────────────────────────────────────────────────────────

function minutesToIso8601(minutes) {
  if (minutes === 0) return 'PT0S';
  const h = Math.floor(minutes / 60);
  const m = minutes % 60;
  return h > 0 && m === 0 ? `PT${h}H` : h > 0 ? `PT${h}H${m}M` : `PT${m}M`;
}

function registerAuthenticationPolicyTools(server) {
  server.tool(
    'okta_update_authentication_policy_rule',
    'Update a rule in an Okta Authentication Policy (app sign-on policy, type ACCESS_POLICY). ' +
    'Supports: factorMode (require 2FA), reauthenticateInMinutes (cap session re-use), and ' +
    'requirePhishingResistantPossession (restrict to Okta Verify / WebAuthn — eliminates SMS OTP ' +
    'and TOTP as eligible factors). All parameters are optional and can be combined in one call. ' +
    'Get policyId and ruleId from okta_list_authentication_policies. ' +
    'Write operation — confirm before calling.',
    {
      policyId: z.string()
        .describe('Authentication policy ID (from okta_list_authentication_policies).'),
      ruleId: z.string()
        .describe('Rule ID to update (from okta_list_authentication_policies).'),
      factorMode: z.enum(['1FA', '2FA']).optional()
        .describe('"2FA" requires a second factor. "1FA" allows password-only access.'),
      reauthenticateInMinutes: z.number().int().min(0).optional()
        .describe('Minutes before re-authentication is required. 0 = never.'),
      requirePhishingResistantPossession: z.boolean().optional()
        .describe(
          'true: add a possession constraint requiring phishing-resistant factors ' +
          '(Okta Verify biometric/number challenge or WebAuthn/FIDO2). ' +
          'false: remove the phishing-resistant constraint. ' +
          'Ensure users have FastPass or WebAuthn enrolled before setting true.',
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
            `Policy ${policyId} is type "${policy.type}", not ACCESS_POLICY. ` +
            'This tool only updates authentication (app sign-on) policies.',
          ));
        }

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

        const appliedChanges = {};
        if (factorMode !== undefined) appliedChanges.factorMode = factorMode;
        if (reauthenticateInMinutes !== undefined) {
          appliedChanges.reauthenticateInMinutes = reauthenticateInMinutes;
          appliedChanges.reauthenticateIn = minutesToIso8601(reauthenticateInMinutes);
        }
        if (requirePhishingResistantPossession !== undefined) {
          appliedChanges.requirePhishingResistantPossession = requirePhishingResistantPossession;
        }

        const savedVm = savedRule.actions?.appSignOn?.verificationMethod || {};
        return buildMcpOk({
          policyId,
          policyName: policy.name,
          ruleId,
          ruleName: savedRule.name,
          appliedChanges,
          result: {
            factorMode: savedVm.factorMode,
            reauthenticateIn: savedVm.reauthenticateIn,
            phishingResistant: hasPhishingResistantPossession(savedVm.constraints || []),
          },
        });
      } catch (err) {
        return buildMcpError(err);
      }
    },
  );

  server.tool(
    'okta_list_authentication_policies',
    'Audit Okta Authentication Policies (app sign-on policies, type ACCESS_POLICY). ' +
    'Checks: (1) rules that allow access without MFA — vulnerable to credential stuffing; ' +
    '(2) catch-all rule that does not DENY — unmatched scenarios may bypass security controls; ' +
    '(3) active policies with no applications assigned — unused policies to clean up. ' +
    'Note: this covers app-level sign-on policies, not the global session policy (see okta_list_session_policies). ' +
    'Returns per-policy and per-rule findings with remediation guidance.',
    {},
    async () => {
      if (process.env.OFFLINE_MODE === 'true') {
        return buildMcpOffline({
          remediation: {
            terraform:         buildAuthPolicyTerraform(),
            logQueries:        buildAuthPolicyLogQueries(),
            adminConsoleSteps: buildAuthPolicyAdminSteps(),
            riskAssessment:    buildAuthPolicyRiskAssessment(),
          },
        });
      }
      try {
        const client = await createOktaClient();
        const result = await fetchAccessPolicies(client);

        if (!result.available) {
          return buildMcpOk({
            available: false,
            reason: result.reason,
            findings: [{
              id: 'ACCESS_POLICY_API_UNAVAILABLE',
              severity: 'INFO',
              description: `Authentication Policies API unavailable: ${result.reason}`,
              recommendation: 'Verify manually under Security > Authentication Policies in the Admin Console.',
            }],
          });
        }

        const policyAudits = await Promise.all(
          result.policies.map((p) => auditPolicy(client, p))
        );

        const allFindings = policyAudits.flatMap((p) => p.findings);
        const highFindings = allFindings.filter((f) => f.severity === 'HIGH').length;
        const totalAllowRules = policyAudits.reduce((sum, p) => sum + p.allowRuleCount, 0);
        const totalPhishingResistant = policyAudits.reduce((sum, p) => sum + p.phishingResistantRuleCount, 0);

        return buildMcpOk({
          summary: {
            totalPolicies: result.policies.length,
            findingCount: allFindings.length,
            highFindings,
            policiesWithFindings: policyAudits.filter((p) => p.findings.length > 0).length,
            phishingResistance: {
              totalAllowRules,
              requirePhishingResistant: totalPhishingResistant,
              lackPhishingResistant: totalAllowRules - totalPhishingResistant,
            },
          },
          policies: policyAudits,
          findings: allFindings,
          remediation: {
            terraform: buildAuthPolicyTerraform(),
            logQueries: buildAuthPolicyLogQueries(),
            adminConsoleSteps: buildAuthPolicyAdminSteps(),
            riskAssessment: buildAuthPolicyRiskAssessment(),
          },
        });
      } catch (err) {
        return buildMcpError(err);
      }
    },
  );
}

module.exports = { registerAuthenticationPolicyTools };
