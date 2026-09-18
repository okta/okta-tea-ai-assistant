'use strict';

const { z } = require('zod');
const { buildMcpOk, buildMcpError, buildMcpOffline, buildMcpReadOnly } = require('./resolver-utils');
const { createOktaClient } = require('../auth/okta-client');

const POLICY_TYPE = 'ACCESS_POLICY';

// Name patterns to match the Account Management Policy across tenant naming conventions
const ACCOUNT_MGMT_POLICY_PATTERNS = [
  'account management',
  'account management policy',
  'self-service',
  'self service',
];

// ── Audit helpers ──────────────────────────────────────────────────────────────

function hasPossessionConstraint(constraints) {
  return Array.isArray(constraints) && constraints.some((c) => c.possession !== undefined);
}

function hasPhishingResistantConstraint(constraints) {
  return Array.isArray(constraints) &&
    constraints.some(
      (c) => c.possession?.phishingResistant === true || c.possession?.phishingResistant === 'REQUIRED',
    );
}

function auditAccountMgmtRule(policyName, rule) {
  const appSignOn = rule.actions?.appSignOn || {};
  const vm = appSignOn.verificationMethod || {};
  const constraints = vm.constraints || [];
  const findings = [];

  const possessionPresent = hasPossessionConstraint(constraints);
  const phishingResistantPresent = hasPhishingResistantConstraint(constraints);

  //  — no possession factor at all
  if (!possessionPresent) {
    findings.push({
      id: 'ACCOUNT_MGMT_NO_POSSESSION',
      severity: 'HIGH',
      description:
        `Rule "${rule.name}" in policy "${policyName}" does not require a possession factor ` +
        `for self-service password reset and recovery — an attacker who controls the user's ` +
        `email or phone can fully take over the account via self-service recovery alone.`,
      recommendation:
        'Add a possession constraint with phishingResistant: true to require Okta Verify or WebAuthn.',
    });
  } else if (!phishingResistantPresent) {
    // Has possession but not phishing-resistant (e.g. SMS OTP, push without number challenge)
    findings.push({
      id: 'ACCOUNT_MGMT_NON_PHISHING_RESISTANT_POSSESSION',
      severity: 'HIGH',
      description:
        `Rule "${rule.name}" requires a possession factor but not a phishing-resistant one ` +
        `(phishingResistant is false or absent). SMS OTP and basic push are susceptible to ` +
        `SIM-swap and MFA fatigue attacks, which are not mitigated by possession alone.`,
      recommendation:
        'Set possession.phishingResistant to true — restricts recovery to Okta Verify ' +
        '(biometric or number challenge) or WebAuthn / FIDO2 security key.',
    });
  }

  return {
    policyId: rule._policyId,
    policyName,
    ruleId: rule.id,
    ruleName: rule.name,
    rulePriority: rule.priority,
    findingCount: findings.length,
    findings,
    current: {
      access: appSignOn.access,
      factorMode: vm.factorMode ?? null,
      possessionPresent,
      phishingResistantPresent,
      constraints,
    },
  };
}

// ── Policy discovery ───────────────────────────────────────────────────────────
//
// Queries all ACCESS_POLICY type policies and matches by name pattern.
// The Account Management Policy is consistently named in OIE tenants and this
// approach avoids the need for a dedicated app ID lookup.

async function discoverAccountMgmtPolicy(client) {
  const diagnostics = { errors: [] };

  try {
    const { data: allPolicies } = await client.get('/api/v1/policies', {
      params: { type: POLICY_TYPE, limit: 200 },
    });

    const match = allPolicies.find((p) => {
      const name = (p.name || '').toLowerCase();
      return ACCOUNT_MGMT_POLICY_PATTERNS.some((pat) => name.includes(pat));
    });

    if (match) {
      return { policy: match, diagnostics };
    }

    diagnostics.errors.push(
      `Policies API returned ${allPolicies.length} ${POLICY_TYPE} policies — none matched ` +
      `patterns: ${ACCOUNT_MGMT_POLICY_PATTERNS.join(', ')}. ` +
      `Policy names found: ${allPolicies.map((p) => `"${p.name}"`).join(', ')}`,
    );
  } catch (err) {
    const detail = err.response?.data ? JSON.stringify(err.response.data) : err.message;
    diagnostics.errors.push(`Policies API failed: ${detail}`);
  }

  return { policy: null, diagnostics };
}

// ── Terraform builder ──────────────────────────────────────────────────────────

function buildAccountMgmtTerraform(policy, ruleAudits) {
  const policyLabel = (policy.name || 'account_management_policy')
    .toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_+|_+$/g, '');

  const rulesHcl = ruleAudits.map((r) => {
    const ruleLabel = r.ruleName
      .toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_+|_+$/g, '');
    return `# Rule ID: ${r.ruleId}
resource "okta_app_signon_policy_rule" "${ruleLabel}_phishing_resistant" {
  policy_id   = okta_app_signon_policy.${policyLabel}.id
  name        = "${r.ruleName}"
  factor_mode = "1FA"
  status      = "ACTIVE"
  priority    = ${r.rulePriority}

  #  — phishing-resistant possession required for self-service recovery
  constraints = jsonencode([
    {
      possession = {
        required          = true
        phishingResistant = "REQUIRED"
        userPresence      = "OPTIONAL"
      }
    }
  ])
}`;
  }).join('\n\n');

  return `# Terraform — Okta Account Management Policy
#
# Restricts self-service password reset and recovery flows to phishing-resistant
# possession factors: Okta Verify (biometric / number challenge) or WebAuthn (FIDO2).
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

# Policy ID: ${policy.id}
resource "okta_app_signon_policy" "${policyLabel}" {
  name        = "${policy.name}"
  description = "Account Management Policy — phishing-resistant possession required"
}

${rulesHcl}
`;
}

// ── Log queries ────────────────────────────────────────────────────────────────

function buildAccountMgmtLogQueries() {
  return [
    {
      description: 'Self-service password reset attempts — verify possession factor required',
      filter: 'eventType eq "user.account.reset_password"',
      timeWindow: 'last 30 days',
      note: 'All password reset events. After enforcing possession, resets without a phishing-resistant factor should drop to zero.',
    },
    {
      description: 'Self-service account unlock events (token-based)',
      filter: 'eventType eq "user.account.unlock"',
      timeWindow: 'last 30 days',
      note: 'Self-service unlock; also for email token, search for eventType eq "system.email.account_unlock.sent_message". Check the authenticator context to confirm possession factors are being used.',
    },
    {
      description: 'Account Management Policy rule changes — audit trail',
      filter: 'eventType eq "policy.rule.update" OR eventType eq "policy.rule.add"',
      timeWindow: 'last 90 days',
      note: 'Tracks all modifications to the Account Management Policy rules and who made them.',
    },
    {
      description: 'WebAuthn (FIDO2) usage during recovery',
      filter: 'eventType eq "user.authentication.auth_via_mfa" AND debugContext.debugData.factor eq "FIDO_WEBAUTHN"',
      timeWindow: 'last 7 days',
      note: 'WebAuthn usage in account management flows — confirms phishing-resistant enrollment is available.',
    },
    {
      description: 'Okta Verify usage during recovery flows',
      filter: 'eventType eq "user.authentication.auth_via_mfa" AND debugContext.debugData.factor eq "OKTA_VERIFY"',
      timeWindow: 'last 7 days',
      note: 'Okta Verify usage in account management flows.',
    },
  ];
}

// ── Admin console steps ────────────────────────────────────────────────────────

function buildAccountMgmtAdminSteps(policyName) {
  return [
    'Sign in to the Okta Admin Console.',

    // ── Prerequisites ──────────────────────────────────────────────────────────
    '(Prerequisite 1) Activate recovery authenticators:',
    '  Go to Security → Authenticators.',
    '  Confirm Okta Verify and Security Key/Biometric (WebAuthn) show status "Active".',
    '  For Okta Verify: click Actions → Edit and confirm "Push notification" is enabled.',
    '  Recovery authenticators must be activated before the policy rule can be met.',

    '(Prerequisite 2) Require enrollment of at least two non-email authenticators:',
    '  Under Security → Authenticators, click the "Enrollment" tab.',
    '  Open your enrollment policy and set Okta Verify and/or WebAuthn to "Required".',
    '  Users who were never required to enroll these cannot satisfy the phishing-resistant rule.',

    // ── Account Management Policy ──────────────────────────────────────────────
    'Go to Security → Authentication Policies.',
    `Find the policy named "${policyName}" (the Okta Account Management Policy).`,
    'Click the policy name, then edit each rule that covers self-service password reset or recovery:',
    '  a. Click the rule name.',
    '  b. Under "Authentication methods", set the possession factor requirement to "Phishing-resistant".',
    '     — This restricts recovery to Okta Verify (biometric or number challenge) or WebAuthn/FIDO2.',
    '  c. Confirm recovery authenticators are not reused for additional verification in the same flow.',
    '     Recovery-only authenticators cannot serve as a second factor in the same sign-in — this',
    '     misconfiguration causes recovery to fail mid-flow without a clear error to the user.',
    '  d. Click Save.',

    // ── LDAP caveat ───────────────────────────────────────────────────────────
    'Note for LDAP-sourced accounts: self-service account unlock via Okta clears the Okta-side lock only.',
    '  The on-premises LDAP instance remains locked and must be unlocked separately by an admin.',

    // ── Verification ──────────────────────────────────────────────────────────
    'Verify via Reports → System Log: filter eventType eq "user.account.reset_password" and confirm',
    '  a phishing-resistant factor appears in the authentication context.',
  ];
}

// ── Risk assessment ────────────────────────────────────────────────────────────

function buildAccountMgmtRiskAssessment() {
  return {
    teaSeverity: 'HIGH',
    changeRisk:  'MODERATE',
    summary:
      'Requiring phishing-resistant possession factors for self-service password reset and account ' +
      'recovery closes a critical bypass path. Without this control, an attacker who has compromised ' +
      "a user's email or SIM (SIM-swap) can use self-service recovery to fully take over the account, " +
      'bypassing all other MFA controls that protect sign-in. ' +
      'The Okta Account Management Policy governs this phishing-resistant recovery path; ' +
      'the password policy self-service settings govern the non-phishing-resistant fallback.',
    preChangeChecks: [
      'Run a factor enrollment report (Directory > Reports > User Factor Enrollment) to check what fraction of users have Okta Verify or WebAuthn enrolled.',
      'Run okta_list_authenticators to confirm Okta Verify (with Push enabled) and WebAuthn are ACTIVE — activating the authenticator alone is not sufficient for Okta Verify.',
      'Confirm the authenticator enrollment policy requires at least two non-email authenticators — users who have never enrolled Okta Verify or WebAuthn cannot satisfy the recovery rule.',
      'Note: recovery authenticators must be distinct from everyday authentication authenticators — reusing a recovery-only authenticator as the second step in the same flow causes silent failure.',
      'For LDAP-sourced accounts: self-service account unlock via Okta clears only the Okta-side lock — the on-premises LDAP instance remains locked and must be unlocked separately.',
    ],
    blastRadius:
      'Users without Okta Verify or a FIDO2 security key enrolled will be unable to perform ' +
      'self-service recovery and will require admin-assisted resets. ' +
      'The blast radius is proportional to the fraction of users without the required factor enrolled. ' +
      'A large fraction of unenrolled users means a high help desk burden after enforcement.',
    rolloutSteps: [
      'Step 1 — Activate recovery authenticators: confirm Okta Verify (with Push enabled) and WebAuthn are active.',
      'Step 2 — Update the enrollment policy to require at least two non-email authenticators.',
      'Step 3 — Audit enrolled factors — check how many users have Okta Verify or WebAuthn enrolled.',
      'Step 4 — Run a targeted enrollment campaign for Okta Verify / WebAuthn.',
      'Step 5 — Enforce on pilot group (admin users, high-value accounts) first.',
      'Step 6 — Enforce org-wide once enrollment is sufficient.',
      'Step 7 — Monitor for admin-assisted reset volume (see postChangeMonitoring queries).',
    ],
    postChangeMonitoring: {
      description:
        'After enforcing phishing-resistant recovery, watch for a spike in admin-assisted password resets — ' +
        'this is the primary signal that users cannot complete self-service recovery.',
      logQueries: [
        {
          description: 'Admin-assisted password resets (proxy for self-service recovery failures)',
          filter: 'eventType eq "user.account.reset_password"',
          timeWindow: 'first 14 days post-change',
          note: 'An increase in admin-actor resets (actor.id != target.id) after enforcement means users cannot complete self-service recovery.',
        },
        {
          description: 'Self-service password reset attempts',
          filter: 'eventType eq "user.account.reset_password" AND actor.type eq "User"',
          timeWindow: 'first 14 days post-change',
          note: 'Self-service reset volume should remain stable or increase slightly as users with enrolled factors succeed.',
        },
        {
          description: 'Phishing-resistant factor enrollment events',
          filter: 'eventType eq "user.mfa.factor.activate" AND target.displayName co "Okta Verify"',
          timeWindow: 'first 30 days post-change',
          note: 'Rising enrollment means users are self-enrolling to meet the new recovery requirement.',
        },
      ],
    },
    rollback:
      'Policy rule changes are immediately reversible — remove the phishingResistant: true constraint ' +
      'to restore the prior possession requirement. Existing authenticated sessions are not affected.',
  };
}

// ── Tool registration ──────────────────────────────────────────────────────────

function registerAccountMgmtPolicyTools(server) {
  server.tool(
    'okta_list_account_management_policy',
    'Audit the Okta Account Management Policy for  — Account Management Policy ' +
    'Possession Factors. Checks whether self-service password reset and recovery rules require ' +
    'phishing-resistant possession factors (Okta Verify or WebAuthn/FIDO2). ' +
    'Without this control, an attacker who compromises a user\'s email or SIM can bypass ' +
    'MFA entirely via self-service recovery. Returns per-rule findings with severity, ' +
    'Terraform HCL, System Log queries, admin console remediation steps, and a risk assessment.',
    {},
    async () => {
      if (process.env.OFFLINE_MODE === 'true') {
        const policy    = { id: '<POLICY_ID>', name: 'Account Management Policy' };
        const ruleAudits = [{ ruleId: '<RULE_ID>', ruleName: 'Default Rule', rulePriority: 1 }];
        return buildMcpOffline({
          remediation: {
            terraform:         buildAccountMgmtTerraform(policy, ruleAudits),
            logQueries:        buildAccountMgmtLogQueries(),
            adminConsoleSteps: buildAccountMgmtAdminSteps('Account Management Policy'),
            riskAssessment:    buildAccountMgmtRiskAssessment(),
          },
        });
      }
      try {
        const client = await createOktaClient();
        const { policy, diagnostics } = await discoverAccountMgmtPolicy(client);

        if (!policy) {
          return buildMcpError(new Error(
            'Could not locate the Okta Account Management Policy. ' +
            `Queried all ${POLICY_TYPE} type policies but none matched ` +
            `patterns: ${ACCOUNT_MGMT_POLICY_PATTERNS.join(', ')}. ` +
            'diagnostics: ' + JSON.stringify(diagnostics, null, 2),
          ));
        }

        const { data: rules } = await client.get(`/api/v1/policies/${policy.id}/rules`);

        const ruleAudits = rules.map((rule) => {
          rule._policyId = policy.id;
          return auditAccountMgmtRule(policy.name, rule);
        });

        const totalFindings = ruleAudits.reduce((n, r) => n + r.findingCount, 0);
        const highFindings = ruleAudits.reduce((n, r) =>
          n + r.findings.filter((f) => f.severity === 'HIGH').length, 0);

        return buildMcpOk({
          summary: {
            policyId: policy.id,
            policyName: policy.name,
            totalRules: rules.length,
            totalFindings,
            highFindings,
            discoveryDiagnostics: diagnostics,
          },
          rules: ruleAudits,
          remediation: {
            terraform: buildAccountMgmtTerraform(policy, ruleAudits),
            logQueries: buildAccountMgmtLogQueries(),
            adminConsoleSteps: buildAccountMgmtAdminSteps(policy.name),
            riskAssessment: buildAccountMgmtRiskAssessment(),
          },
        });
      } catch (err) {
        return buildMcpError(err);
      }
    },
  );

  server.tool(
    'okta_update_account_management_policy_rule',
    'Update a rule in the Okta Account Management Policy to require phishing-resistant ' +
    'possession factors for self-service password reset and recovery. ' +
    'Get policyId and ruleId from okta_list_account_management_policy. ' +
    'Write operation — confirm with the admin before calling.',
    {
      policyId: z.string()
        .describe('Account Management Policy ID (from okta_list_account_management_policy).'),
      ruleId: z.string()
        .describe('Policy rule ID to update (from okta_list_account_management_policy).'),
      requirePhishingResistantPossession: z.boolean()
        .describe(
          'true: add a possession constraint with phishingResistant: true (Okta Verify or WebAuthn). ' +
          'false: remove the phishing-resistant constraint, reverting to no possession requirement.',
        ),
    },
    async ({ policyId, ruleId, requirePhishingResistantPossession }) => {
      if (process.env.OFFLINE_MODE === 'true') {
        return buildMcpOffline({ skipped: true, message: 'Write operations are not available in offline mode.' });
      }
      if (process.env.PROD_MODE === 'true') {
        return buildMcpReadOnly();
      }
      try {
        const client = await createOktaClient();

        const [{ data: policy }, { data: rule }] = await Promise.all([
          client.get(`/api/v1/policies/${policyId}`),
          client.get(`/api/v1/policies/${policyId}/rules/${ruleId}`),
        ]);

        if (policy.type !== POLICY_TYPE) {
          return buildMcpError(new Error(
            `Policy "${policyId}" is type "${policy.type}", not ${POLICY_TYPE}. ` +
            'Use okta_list_account_management_policy to get the correct IDs.',
          ));
        }

        const updated = JSON.parse(JSON.stringify(rule));
        if (!updated.actions) updated.actions = {};
        if (!updated.actions.appSignOn) updated.actions.appSignOn = {};
        if (!updated.actions.appSignOn.verificationMethod) {
          updated.actions.appSignOn.verificationMethod = {};
        }
        const vm = updated.actions.appSignOn.verificationMethod;

        // Okta requires verificationMethod.type to be set when constraints are present.
        // Rules without a pre-existing verificationMethod won't have this field.
        if (!vm.type) {
          vm.type = 'ASSURANCE';
        }

        if (requirePhishingResistantPossession) {
          // Replace/add possession constraint, leaving non-possession constraints in place.
          // phishingResistant must be the string "REQUIRED" (not boolean true) per the
          // Okta Account Management Policy API spec.
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
          // Remove phishing-resistant possession constraint only
          vm.constraints = (vm.constraints || []).filter(
            (c) => !(c.possession?.phishingResistant === true || c.possession?.phishingResistant === 'REQUIRED'),
          );
        }

        const { data: savedRule } = await client.put(
          `/api/v1/policies/${policyId}/rules/${ruleId}`,
          updated,
        );

        rule._policyId = policyId;
        savedRule._policyId = policyId;

        const auditBefore = auditAccountMgmtRule(policy.name, rule);
        const auditAfter = auditAccountMgmtRule(policy.name, savedRule);

        return buildMcpOk({
          message: `Account Management Policy rule "${savedRule.name}" updated in policy "${policy.name}".`,
          policyId,
          ruleId,
          appliedChanges: { requirePhishingResistantPossession },
          findingsBefore: auditBefore.findingCount,
          findingsAfter: auditAfter.findingCount,
          remainingFindings: auditAfter.findings,
          remediation: {
            terraform: buildAccountMgmtTerraform(policy, [auditAfter]),
            logQueries: buildAccountMgmtLogQueries(),
            adminConsoleSteps: buildAccountMgmtAdminSteps(policy.name),
            riskAssessment: buildAccountMgmtRiskAssessment(),
          },
        });
      } catch (err) {
        return buildMcpError(err);
      }
    },
  );
}

module.exports = {
  registerAccountMgmtPolicyTools,
  auditAccountMgmtRule,
  buildAccountMgmtTerraform,
  buildAccountMgmtLogQueries,
  buildAccountMgmtRiskAssessment,
};
