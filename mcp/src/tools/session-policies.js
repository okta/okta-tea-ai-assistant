'use strict';

const { z } = require('zod');
const { buildMcpOk, buildMcpError, buildMcpOffline, buildMcpReadOnly } = require('./resolver-utils');
const { createOktaClient } = require('../auth/okta-client');

const GLOBAL_SESSION_POLICY_TYPE = 'OKTA_SIGN_ON';

// NIST SP 800-63B / Okta TEA recommendations
const MAX_SESSION_LIFETIME_MINUTES_RECOMMENDED = 720;  // 12 hours (AAL2)

// Mirrors SessionIdleTimeIsShort in the TEA analyzer: threshold is inferred from the policy name.
function inferAssuranceLevel(policyName) {
  const name = (policyName || '').toLowerCase();
  const aal3 = ['high risk', 'highrisk', 'high_risk', 'high', 'aal3'];
  const aal2 = ['medium risk', 'moderate risk', 'mediumrisk', 'moderaterisk', 'medium', 'moderate', 'aal2'];
  if (aal3.some((k) => name.includes(k))) return 'AAL3';
  if (aal2.some((k) => name.includes(k))) return 'AAL2';
  return 'AAL1';
}

function idleThresholdMinutes(policyName) {
  const aal = inferAssuranceLevel(policyName);
  if (aal === 'AAL3') return 15;
  if (aal === 'AAL2') return 30;
  return 120; // AAL1 default
}

// ── Audit helpers ──────────────────────────────────────────────────────────────

function auditSessionPolicyRule(policyName, rule) {
  const signon = rule.actions?.signon || {};
  const session = signon.session || {};
  const findings = [];

  // MFA not required at global session level
  if (signon.requireFactor === false || signon.requireFactor === undefined) {
    findings.push({
      id: 'MFA_NOT_REQUIRED',
      severity: 'HIGH',
      description: `Rule "${rule.name}" in policy "${policyName}" does not require MFA — vulnerable to credential stuffing.`,
      recommendation: 'Set requireFactor to true.',
    });
  }

  // session lifetime too long or unlimited
  const lifetime = session.maxSessionLifetimeMinutes ?? 0;
  if (lifetime === 0 || lifetime > MAX_SESSION_LIFETIME_MINUTES_RECOMMENDED) {
    findings.push({
      id: 'SESSION_LIFETIME',
      severity: 'HIGH',
      description: `Rule "${rule.name}" session lifetime is ${lifetime === 0 ? 'unlimited' : `${lifetime} minutes`} — should be ≤ ${MAX_SESSION_LIFETIME_MINUTES_RECOMMENDED} minutes (NIST SP 800-63B).`,
      recommendation: `Set maxSessionLifetimeMinutes to ${MAX_SESSION_LIFETIME_MINUTES_RECOMMENDED}.`,
      current: lifetime,
      recommended: MAX_SESSION_LIFETIME_MINUTES_RECOMMENDED,
    });
  }

  // idle timeout too long — threshold varies by NIST AAL inferred from policy name
  const idleThreshold = idleThresholdMinutes(policyName);
  const idle = session.maxSessionIdleMinutes ?? 0;
  if (idle === 0 || idle > idleThreshold) {
    findings.push({
      id: 'SESSION_IDLE',
      severity: 'MODERATE',
      description: `Rule "${rule.name}" idle timeout is ${idle === 0 ? 'not set' : `${idle} minutes`} — should be ≤ ${idleThreshold} minutes (NIST ${inferAssuranceLevel(policyName)}).`,
      recommendation: `Set maxSessionIdleMinutes to ${idleThreshold}.`,
      current: idle,
      recommended: idleThreshold,
    });
  }

  return {
    policyName,
    policyId: rule._policyId,
    ruleId: rule.id,
    ruleName: rule.name,
    rulePriority: rule.priority,
    findingCount: findings.length,
    highCount: findings.filter((f) => f.severity === 'HIGH').length,
    findings,
    current: {
      requireFactor: signon.requireFactor,
      factorPromptMode: signon.factorPromptMode,
      access: signon.access,
      maxSessionLifetimeMinutes: lifetime,
      maxSessionIdleMinutes: idle,
      usePersistentCookie: session.usePersistentCookie,
    },
  };
}

async function fetchPoliciesWithRules(client) {
  const { data: policies } = await client.get('/api/v1/policies', {
    params: { type: GLOBAL_SESSION_POLICY_TYPE },
  });

  const results = [];
  for (const policy of policies) {
    const { data: rules } = await client.get(`/api/v1/policies/${policy.id}/rules`);
    for (const rule of rules) {
      rule._policyId = policy.id;
    }
    results.push({ policy, rules });
  }
  return results;
}

// ── Terraform builder ──────────────────────────────────────────────────────────

function buildSessionPolicyTerraform(policy, rule) {
  const signon = rule.actions?.signon || {};
  const session = signon.session || {};

  const policyLabel = policy.name
    .toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_+|_+$/g, '') || 'session_policy';
  const ruleLabel = rule.name
    .toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_+|_+$/g, '') || 'session_rule';

  return `# Terraform — Okta Global Session Policy (TEA hardening)
#
# Provider setup:
#   https://developer.okta.com/docs/guides/terraform-enable-org-access/main/
# Resource reference:
#   https://registry.terraform.io/providers/okta/okta/latest/docs/resources/policy_signon
#   https://registry.terraform.io/providers/okta/okta/latest/docs/resources/policy_rule_signon

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
resource "okta_policy_signon" "${policyLabel}" {
  name   = "${policy.name}"
  status = "${policy.status || 'ACTIVE'}"
}

# Rule ID: ${rule.id}
resource "okta_policy_rule_signon" "${ruleLabel}" {
  policy_id = okta_policy_signon.${policyLabel}.id
  name      = "${rule.name}"
  status    = "${rule.status || 'ACTIVE'}"
  priority  = ${rule.priority ?? 1}

  # TEA Finding — require MFA
  require_factor  = ${signon.requireFactor ?? true}
  factor_sequence = "${signon.factorPromptMode || 'ALWAYS'}"

  # TEA Finding — cap session lifetime (≤ 720 min, NIST SP 800-63B AAL2)
  session_lifetime   = ${session.maxSessionLifetimeMinutes ?? MAX_SESSION_LIFETIME_MINUTES_RECOMMENDED}
  session_persistent = ${session.usePersistentCookie ?? false}

  # TEA Finding — idle timeout (≤ ${idleThresholdMinutes(policy.name)} min, NIST ${inferAssuranceLevel(policy.name)})
  session_idle = ${session.maxSessionIdleMinutes ?? idleThresholdMinutes(policy.name)}
}
`;
}

// ── Log queries ────────────────────────────────────────────────────────────────

function buildSessionPolicyLogQueries() {
  return [
    {
      description: 'Sign-on policy rule changes — audit trail',
      filter: 'eventType eq "policy.rule.update"',
      timeWindow: 'last 90 days',
      note: 'Tracks who changed global session policy rules and when.',
    },
    {
      description: 'Session starts — verify new sessions respect lifetime limits',
      filter: 'eventType eq "user.session.start"',
      timeWindow: 'last 7 days',
      note: 'After reducing session lifetime, verify new sessions start and expire correctly.',
    },
    {
      description: 'Session expiry events',
      filter: 'eventType eq "user.session.expire"',
      timeWindow: 'last 7 days',
      note: 'Confirms sessions are expiring per the new lifetime/idle settings.',
    },
    {
      description: 'MFA verification events — confirm MFA is being enforced',
      filter: 'eventType eq "user.authentication.auth_via_mfa"',
      timeWindow: 'last 7 days',
      note: 'After enabling requireFactor, MFA events should appear for all sign-ins covered by this policy.',
    },
    {
      description: 'Sign-on policy evaluations',
      filter: 'eventType eq "policy.evaluate_sign_on"',
      timeWindow: 'last 24 hours',
      note: 'Confirms which policy rules are being evaluated per sign-in attempt.',
    },
  ];
}

// ── Admin console steps ────────────────────────────────────────────────────────

function buildSessionPolicyAdminSteps(policyName, ruleName) {
  const idleThreshold = idleThresholdMinutes(policyName);
  const aal = inferAssuranceLevel(policyName);
  return [
    'Sign in to the Okta Admin Console.',
    'Go to Security > Global Session Policy.',
    `Click the policy named "${policyName}".`,
    `Find the rule named "${ruleName}" and click the pencil/edit icon.`,
    'In the rule editor:',
    '  • Set "User must authenticate with" to "Password + Another factor".',
    '  • Under "Session expires after", set to 720 minutes (12 hours).',
    `  • Under "Expire session if idle after", set to ${idleThreshold} minutes (NIST ${aal}).`,
    'Click Save.',
    'Verify changes in Reports > System Log: filter eventType eq "policy.rule.update".',
  ];
}

// ── Risk assessment ────────────────────────────────────────────────────────────

function buildSessionPolicyRiskAssessment() {
  return {
    teaSeverity: 'MODERATE',
    changeRisk:  'MODERATE',
    summary:
      'Reducing session lifetimes and requiring MFA at the global session level are ' +
      'critical defences against session theft (T1539) and credential stuffing (T1110). ' +
      'These changes have moderate user impact — users will need to re-authenticate more frequently. ' +
      'Critical enforcement gap: global session policy settings are disabled for users who ' +
      'authenticate via the Okta LDAP interface — those users bypass global session management entirely.',
    preChangeChecks: [
      'Run an MFA enrollment report (Reports > Reports) — any user without an enrolled factor will be locked out when requireFactor is enabled.',
      'Determine if the LDAP interface is in use (Security > API > LDAP Interface) — LDAP-authenticated users bypass global session policy entirely.',
      'Identify applications that rely on persistent or long-lived sessions (e.g. background sync jobs, always-on dashboard apps).',
      'Check if any service accounts authenticate via the Okta sign-on flow — they will be subject to MFA requirements.',
    ],
    blastRadius:
      'Session lifetime changes do not immediately terminate active sessions — ' +
      'existing sessions expire at the new limit on the next access attempt. There is no immediate forced sign-out. ' +
      'Applications that rely on persistent sessions will require re-login once the shorter window is reached. ' +
      'LDAP-authenticated users are completely unaffected by global session policy — ' +
      'if LDAP interface is in use, session controls must be enforced at the directory level separately. ' +
      'Users without an enrolled MFA factor will be locked out if requireFactor is enabled — ' +
      'always check enrollment coverage before enabling MFA.',
    rolloutSteps: [
      'Step 1 — Check MFA enrollment coverage (Reports > Reports) — do not enable requireFactor if any users have no factor.',
      'Step 2 — Determine if the LDAP interface is in use (Security > API > LDAP Interface).',
      'Step 3 — Update session lifetime to 720 minutes.',
      'Step 4 — Update idle timeout to 120 minutes.',
      'Step 5 — Enable requireFactor last to avoid lockouts.',
      'Step 6 — Monitor System Log for session expire events and MFA prompts (see postChangeMonitoring queries).',
      'Step 7 — If LDAP interface is active, enforce equivalent session controls at the directory level.',
    ],
    postChangeMonitoring: {
      description:
        'After tightening session policies, monitor for unexpected user lockouts and verify MFA prompts ' +
        'are appearing correctly. Watch for a spike in help desk calls about re-authentication frequency.',
      logQueries: [
        {
          description: 'Session expirations triggered by the new lifetime limit',
          filter: 'eventType eq "user.session.expire"',
          timeWindow: 'first 48 hours post-change',
          note: 'Volume increase is expected and correct. A very high volume in off-hours may indicate session lifetime was set too aggressively.',
        },
        {
          description: 'MFA challenges at sign-in (confirms requireFactor is working)',
          filter: 'eventType eq "user.authentication.auth_via_mfa"',
          timeWindow: 'first 48 hours post-change',
          note: 'Should increase after enabling requireFactor. If no increase, verify the policy rule was saved correctly.',
        },
        {
          description: 'Sign-in denials (could indicate lockout of users without MFA)',
          filter: 'eventType eq "user.session.start" AND outcome.result eq "DENY"',
          timeWindow: 'first 24 hours post-change',
          note: 'A spike here after enabling requireFactor means users lack an enrolled factor — check enrollment report and assist affected users.',
        },
      ],
    },
    rollback:
      'Policy rule changes are immediately reversible. Reverting to longer session lifetimes ' +
      'or removing MFA requirements takes effect immediately for new sign-ins. ' +
      'Active sessions that have not yet hit the old window continue uninterrupted.',
  };
}

// ── Tool registration ─────────────────────────────────────────────────────────

function registerSessionPolicyTools(server) {
  server.tool(
    'okta_list_session_policies',
    'List all Okta Global Session Policies (type OKTA_SIGN_ON) with a TEA-aligned ' +
    'security audit of every rule. Flags rules that: do not require MFA, ' +
    'have session lifetimes > 720 minutes or unlimited, and have idle timeouts ' +
    'exceeding the NIST AAL threshold inferred from the policy name ' +
    '(AAL1=120 min, AAL2=30 min, AAL3=15 min). Returns a compliance table by policy and ' +
    'rule, Terraform HCL, and remediation guidance.',
    {},
    async () => {
      if (process.env.OFFLINE_MODE === 'true') {
        const defaultPolicy = { id: '<POLICY_ID>', name: 'Default Policy', status: 'ACTIVE' };
        const defaultRule = { id: '<RULE_ID>', name: 'Default Rule', actions: { signon: { session: {} } } };
        return buildMcpOffline({
          remediation: {
            terraform:         buildSessionPolicyTerraform(defaultPolicy, defaultRule),
            logQueries:        buildSessionPolicyLogQueries(),
            adminConsoleSteps: buildSessionPolicyAdminSteps('Default Policy', 'Default Rule'),
            riskAssessment:    buildSessionPolicyRiskAssessment(),
          },
        });
      }
      try {
        const client = await createOktaClient();
        const policiesWithRules = await fetchPoliciesWithRules(client);

        const allRuleAudits = [];
        for (const { policy, rules } of policiesWithRules) {
          for (const rule of rules) {
            allRuleAudits.push(auditSessionPolicyRule(policy.name, rule));
          }
        }

        const totalFindings = allRuleAudits.reduce((n, r) => n + r.findingCount, 0);
        const highFindings = allRuleAudits.reduce((n, r) => n + r.highCount, 0);

        const firstPolicyWithRules = policiesWithRules[0];
        let terraform = null;
        if (firstPolicyWithRules && firstPolicyWithRules.rules.length > 0) {
          terraform = buildSessionPolicyTerraform(
            firstPolicyWithRules.policy,
            firstPolicyWithRules.rules[0],
          );
        }

        return buildMcpOk({
          summary: {
            totalPolicies: policiesWithRules.length,
            totalRules: allRuleAudits.length,
            totalFindings,
            highFindings,
            rulesWithHighFindings: allRuleAudits.filter((r) => r.highCount > 0).length,
          },
          rules: allRuleAudits,
          remediation: {
            terraform,
            logQueries: buildSessionPolicyLogQueries(),
            adminConsoleSteps: buildSessionPolicyAdminSteps('<policy name>', '<rule name>'),
            riskAssessment: buildSessionPolicyRiskAssessment(),
          },
        });
      } catch (err) {
        return buildMcpError(err);
      }
    },
  );

  server.tool(
    'okta_update_session_policy_rule',
    'Update a Global Session Policy rule to address TEA security findings. ' +
    'Patches only the fields you provide. Addresses: requireFactor, ' +
    'maxSessionLifetimeMinutes, and maxSessionIdleMinutes. ' +
    'Write operation — confirm with the admin before calling.',
    {
      policyId: z.string().describe('Global Session Policy ID (from okta_list_session_policies).'),
      ruleId: z.string().describe('Policy rule ID to update.'),
      requireFactor: z.boolean().optional()
        .describe('Require MFA for all sign-ins under this rule.'),
      factorPromptMode: z.enum(['ALWAYS', 'DEVICE', 'SESSION']).optional()
        .describe('When to prompt for MFA: ALWAYS, DEVICE (once per device), or SESSION (once per session).'),
      maxSessionLifetimeMinutes: z.number().int().min(0).optional()
        .describe('Max session lifetime in minutes. 0 = unlimited (not recommended). TEA recommendation: 720.'),
      maxSessionIdleMinutes: z.number().int().min(0).optional()
        .describe('Max idle time in minutes before session expires. TEA recommendation: 120 (AAL1 default), 30 (AAL2), 15 (AAL3) — inferred from policy name.'),
      usePersistentCookie: z.boolean().optional()
        .describe('Allow persistent session cookie. Disable for higher-security policies.'),
    },
    async ({
      policyId,
      ruleId,
      requireFactor,
      factorPromptMode,
      maxSessionLifetimeMinutes,
      maxSessionIdleMinutes,
      usePersistentCookie,
    }) => {
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

        if (policy.type !== GLOBAL_SESSION_POLICY_TYPE) {
          return buildMcpError(new Error(
            `Policy "${policyId}" is type "${policy.type}", not ${GLOBAL_SESSION_POLICY_TYPE}. ` +
            'Use okta_list_session_policies to find valid policy IDs.',
          ));
        }

        const updated = JSON.parse(JSON.stringify(rule));
        const signon = (updated.actions = updated.actions || {}).signon = (updated.actions?.signon || {});
        const session = (signon.session = signon.session || {});

        if (requireFactor !== undefined) { signon.requireFactor = requireFactor; }
        if (factorPromptMode !== undefined) { signon.factorPromptMode = factorPromptMode; }
        if (maxSessionLifetimeMinutes !== undefined) { session.maxSessionLifetimeMinutes = maxSessionLifetimeMinutes; }
        if (maxSessionIdleMinutes !== undefined) { session.maxSessionIdleMinutes = maxSessionIdleMinutes; }
        if (usePersistentCookie !== undefined) { session.usePersistentCookie = usePersistentCookie; }

        const { data: savedRule } = await client.put(
          `/api/v1/policies/${policyId}/rules/${ruleId}`,
          updated,
        );

        rule._policyId = policyId;
        savedRule._policyId = policyId;

        const auditBefore = auditSessionPolicyRule(policy.name, rule);
        const auditAfter = auditSessionPolicyRule(policy.name, savedRule);

        const appliedChanges = {};
        if (requireFactor !== undefined) { appliedChanges.requireFactor = requireFactor; }
        if (factorPromptMode !== undefined) { appliedChanges.factorPromptMode = factorPromptMode; }
        if (maxSessionLifetimeMinutes !== undefined) { appliedChanges.maxSessionLifetimeMinutes = maxSessionLifetimeMinutes; }
        if (maxSessionIdleMinutes !== undefined) { appliedChanges.maxSessionIdleMinutes = maxSessionIdleMinutes; }
        if (usePersistentCookie !== undefined) { appliedChanges.usePersistentCookie = usePersistentCookie; }

        return buildMcpOk({
          message: `Session policy rule "${savedRule.name}" in policy "${policy.name}" updated.`,
          policyId,
          ruleId,
          appliedChanges,
          findingsBefore: auditBefore.findingCount,
          findingsAfter: auditAfter.findingCount,
          remainingFindings: auditAfter.findings,
          remediation: {
            terraform: buildSessionPolicyTerraform(policy, savedRule),
            logQueries: buildSessionPolicyLogQueries(),
            adminConsoleSteps: buildSessionPolicyAdminSteps(policy.name, savedRule.name),
            riskAssessment: buildSessionPolicyRiskAssessment(),
          },
        });
      } catch (err) {
        return buildMcpError(err);
      }
    },
  );
}

module.exports = {
  registerSessionPolicyTools,
  auditSessionPolicyRule,
  buildSessionPolicyTerraform,
  buildSessionPolicyLogQueries,
  buildSessionPolicyRiskAssessment,
};
