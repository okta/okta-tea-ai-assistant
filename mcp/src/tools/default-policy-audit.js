'use strict';

const { buildMcpOk, buildMcpError, buildMcpOffline } = require('./resolver-utils');
const { createOktaClient } = require('../auth/okta-client');

// Policy types to check for default names
const POLICY_TYPES = [
  'OKTA_SIGN_ON',
  'PASSWORD',
  'ACCESS_POLICY',
  'MFA_ENROLL',
  'PROFILE_ENROLLMENT',
];

// ── Fetchers ───────────────────────────────────────────────────────────────────

async function fetchPoliciesByType(client, type) {
  try {
    const { data } = await client.get(`/api/v1/policies?type=${type}`);
    return Array.isArray(data) ? data.map((p) => ({ ...p, policyType: type })) : [];
  } catch (err) {
    const status = err.response?.status;
    // 404 is expected for policy types not available on the tenant
    if (status === 404 || status === 403) {
      return [];
    }
    return [];
  }
}

// ── Audit ──────────────────────────────────────────────────────────────────────

function isDefaultName(name) {
  if (!name) return false;
  const lower = name.toLowerCase().trim();
  return (
    lower === 'default' ||
    lower === 'default policy' ||
    lower === 'default sign on policy' ||
    lower === 'default password policy' ||
    lower.startsWith('default ') ||
    lower.endsWith(' default') ||
    lower.includes('default policy')
  );
}

function auditDefaultPolicies(allPolicies) {
  const findings = [];
  const flaggedPolicies = [];

  for (const policy of allPolicies) {
    if (!isDefaultName(policy.name)) continue;

    findings.push({
      id: 'DEFAULT_POLICY_NAME',
      severity: 'LOW',
      description:
        `Policy "${policy.name}" (type: ${policy.policyType}, status: ${policy.status}) ` +
        'still uses a default Okta policy name. Default-named policies are difficult to ' +
        'distinguish from custom policies during audits and incident response. ' +
        'They should be renamed to reflect their purpose and scope.',
      recommendation:
        `Rename "${policy.name}" to a descriptive name that reflects its purpose ` +
        '(e.g. "Corporate Employees — Sign On Policy" instead of "Default Sign On Policy"). ' +
        'You can also review whether the policy\'s rules align with your current security requirements.',
      policyId: policy.id,
      policyType: policy.policyType,
    });

    flaggedPolicies.push({
      id: policy.id,
      name: policy.name,
      type: policy.policyType,
      status: policy.status,
    });
  }

  return { findings, flaggedPolicies };
}

// ── Terraform ──────────────────────────────────────────────────────────────────

function buildDefaultPolicyTerraform() {
  return `# Terraform — Rename Default Okta Policies
#
# Provider setup:
#   https://developer.okta.com/docs/guides/terraform-enable-org-access/main/
# Resource references:
#   https://registry.terraform.io/providers/okta/okta/latest/docs/resources/policy_signon
#   https://registry.terraform.io/providers/okta/okta/latest/docs/resources/policy_password

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

# Rename a default sign-on policy
resource "okta_policy_signon" "corporate_signon" {
  name        = "Corporate Employees — Sign On Policy"   # Replace "Default Sign On Policy"
  description = "Global session policy for all employees"
  status      = "ACTIVE"
  priority    = 1
}

# Rename a default password policy
resource "okta_policy_password" "corporate_password" {
  name        = "Corporate Employees — Password Policy"  # Replace "Default Policy"
  description = "Password requirements for all employees"
  status      = "ACTIVE"
  priority    = 1

  password_min_length        = 15
  password_exclude_username  = true
  password_dictionary_lookup = true
}
`;
}

// ── Log queries ────────────────────────────────────────────────────────────────

function buildDefaultPolicyLogQueries() {
  return [
    {
      description: 'Policy rename events — audit trail',
      filter: 'eventType eq "policy.lifecycle.update"',
      timeWindow: 'last 90 days',
      note: 'Tracks policy configuration changes including name updates.',
    },
    {
      description: 'Policy evaluations — identify which policies are active',
      filter: 'eventType eq "policy.evaluate_sign_on"',
      timeWindow: 'last 7 days',
      note: 'Shows which sign-on policies are actively being evaluated — helps prioritise which default-named policies to address first.',
    },
  ];
}

// ── Admin console steps ────────────────────────────────────────────────────────

function buildDefaultPolicyAdminSteps() {
  return [
    'Sign in to the Okta Admin Console.',
    'For each flagged policy, navigate to its location:',
    '  • Sign-on policies: Security > Authentication > Sign On',
    '  • Password policies: Security > Authentication > Password',
    '  • App sign-on policies: Security > Authentication Policies',
    '  • MFA Enrollment policies: Security > Multifactor > Enrollment',
    '  • Profile Enrollment policies: Directory > Profile Editor > Profile Enrollment',
    'Click the policy name, then click "Edit" or "Rename".',
    'Update the name to clearly reflect:',
    '  • The target audience (e.g. "Corporate Employees", "Contractors", "Admins")',
    '  • The policy purpose (e.g. "Sign On Policy", "Password Requirements")',
    '  • Example: "All Employees — MFA Enrollment Policy"',
    'Click Save.',
    'Review the policy rules to ensure they still reflect current security requirements.',
  ];
}

// ── Risk assessment ────────────────────────────────────────────────────────────

function buildDefaultPolicyRiskAssessment() {
  return {
    teaSeverity: 'LOW',
    changeRisk:  'LOW',
    summary:
      'Default-named policies are a housekeeping risk rather than a direct security vulnerability. ' +
      'They complicate incident response and audits by making it hard to identify which policy ' +
      'applies to which users or applications. They often also indicate the policy has not been ' +
      'reviewed and tightened since initial Okta setup.',
    preChangeChecks: [
      'No prerequisites — renaming a policy is a zero-risk administrative change.',
      'Note the current policy name before renaming so you can identify it in System Log history.',
    ],
    blastRadius:
      'Renaming a policy has no impact on its behaviour — all rules and assignments are preserved. ' +
      'Some tenants legitimately keep "Default Policy" as a name for catch-all policies; ' +
      'confirm the rename will add clarity before proceeding.',
    rolloutSteps: [
      'Step 1 — Rename default sign-on and password policies (highest visibility).',
      'Step 2 — Rename authentication policies for apps covered by Appendix D.',
      'Step 3 — While renaming, review each policy\'s rules to catch stale configurations.',
    ],
    postChangeMonitoring: {
      description:
        'Renaming a policy has no security impact to monitor. Confirm the rename appears in System Log for audit purposes.',
      logQueries: [
        {
          description: 'Policy rename audit trail',
          filter: 'eventType eq "policy.lifecycle.update"',
          timeWindow: 'last 7 days',
          note: 'Confirms policy was renamed. Check displayMessage for the old and new policy names.',
        },
      ],
    },
    rollback:
      'Policy names can be changed back at any time. No functional impact from renaming.',
  };
}

// ── Tool registration ─────────────────────────────────────────────────────────

function registerDefaultPolicyAuditTools(server) {
  server.tool(
    'okta_audit_default_policies',
    'Audit all Okta policies for default names — checks sign-on, password, authentication, ' +
    'MFA enrollment, and profile enrollment policies for names containing "default". ' +
    'Default-named policies are difficult to distinguish during audits and incident response, ' +
    'and often indicate the policy has not been reviewed since initial tenant setup. ' +
    'Returns a list of flagged policies with rename guidance.',
    {},
    async () => {
      if (process.env.OFFLINE_MODE === 'true') {
        return buildMcpOffline({
          remediation: {
            terraform:         buildDefaultPolicyTerraform(),
            logQueries:        buildDefaultPolicyLogQueries(),
            adminConsoleSteps: buildDefaultPolicyAdminSteps(),
            riskAssessment:    buildDefaultPolicyRiskAssessment(),
          },
        });
      }
      try {
        const client = await createOktaClient();

        const allPolicies = (
          await Promise.all(POLICY_TYPES.map((type) => fetchPoliciesByType(client, type)))
        ).flat();

        const { findings, flaggedPolicies } = auditDefaultPolicies(allPolicies);

        return buildMcpOk({
          summary: {
            totalPoliciesScanned: allPolicies.length,
            findingCount: findings.length,
            flaggedPolicies: flaggedPolicies.length,
          },
          flaggedPolicies,
          findings,
          remediation: {
            terraform: buildDefaultPolicyTerraform(),
            logQueries: buildDefaultPolicyLogQueries(),
            adminConsoleSteps: buildDefaultPolicyAdminSteps(),
            riskAssessment: buildDefaultPolicyRiskAssessment(),
          },
        });
      } catch (err) {
        return buildMcpError(err);
      }
    },
  );
}

module.exports = { registerDefaultPolicyAuditTools };
