'use strict';

const { z } = require('zod');
const { buildMcpOk, buildMcpError, buildMcpOffline, buildMcpReadOnly } = require('./resolver-utils');
const { createOktaClient } = require('../auth/okta-client');

// POST_AUTH_SESSION is the current type (GA ~2024); CONTINUOUS_ACCESS is the deprecated alias
// retained by Okta for backward compatibility. Try the current name first.
const POLICY_TYPE_CURRENT = 'POST_AUTH_SESSION';
const POLICY_TYPE_LEGACY = 'CONTINUOUS_ACCESS';

// Feature flag name fragments to match against /api/v1/features
const ITP_UNIVERSAL_LOGOUT_FEATURE_NAMES = [
  'IDENTITY_THREAT_PROTECTION_UNIVERSAL_LOGOUT',
  'ITP_UNIVERSAL_LOGOUT',
  'UNIVERSAL_LOGOUT',
];

const ITP_WORKFLOWS_FEATURE_NAMES = [
  'IDENTITY_THREAT_PROTECTION_WORKFLOWS',
  'ITP_WORKFLOWS',
  'ITP_WORKFLOW_DETECTIONS',
];

// The session action level that satisfies the TEA recommendation for ITP Session Protection
const TERMINATE_SESSION_ACTION = 'TERMINATE_SESSION';
const TERMINATE_ACTION_VARIANTS = ['TERMINATE_SESSION', 'TERMINATE', 'KILL'];

// ── Fetchers ───────────────────────────────────────────────────────────────────

async function fetchContinuousAccessPolicies(client) {
  // Try the current policy type first; fall back to the deprecated alias for older tenants.
  for (const policyType of [POLICY_TYPE_CURRENT, POLICY_TYPE_LEGACY]) {
    try {
      const { data } = await client.get(`/api/v1/policies?type=${policyType}`);
      const policies = Array.isArray(data) ? data : [];
      // Okta returns an empty array (not 404) when ITP is not provisioned — treat
      // a non-empty result on either type as the authoritative source.
      if (policies.length > 0 || policyType === POLICY_TYPE_LEGACY) {
        return { available: true, policies, policyType };
      }
    } catch (err) {
      const status = err.response?.status;
      if (status === 404 || status === 403) {
        if (policyType === POLICY_TYPE_LEGACY) {
          return {
            available: false,
            reason: `API returned ${status} — ITP may not be provisioned or requires okta.policies.read scope.`,
          };
        }
        // 404 on current type — try legacy before giving up
        continue;
      }
      return { available: false, reason: err.message };
    }
  }
  return { available: true, policies: [], policyType: POLICY_TYPE_CURRENT };
}

async function fetchITPFeatures(client) {
  try {
    const { data } = await client.get('/api/v1/features');
    return { available: true, features: Array.isArray(data) ? data : [] };
  } catch (err) {
    return { available: false, reason: err.message, features: [] };
  }
}

async function fetchPolicyRules(client, policyId) {
  const { data } = await client.get(`/api/v1/policies/${policyId}/rules`);
  return Array.isArray(data) ? data : [];
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function matchFeature(features, nameList) {
  return features.find((f) =>
    nameList.some((n) => f.name?.toUpperCase().includes(n) || f.id?.toUpperCase().includes(n))
  ) || null;
}

function ruleActionIsTerminate(rule) {
  const action =
    rule.actions?.sessionAccess?.action ||
    rule.actions?.signon?.access ||
    rule.actions?.continuousAccess?.action ||
    '';
  return TERMINATE_ACTION_VARIANTS.some((v) => action.toUpperCase().includes(v));
}

// ── Audit ─────────────────────────────────────────────────────────────────────

function auditSessionProtection(policies) {
  if (!policies || policies.length === 0) {
    return {
      configured: false,
      canTerminateSessions: false,
      finding: {
        id: 'ITP_SESSION_PROTECTION_NOT_CONFIGURED',
        severity: 'MODERATE',
        description:
          'No Continuous Access Evaluation / ITP Session Protection policies were found. ' +
          'ITP Session Protection is not configured on this tenant.',
        recommendation:
          'Enable ITP Session Protection under Security > Identity Threat Protection > Session Protection ' +
          'and set the HIGH risk action to "Terminate Session".',
      },
    };
  }

  const allRules = policies.flatMap((p) =>
    (p.rules || []).map((r) => ({ ...r, policyId: p.id, policyName: p.name }))
  );
  const terminateRules = allRules.filter(ruleActionIsTerminate);

  if (terminateRules.length === 0) {
    return {
      configured: true,
      canTerminateSessions: false,
      finding: {
        id: 'ITP_SESSION_PROTECTION_NO_TERMINATE_ACTION',
        severity: 'MODERATE',
        description:
          'ITP Session Protection is configured but no rules are set to TERMINATE_SESSION on ' +
          'high-risk activity. Suspicious sessions will not be automatically terminated — ' +
          'an attacker who has hijacked a session retains access until the token expires.',
        recommendation:
          'Update ITP Session Protection rules: set the HIGH risk condition action to ' +
          '"Terminate Session", and MEDIUM risk to "Reauthenticate" at minimum.',
      },
      policies: policies.map((p) => ({ id: p.id, name: p.name, status: p.status, ruleCount: (p.rules || []).length })),
    };
  }

  return {
    configured: true,
    canTerminateSessions: true,
    finding: null,
    policies: policies.map((p) => ({ id: p.id, name: p.name, status: p.status, ruleCount: (p.rules || []).length })),
  };
}

// ── Terraform ─────────────────────────────────────────────────────────────────

function buildITPTerraform() {
  return `# Terraform — Identity Threat Protection (ITP)
#
# NOTE: Continuous Access Evaluation policies may not be fully supported by the
# Terraform Okta provider yet. Check current provider docs:
#   https://registry.terraform.io/providers/okta/okta/latest/docs
#
# Manual paths:
#   Session Protection : Security > Identity Threat Protection > Session Protection
#   Universal Logout   : Security > Identity Threat Protection > Universal Logout
#   Workflows          : Workflows Console > New Flow (ITP trigger)

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
  scopes      = ["okta.policies.manage", "okta.orgs.manage"]
  private_key = "<PATH_OR_CONTENT_OF_PRIVATE_KEY>"
}

# If your provider version supports continuous access evaluation policies:
# resource "okta_policy_continuous_access_evaluation" "itp_session_protection" {
#   name   = "ITP Session Protection"
#   status = "ACTIVE"
#
#   rules {
#     name   = "High Risk - Terminate Session"
#     status = "ACTIVE"
#     conditions {
#       risk_score = "HIGH"
#     }
#     actions {
#       session_access = "TERMINATE_SESSION"
#     }
#   }
#
#   rules {
#     name   = "Medium Risk - Reauthenticate"
#     status = "ACTIVE"
#     conditions {
#       risk_score = "MEDIUM"
#     }
#     actions {
#       session_access = "REAUTHENTICATE"
#     }
#   }
# }
`;
}

// ── Log queries ───────────────────────────────────────────────────────────────

function buildITPLogQueries() {
  return [
    {
      description: 'Entity Risk Detections',
      filter: 'eventType eq "user.risk.detect"',
      timeWindow: 'last 30 days',
      note: 'Fires when Okta ITP detects elevated entity risk for a user. Baseline signal for all ITP-driven actions.',
    },
    {
      description: 'Entity Risk Policy Actions',
      filter: 'eventType eq "policy.entity_risk.action"',
      timeWindow: 'last 30 days',
      note: 'Records the policy action taken in response to an entity risk detection (e.g. reauthenticate, terminate).',
    },
    {
      description: 'Session Context Changes (mid-session shifts)',
      filter: 'eventType eq "user.session.context.change"',
      timeWindow: 'last 30 days',
      note: 'Mid-session changes to IP, device, or network context that ITP uses as risk signals (T1539, T1557).',
    },
    {
      description: 'Continuous Session Violations',
      filter: 'eventType eq "policy.auth_reevaluate.fail"',
      timeWindow: 'last 30 days',
      note: 'Sessions that failed continuous access re-evaluation — attacker or compromised-device activity indicator.',
    },
    {
      description: 'ITP Terminated Sessions',
      filter: 'eventType eq "policy.auth_reevaluate.action" and debugContext.debugData.RuleAction eq "TERMINATE_SESSION"',
      timeWindow: 'last 30 days',
      note: 'Sessions explicitly terminated by an ITP Session Protection rule. Monitor volume for false-positive impact on users.',
    },
    {
      description: 'Universal Logout Events',
      filter: 'eventType eq "user.authentication.universal_logout"',
      timeWindow: 'last 7 days',
      note: 'Cross-app session terminations triggered by Universal Logout. Verify after enabling Universal Logout.',
    },
    {
      description: 'Admin ITP Feedback Submitted',
      filter: 'eventType eq "analytics.feedback.provide"',
      timeWindow: 'last 30 days',
      note: 'Admin-submitted feedback on ITP detections — confirms the SOC is actively reviewing and tuning signals.',
    },
    {
      description: 'Shared Signals (SSF) Ingested',
      filter: 'eventType eq "security.events.provider.receive_event"',
      timeWindow: 'last 7 days',
      note: 'Events received from external Shared Signals Framework providers (e.g. CrowdStrike, Microsoft). Confirms SSF pipeline is active.',
    },
  ];
}

// ── Admin console steps ───────────────────────────────────────────────────────

function buildSessionProtectionAdminSteps() {
  return [
    'Sign in to the Okta Admin Console.',
    'Go to Security > Identity Threat Protection.',
    'Click "Session Protection" (Continuous Access Evaluation).',
    'Confirm Session Protection is set to ACTIVE.',
    'Edit the default rule (or add a rule):',
    '  - For HIGH risk: set action to "Terminate Session".',
    '  - For MEDIUM risk: set action to "Reauthenticate" as minimum.',
    'Click Save.',
    'Communicate to users: suspicious sessions may be abruptly terminated — ' +
    'they will need to re-authenticate from a trusted device.',
    'Verify via Reports > System Log: filter eventType eq "policy.auth_reevaluate.action" and debugContext.debugData.RuleAction eq "TERMINATE_SESSION".',
    'Resources: https://help.okta.com/en-us/content/topics/itp/continuous-access-evaluation.htm',
  ];
}

function buildUniversalLogoutAdminSteps() {
  return [
    'Sign in to the Okta Admin Console.',
    'Go to Security > Identity Threat Protection.',
    'Click "Universal Logout".',
    'Enable Universal Logout — terminates sessions across ALL connected apps when suspicious activity is detected.',
    'Review the list of supported apps (OIDC/SAML apps that implement back-channel logout).',
    'Configure which risk events trigger Universal Logout (recommended: HIGH risk and above).',
    'Click Save.',
    'Note: Apps that do not implement back-channel logout may not terminate immediately. ' +
    'Review: https://help.okta.com/en-us/content/topics/itp/universal-supported-apps.htm',
    'Verify: Reports > System Log > eventType eq "user.authentication.universal_logout" after a test risk event.',
  ];
}

function buildITPWorkflowsAdminSteps() {
  return [
    'Sign in to the Okta Admin Console.',
    'Go to Workflow > Workflows Console (or navigate to workflows.okta.com).',
    'Create a new workflow. Under Triggers, select an ITP trigger:',
    '  - "Identity Threat Protection: User Risk Changed" — fires when ITP detects increased user risk',
    '  - "Identity Threat Protection: Session Risk Changed" — fires on session-level risk changes',
    'Configure workflow actions for detected threats, such as:',
    '  - Send an alert to your SOC (Slack, email, or webhook to SIEM)',
    '  - Suspend the Okta user account if risk is HIGH',
    '  - Clear all active sessions for the user',
    '  - Create a ServiceNow / Jira incident ticket',
    'Activate the workflow.',
    'Test by triggering a manual risk evaluation from the user\'s profile in the Admin Console.',
    'Resources: https://help.okta.com/en-us/content/topics/itp/detections.htm',
  ];
}

// ── Risk assessment ───────────────────────────────────────────────────────────

function buildITPRiskAssessment() {
  return {
    teaSeverity: 'MODERATE',
    changeRisk:  'LOW',
    summary:
      'ITP provides continuous, post-authentication risk monitoring using AI signals from Okta Verify, ' +
      'EDR tools, and the Okta platform (T1539 / Steal Web Session Cookie, T1557 / AiTM). ' +
      'Unlike traditional MFA which only protects sign-in, ITP can terminate sessions mid-flight ' +
      'when hijacking or credential theft is detected.',
    preChangeChecks: [
      'Verify the ITP license is active on the tenant (ITP requires an Okta Identity Threat Protection subscription).',
      'Confirm Okta Verify is enrolled on a representative sample of user devices before enabling — ITP uses Okta Verify device signals.',
      'Run the policy.auth_reevaluate.action queries (30-day baseline) to understand current risk event volume before enforcing session termination.',
      'Identify any service accounts or automated integrations that use long-running sessions — TERMINATE_SESSION will break them if they hit a risk event.',
    ],
    blastRadius:
      'TERMINATE_SESSION may abruptly end legitimate sessions if ITP generates false positives. ' +
      'Users will need to re-authenticate from a trusted device. ' +
      'Start with REAUTHENTICATE for MEDIUM risk and monitor for false positives before escalating to TERMINATE_SESSION for HIGH risk. ' +
      'Service accounts with persistent sessions are at highest risk of disruption from TERMINATE_SESSION actions.',
    rolloutSteps: [
      'Step 1 — Enable ITP Session Protection with REAUTHENTICATE for MEDIUM risk (lower user impact).',
      'Step 2 — Monitor System Log for false positives over 1–2 weeks (see postChangeMonitoring queries).',
      'Step 3 — Escalate HIGH risk to TERMINATE_SESSION when false positive rate is acceptable.',
      'Step 4 — Enable Universal Logout to extend protection across all connected apps.',
      'Step 5 — Create ITP Workflows to alert SOC on HIGH-risk events.',
    ],
    postChangeMonitoring: {
      description:
        'After enabling ITP Session Protection, watch for unexpected session terminations on legitimate users. ' +
        'The key query is policy.auth_reevaluate.action with TERMINATE_SESSION outcomes — each one is a user kicked out mid-session.',
      logQueries: [
        {
          description: 'ITP-triggered session terminations',
          filter: 'eventType eq "policy.auth_reevaluate.action" AND outcome.result eq "TERMINATE_SESSION"',
          timeWindow: 'first 14 days post-change',
          note: 'Review actor.displayName for each termination. Known users terminated during normal business hours may be false positives.',
        },
        {
          description: 'ITP risk evaluations (all outcomes)',
          filter: 'eventType eq "policy.auth_reevaluate.action"',
          timeWindow: 'first 7 days post-change',
          note: 'Full picture of what ITP is evaluating. Compare TERMINATE vs REAUTHENTICATE vs ALLOW volumes.',
        },
        {
          description: 'Universal Logout events post-enablement',
          filter: 'eventType sw "user.session.end"',
          timeWindow: 'first 7 days post-Universal-Logout-enablement',
          note: 'Confirms Universal Logout is terminating sessions across connected apps when ITP fires.',
        },
      ],
    },
    rollback:
      'ITP Session Protection actions can be changed back to REAUTHENTICATE or NONE at any time ' +
      'from Security > Identity Threat Protection. Changes take effect on the next risk evaluation.',
  };
}

// ── Tool registration ─────────────────────────────────────────────────────────

function registerITPTools(server) {
  server.tool(
    'okta_get_itp_config',
    'Audit Identity Threat Protection (ITP) configuration for . ' +
    'Checks: (1) ITP Session Protection / Continuous Access Evaluation — verifies policies exist ' +
    'and high-risk rules are configured to TERMINATE_SESSION; ' +
    '(2) ITP Universal Logout — checks if cross-app session termination is enabled; ' +
    '(3) ITP Workflow detections — checks if ITP triggers are wired to automated response workflows. ' +
    'Returns per-finding status and full remediation guidance.',
    {},
    async () => {
      if (process.env.OFFLINE_MODE === 'true') {
        return buildMcpOffline({
          remediation: {
            terraform:         buildITPTerraform(),
            logQueries:        buildITPLogQueries(),
            adminConsoleSteps: buildSessionProtectionAdminSteps(),
            riskAssessment:    buildITPRiskAssessment(),
          },
        });
      }
      try {
        const client = await createOktaClient();
        const [continuousAccess, features] = await Promise.all([
          fetchContinuousAccessPolicies(client),
          fetchITPFeatures(client),
        ]);

        const featureList = features.available ? features.features : [];

        const sessionAudit = continuousAccess.available
          ? auditSessionProtection(continuousAccess.policies)
          : {
            configured: false,
            canTerminateSessions: false,
            finding: {
              id: 'ITP_API_UNAVAILABLE',
              severity: 'MODERATE',
              description: `Cannot read ITP Session Protection policies: ${continuousAccess.reason}`,
              recommendation: 'Check Security > Identity Threat Protection in the Admin Console.',
            },
          };

        const universalLogoutFeature = matchFeature(featureList, ITP_UNIVERSAL_LOGOUT_FEATURE_NAMES);
        const universalLogoutEnabled = universalLogoutFeature?.status === 'ENABLED';
        const universalLogoutFinding = !universalLogoutEnabled
          ? {
            id: 'ITP_UNIVERSAL_LOGOUT_NOT_ENABLED',
            severity: 'MODERATE',
            description:
              'ITP Universal Logout is not enabled. When suspicious activity is detected, Okta ' +
              'cannot automatically terminate sessions across all connected applications simultaneously. ' +
              'An attacker with a stolen session retains access to every app until individual tokens expire.',
            recommendation:
              'Enable Universal Logout under Security > Identity Threat Protection > Universal Logout.',
          }
          : null;

        const workflowsFeature = matchFeature(featureList, ITP_WORKFLOWS_FEATURE_NAMES);
        const workflowsEnabled = workflowsFeature?.status === 'ENABLED';
        const workflowsFinding = !workflowsEnabled
          ? {
            id: 'ITP_WORKFLOWS_NOT_ENABLED',
            severity: 'MODERATE',
            description:
              'ITP Workflow detections are not configured. ITP detections do not trigger automated ' +
              'responses (SOC alerts, account suspension, ticket creation). Threat actors can exploit ' +
              'the detection-to-response gap.',
            recommendation:
              'Create ITP-triggered workflows in the Okta Workflows Console with actions such as ' +
              'SOC notification, user suspension, and session clearing.',
          }
          : null;

        const allFindings = [
          sessionAudit.finding,
          universalLogoutFinding,
          workflowsFinding,
        ].filter(Boolean);

        return buildMcpOk({
          summary: {
            findingCount: allFindings.length,
            apiCoverage: {
              continuousAccessPoliciesAvailable: continuousAccess.available,
              featuresApiAvailable: features.available,
            },
          },
          findings: allFindings,
          itpStatus: {
            sessionProtection: {
              configured: sessionAudit.configured,
              canTerminateSessions: sessionAudit.canTerminateSessions,
              policies: sessionAudit.policies || null,
            },
            universalLogout: {
              enabled: universalLogoutEnabled,
              featureDetected: Boolean(universalLogoutFeature),
              featureStatus: universalLogoutFeature?.status || null,
            },
            workflows: {
              enabled: workflowsEnabled,
              featureDetected: Boolean(workflowsFeature),
              featureStatus: workflowsFeature?.status || null,
            },
          },
          remediation: {
            terraform: buildITPTerraform(),
            logQueries: buildITPLogQueries(),
            adminConsoleSteps: {
              sessionProtection: buildSessionProtectionAdminSteps(),
              universalLogout: buildUniversalLogoutAdminSteps(),
              workflows: buildITPWorkflowsAdminSteps(),
            },
            riskAssessment: buildITPRiskAssessment(),
          },
        });
      } catch (err) {
        return buildMcpError(err);
      }
    },
  );

  server.tool(
    'okta_enable_itp_session_protection',
    'Enable or upgrade ITP Session Protection to terminate suspicious sessions (MITRE T1539). ' +
    'Finds the Continuous Access Evaluation policy and updates high-risk rules to TERMINATE_SESSION. ' +
    'If the API is unavailable or no policy exists, returns detailed manual admin console steps. ' +
    'Write operation — confirm before calling.',
    {
      policyId: z.string().optional()
        .describe('ID of the Continuous Access Evaluation policy to update. Omit to auto-detect the first policy.'),
    },
    async ({ policyId }) => {
      if (process.env.OFFLINE_MODE === 'true') {
        return buildMcpOffline({ skipped: true, message: 'Write operations are not available in offline mode.' });
      }
      if (process.env.PROD_MODE === 'true') {
        return buildMcpReadOnly();
      }
      try {
        const client = await createOktaClient();
        const { available, policies, reason } = await fetchContinuousAccessPolicies(client);

        if (!available) {
          return buildMcpOk({
            message: `ITP Continuous Access Evaluation API not available (${reason}) — follow manual steps below.`,
            apiAvailable: false,
            remediation: {
              terraform: buildITPTerraform(),
              logQueries: buildITPLogQueries(),
              adminConsoleSteps: buildSessionProtectionAdminSteps(),
              riskAssessment: buildITPRiskAssessment(),
            },
          });
        }

        if (!policies || policies.length === 0) {
          return buildMcpOk({
            message:
              'No Continuous Access Evaluation policies found. ' +
              'ITP Session Protection must be enabled in the Admin Console first, then this tool can ' +
              'update the rule action to TERMINATE_SESSION.',
            apiAvailable: true,
            policyFound: false,
            remediation: {
              terraform: buildITPTerraform(),
              logQueries: buildITPLogQueries(),
              adminConsoleSteps: buildSessionProtectionAdminSteps(),
              riskAssessment: buildITPRiskAssessment(),
            },
          });
        }

        const targetPolicy = policyId
          ? policies.find((p) => p.id === policyId)
          : policies[0];

        if (!targetPolicy) {
          return buildMcpError(
            new Error(`Policy "${policyId}" not found. Use okta_get_itp_config to list policies.`)
          );
        }

        const rules = await fetchPolicyRules(client, targetPolicy.id);
        const updatedRules = [];

        for (const rule of rules) {
          const alreadyTerminates = ruleActionIsTerminate(rule);
          if (alreadyTerminates) continue;

          // Determine which action key to patch — try the most common CAE action paths
          const updatedRule = { ...rule };
          if (rule.actions?.sessionAccess) {
            updatedRule.actions = {
              ...rule.actions,
              sessionAccess: { ...rule.actions.sessionAccess, action: TERMINATE_SESSION_ACTION },
            };
          } else if (rule.actions?.continuousAccess) {
            updatedRule.actions = {
              ...rule.actions,
              continuousAccess: { ...rule.actions.continuousAccess, action: TERMINATE_SESSION_ACTION },
            };
          } else {
            // Unknown action structure — skip and report
            updatedRules.push({
              ruleId: rule.id,
              ruleName: rule.name,
              skipped: true,
              reason: 'Unknown action structure — manual update required',
              currentActions: rule.actions,
            });
            continue;
          }

          try {
            await client.put(`/api/v1/policies/${targetPolicy.id}/rules/${rule.id}`, updatedRule);
            updatedRules.push({
              ruleId: rule.id,
              ruleName: rule.name,
              skipped: false,
              appliedAction: TERMINATE_SESSION_ACTION,
            });
          } catch (ruleErr) {
            updatedRules.push({
              ruleId: rule.id,
              ruleName: rule.name,
              skipped: true,
              reason: `Rule update failed: ${ruleErr.message}`,
            });
          }
        }

        const successCount = updatedRules.filter((r) => !r.skipped).length;

        return buildMcpOk({
          message: successCount > 0
            ? `Updated ${successCount} ITP Session Protection rule(s) to TERMINATE_SESSION.`
            : 'No rules were updated — rules may already use TERMINATE_SESSION, or action structure ' +
              'requires manual configuration. See adminConsoleSteps below.',
          apiAvailable: true,
          policyId: targetPolicy.id,
          policyName: targetPolicy.name,
          updatedRules,
          remediation: {
            terraform: buildITPTerraform(),
            logQueries: buildITPLogQueries(),
            adminConsoleSteps: buildSessionProtectionAdminSteps(),
            riskAssessment: buildITPRiskAssessment(),
          },
        });
      } catch (err) {
        return buildMcpError(err);
      }
    },
  );

  server.tool(
    'okta_enable_itp_universal_logout',
    'Enable Identity Threat Protection Universal Logout to automatically terminate sessions ' +
    'across all applications when suspicious activity is detected. ' +
    'Attempts to enable via the Okta features API; falls back to manual console steps if not available. ' +
    'Write operation — confirm before calling.',
    {},
    async () => {
      if (process.env.OFFLINE_MODE === 'true') {
        return buildMcpOffline({ skipped: true, message: 'Write operations are not available in offline mode.' });
      }
      if (process.env.PROD_MODE === 'true') {
        return buildMcpReadOnly();
      }
      try {
        const client = await createOktaClient();
        let apiAvailable = false;
        let apiResult = null;

        try {
          const { data: allFeatures } = await client.get('/api/v1/features');
          const feature = matchFeature(allFeatures, ITP_UNIVERSAL_LOGOUT_FEATURE_NAMES);

          if (feature?.status === 'ENABLED') {
            return buildMcpOk({
              message: 'ITP Universal Logout is already enabled.',
              apiAvailable: true,
              apiResult: feature,
              remediation: {
                terraform: buildITPTerraform(),
                logQueries: buildITPLogQueries(),
                adminConsoleSteps: buildUniversalLogoutAdminSteps(),
                riskAssessment: buildITPRiskAssessment(),
              },
            });
          }

          if (feature) {
            const { data: enabled } = await client.post(
              `/api/v1/features/${feature.id}/lifecycle/enable`,
              {}
            );
            apiResult = enabled;
            apiAvailable = true;
          }
        } catch (apiErr) {
          const status = apiErr.response?.status;
          if (status !== 404 && status !== 405 && status !== 403) throw apiErr;
        }

        return buildMcpOk({
          message: apiAvailable
            ? 'ITP Universal Logout enabled via features API.'
            : 'ITP Universal Logout feature not found via API — follow manual steps below to enable in the Admin Console.',
          apiAvailable,
          apiResult,
          remediation: {
            terraform: buildITPTerraform(),
            logQueries: buildITPLogQueries(),
            adminConsoleSteps: buildUniversalLogoutAdminSteps(),
            riskAssessment: buildITPRiskAssessment(),
          },
        });
      } catch (err) {
        return buildMcpError(err);
      }
    },
  );
}

module.exports = {
  registerITPTools,
  auditSessionProtection,
  buildITPLogQueries,
  buildITPRiskAssessment,
};
