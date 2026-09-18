'use strict';

const { buildMcpOk, buildMcpError, buildMcpOffline } = require('./resolver-utils');
const { createOktaClient } = require('../auth/okta-client');

// ── Fetchers ───────────────────────────────────────────────────────────────────

async function fetchBehaviors(client) {
  try {
    const { data } = await client.get('/api/v1/behaviors');
    return { available: true, behaviors: Array.isArray(data) ? data : [] };
  } catch (err) {
    const status = err.response?.status;
    if (status === 404 || status === 403) {
      return {
        available: false,
        reason: `API returned ${status} — Behavior Detection may not be provisioned or requires okta.behaviors.read scope.`,
        behaviors: [],
      };
    }
    return { available: false, reason: err.message, behaviors: [] };
  }
}

// ── Audit ──────────────────────────────────────────────────────────────────────

function auditBehaviors({ behaviors }) {
  const findings = [];

  const activeBehaviors = behaviors.filter((b) => b.status === 'ACTIVE');

  if (behaviors.length === 0) {
    findings.push({
      id: 'BEHAVIOR_DETECTION_NOT_CONFIGURED',
      severity: 'MODERATE',
      description:
        'No Behavior Detection rules are configured. Behavior Detection identifies anomalous ' +
        'access patterns (new device, new IP, new city, new country, velocity) and can be ' +
        'referenced in authentication policy rules to step up or block access.',
      recommendation:
        'Enable Behavior Detection under Security > Behavior Detection. ' +
        'Create rules for New Device, New IP, and Velocity and reference them in ' +
        'authentication policy conditions.',
    });
  } else if (activeBehaviors.length === 0) {
    findings.push({
      id: 'BEHAVIOR_DETECTION_ALL_DISABLED',
      severity: 'MODERATE',
      description:
        `${behaviors.length} Behavior Detection rule(s) exist but none have status ACTIVE. ` +
        'Inactive rules are not evaluated during authentication.',
      recommendation:
        'Enable at least the New Device, New IP, and Velocity behavior detection rules under ' +
        'Security > Behavior Detection.',
    });
  }

  return {
    findingCount: findings.length,
    findings,
    summary: {
      totalBehaviors: behaviors.length,
      activeBehaviors: activeBehaviors.length,
      behaviors: behaviors.map((b) => ({ id: b.id, name: b.name, type: b.type, status: b.status })),
    },
  };
}

// ── Terraform ──────────────────────────────────────────────────────────────────

function buildBehaviorTerraform() {
  return `# Terraform — Okta Behavior Detection
#
# Provider setup:
#   https://developer.okta.com/docs/guides/terraform-enable-org-access/main/
# Resource reference:
#   https://registry.terraform.io/providers/okta/okta/latest/docs/resources/behavior

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
  scopes      = ["okta.behaviors.manage"]
  private_key = "<PATH_OR_CONTENT_OF_PRIVATE_KEY>"
}

resource "okta_behavior" "new_device" {
  name   = "New Device"
  type   = "ANOMALOUS_DEVICE"
  status = "ACTIVE"

  # Number of days a device is considered "new" after first seen
  number_of_authentications = 0
  radius_from_location      = 0
}

resource "okta_behavior" "new_city" {
  name   = "New City"
  type   = "ANOMALOUS_LOCATION"
  status = "ACTIVE"

  number_of_authentications = 0
  radius_from_location      = 0
}

resource "okta_behavior" "velocity" {
  name       = "Velocity"
  type       = "VELOCITY"
  status     = "ACTIVE"
  velocity   = 805   # km/h — faster than possible travel → impossible travel detection
}
`;
}

// ── Log queries ────────────────────────────────────────────────────────────────

function buildBehaviorLogQueries() {
  return [
    {
      description: 'Behavior Detection rule evaluations',
      filter: 'eventType eq "policy.evaluate_sign_on" AND outcome.result eq "CHALLENGE"',
      timeWindow: 'last 30 days',
      note: 'Sign-on policy evaluations that resulted in a step-up challenge — often triggered by behavior anomalies.',
    },
    {
      description: 'Behavior Detection configuration changes',
      filter: 'eventType sw "behavior."',
      timeWindow: 'last 90 days',
      note: 'Audit trail of changes to behavior detection rules.',
    },
    {
      description: 'Authentication from new devices',
      filter: 'eventType eq "user.authentication.auth_via_mfa" AND debugContext.debugData.behaviors co "NEW_DEVICE"',
      timeWindow: 'last 7 days',
      note: 'Sign-ins where the New Device behavior was detected — confirms behavior rules are evaluating correctly.',
    },
  ];
}

// ── Admin console steps ────────────────────────────────────────────────────────

function buildBehaviorAdminSteps() {
  return [
    'Sign in to the Okta Admin Console.',
    'Go to Security > Behavior Detection.',
    'Enable the following behavior rules (click each toggle to ACTIVE):',
    '  • New Device — detects sign-ins from a device not previously seen for this user',
    '  • New IP — detects sign-ins from an IP not previously seen for this user',
    '  • New City / New Country — detects sign-ins from an unexpected geographic location',
    '  • Velocity — detects impossible travel (sign-ins from two locations too far apart too quickly)',
    'After enabling rules, reference them in Authentication Policy conditions:',
    '  a. Go to Security > Authentication Policies.',
    '  b. Edit an existing policy or create a new rule.',
    '  c. Under "Conditions", add "User matches behavior" and select the behavior rules.',
    '  d. Set the action to "Challenge with additional factor" or "Deny access" as appropriate.',
    'Click Save on each policy rule.',
  ];
}

// ── Risk assessment ────────────────────────────────────────────────────────────

function buildBehaviorRiskAssessment() {
  return {
    teaSeverity: 'MODERATE',
    changeRisk:  'LOW',
    summary:
      'Behavior Detection rules provide risk signals that authentication policies can act on. ' +
      'Without them, Okta cannot distinguish a legitimate user from an attacker using stolen ' +
      'credentials on a new device or from an unusual location.',
    preChangeChecks: [
      'Enabling Behavior Detection itself carries no risk — it only generates signals.',
      'Before referencing behavior signals in authentication policy DENY rules, check System Log to understand the current volume of new device and new location sign-ins.',
      'Identify travelling employees or teams with distributed locations before enabling New Country rules — they will generate elevated behavior risk scores.',
    ],
    blastRadius:
      'Enabling Behavior Detection itself does not affect sign-in flows — impact only occurs ' +
      'when you reference behavior rules in authentication policy conditions with a CHALLENGE or DENY action. ' +
      'Scope the policy conditions carefully before enabling enforcement. ' +
      'False positives (legitimate users challenged) are most common for users with dynamic IPs, VPNs, or frequent travel.',
    rolloutSteps: [
      'Step 1 — Enable New Device and Velocity rules (highest risk signals, lowest false-positive rate).',
      'Step 2 — Add behavior conditions to authentication policies with CHALLENGE action (not DENY).',
      'Step 3 — Monitor System Log for unexpected challenges over 1–2 weeks.',
      'Step 4 — Enable New IP, New City, and New Country rules.',
      'Step 5 — Tighten policy actions from CHALLENGE to DENY for high-confidence rules after monitoring.',
    ],
    postChangeMonitoring: {
      description:
        'After wiring behavior signals to authentication policies, watch for unexpected step-up challenges ' +
        'on legitimate users. Check whether travel or VPN use is triggering false positives.',
      logQueries: [
        {
          description: 'Behavior detection risk evaluations — all outcomes',
          filter: 'eventType eq "policy.evaluate_sign_on"',
          timeWindow: 'first 14 days post-change',
          note: 'Look for CHALLENGE outcomes on known users. A high rate on regular users suggests behavior thresholds need tuning.',
        },
        {
          description: 'MFA step-ups triggered by behavior risk signals',
          filter: 'eventType eq "user.authentication.auth_via_mfa"',
          timeWindow: 'first 14 days post-change',
          note: 'Volume increase after enabling behavior rules is expected. Unusual spikes during normal working hours may indicate false positives.',
        },
      ],
    },
    rollback:
      'Behavior rules can be disabled at any time from Security > Behavior Detection. ' +
      'Policy rule changes are also immediately reversible.',
  };
}

// ── Tool registration ─────────────────────────────────────────────────────────

function registerBehaviorDetectionTools(server) {
  server.tool(
    'okta_get_behavior_detection',
    'Audit Okta Behavior Detection configuration — checks whether behavior detection rules ' +
    '(New Device, New IP, New City, Velocity) are configured and ACTIVE. ' +
    'Behavior rules provide risk signals referenced by authentication policies to step up ' +
    'or block access on anomalous activity. Returns current rule status and remediation guidance.',
    {},
    async () => {
      if (process.env.OFFLINE_MODE === 'true') {
        return buildMcpOffline({
          remediation: {
            terraform:         buildBehaviorTerraform(),
            logQueries:        buildBehaviorLogQueries(),
            adminConsoleSteps: buildBehaviorAdminSteps(),
            riskAssessment:    buildBehaviorRiskAssessment(),
          },
        });
      }
      try {
        const client = await createOktaClient();
        const result = await fetchBehaviors(client);

        if (!result.available) {
          return buildMcpOk({
            available: false,
            reason: result.reason,
            summary: { totalBehaviors: 0, activeBehaviors: 0, behaviors: [] },
            findings: [{
              id: 'BEHAVIOR_API_UNAVAILABLE',
              severity: 'INFO',
              description: `Behavior Detection API unavailable: ${result.reason}`,
              recommendation: 'Verify manually under Security > Behavior Detection in the Admin Console.',
            }],
          });
        }

        const audit = auditBehaviors(result);

        return buildMcpOk({
          ...audit,
          remediation: {
            terraform: buildBehaviorTerraform(),
            logQueries: buildBehaviorLogQueries(),
            adminConsoleSteps: buildBehaviorAdminSteps(),
            riskAssessment: buildBehaviorRiskAssessment(),
          },
        });
      } catch (err) {
        return buildMcpError(err);
      }
    },
  );
}

module.exports = { registerBehaviorDetectionTools };
