'use strict';

const { buildMcpOk, buildMcpError, buildMcpOffline } = require('./resolver-utils');
const { createOktaClient } = require('../auth/okta-client');

const ATTACK_PROTECTION_PATH = '/api/v1/attack_protection';

// Feature flag name fragments to match against /api/v1/features
const BREACHED_PASSWORD_FEATURE_NAMES = [
  'BREACHED_PASSWORD',
  'BREACHED_CREDENTIAL',
  'COMPROMISED_CREDENTIAL',
];

const ENUMERATION_PROTECTION_FEATURE_NAMES = [
  'USERNAME_ENUMERATION',
  'ENUMERATION_PROTECTION',
  'USER_ENUMERATION',
];

// ── Fetchers ───────────────────────────────────────────────────────────────────

async function fetchAttackProtection(client) {
  try {
    const { data } = await client.get(ATTACK_PROTECTION_PATH);
    return { available: true, data };
  } catch (err) {
    const status = err.response?.status;
    if (status === 404 || status === 403) {
      return {
        available: false,
        reason: `API returned ${status} — attack protection endpoint may require OIE or specific scopes.`,
        data: null,
      };
    }
    return { available: false, reason: err.message, data: null };
  }
}

async function fetchFeatures(client) {
  try {
    const { data } = await client.get('/api/v1/features');
    return { available: true, features: Array.isArray(data) ? data : [] };
  } catch (err) {
    return { available: false, reason: err.message, features: [] };
  }
}

// ── Helpers ────────────────────────────────────────────────────────────────────

function matchFeature(features, nameList) {
  return features.find((f) =>
    nameList.some((n) => f.name?.toUpperCase().includes(n) || f.id?.toUpperCase().includes(n))
  ) || null;
}

// ── Audit ──────────────────────────────────────────────────────────────────────

function auditAttackProtection({ attackProtection, features }) {
  const findings = [];
  const featureList = features.available ? (features.features || []) : [];
  const apData = attackProtection.available ? attackProtection.data : null;

  // ── Breached Password Detection ────────────────────────────────────────────
  const breachedPasswordFeature = matchFeature(featureList, BREACHED_PASSWORD_FEATURE_NAMES);
  const breachedPasswordEnabled =
    breachedPasswordFeature?.status === 'ENABLED' ||
    apData?.breachedPassword?.mode === 'ENABLED' ||
    apData?.breachedPassword?.action !== undefined;

  if (!breachedPasswordEnabled) {
    findings.push({
      id: 'BREACHED_PASSWORD_DETECTION_DISABLED',
      severity: 'HIGH',
      description:
        'Breached Password Detection is not enabled. Okta checks user passwords against a ' +
        'database of known compromised credentials during authentication. When disabled, users ' +
        'with breached passwords are not prompted to change them, leaving accounts vulnerable ' +
        'to credential stuffing attacks.',
      recommendation:
        'Enable Breached Password Detection under Security > General > Password Policy or ' +
        'Security > Attack Protection. Set the action to "Force password change" or "Deny access".',
      detectedVia: breachedPasswordFeature
        ? `features API (status: ${breachedPasswordFeature.status})`
        : 'not detected via API — manual check required',
    });
  }

  // ── Username Enumeration Protection ───────────────────────────────────────
  const enumerationFeature = matchFeature(featureList, ENUMERATION_PROTECTION_FEATURE_NAMES);
  const enumerationEnabled =
    enumerationFeature?.status === 'ENABLED' ||
    apData?.userLockout?.userNameProtection === true;

  if (!enumerationEnabled) {
    findings.push({
      id: 'ENUMERATION_PROTECTION_DISABLED',
      severity: 'MODERATE',
      description:
        'Username Enumeration Protection is not enabled. Without it, an attacker can determine ' +
        'which usernames exist in your Okta tenant by observing different error messages for ' +
        'valid vs invalid usernames during sign-in or password reset.',
      recommendation:
        'Enable "Username Enumeration Protection" under Security > General or Security > Attack Protection. ' +
        'This returns identical error messages for valid and invalid usernames.',
      detectedVia: enumerationFeature
        ? `features API (status: ${enumerationFeature.status})`
        : 'not detected via API — manual check required',
    });
  }

  return {
    findingCount: findings.length,
    findings,
    rawStatus: {
      attackProtectionAvailable: attackProtection.available,
      breachedPassword: apData?.breachedPassword ?? null,
      userLockout: apData?.userLockout ?? null,
      breachedPasswordFeature: breachedPasswordFeature
        ? { id: breachedPasswordFeature.id, name: breachedPasswordFeature.name, status: breachedPasswordFeature.status }
        : null,
      enumerationFeature: enumerationFeature
        ? { id: enumerationFeature.id, name: enumerationFeature.name, status: enumerationFeature.status }
        : null,
    },
  };
}

// ── Terraform ──────────────────────────────────────────────────────────────────

function buildAttackProtectionTerraform() {
  return `# Terraform — Okta Attack Protection Settings
#
# Provider setup:
#   https://developer.okta.com/docs/guides/terraform-enable-org-access/main/
# Resource reference:
#   https://registry.terraform.io/providers/okta/okta/latest/docs/resources/policy_password
#   https://registry.terraform.io/providers/okta/okta/latest/docs/resources/org_configuration

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

# Breached Password Detection is configured at the password policy level.
# Set password_dictionary_lookup = true to check against common and breached passwords.
resource "okta_policy_password" "default_password_policy" {
  name   = "<YOUR_PASSWORD_POLICY_NAME>"
  status = "ACTIVE"

  # Enable dictionary-based and breached credential checks
  password_dictionary_lookup = true
  password_exclude_username  = true
  password_min_length        = 15
}

# Username Enumeration Protection and other attack protection settings
# are configured in org settings or via the Admin Console.
# Check current provider support:
#   https://registry.terraform.io/providers/okta/okta/latest/docs/resources/org_configuration
`;
}

// ── Log queries ────────────────────────────────────────────────────────────────

function buildAttackProtectionLogQueries() {
  return [
    {
      description: 'Breached credential detections',
      filter: 'eventType eq "security.breached_credential.detected"',
      timeWindow: 'last 30 days',
      note: 'Fires when Okta detects a user\'s password in a breach database. Confirms Breached Password Detection is active.',
    },
    {
      description: 'Forced password changes from breached credential detection',
      filter: 'eventType eq "user.account.update_password" AND debugContext.debugData.requestUri co "breached"',
      timeWindow: 'last 30 days',
      note: 'Password changes triggered by breached credential detection.',
    },
    {
      description: 'Brute force lockouts — enumeration protection verification',
      filter: 'eventType eq "security.attack.start"',
      timeWindow: 'last 7 days',
      note: 'Okta-detected attack events. Presence of these events confirms attack protection is evaluating sign-in traffic.',
    },
  ];
}

// ── Admin console steps ────────────────────────────────────────────────────────

function buildAttackProtectionAdminSteps() {
  return [
    'Sign in to the Okta Admin Console.',
    '',
    'To enable Breached Password Detection:',
    '  1. Go to Security > Attack Protection.',
    '  2. Under "Breached Password Detection", click Edit.',
    '  3. Toggle the setting to Enabled.',
    '  4. Set the action to "Force users to change their password" for the highest protection.',
    '  5. Click Save.',
    '  Alternatively, enable it in password policy settings:',
    '  1. Go to Security > Authenticators > Password > Enrollment.',
    '  2. Edit the default password policy.',
    '  3. Under Complexity, enable "Does not contain common/breached passwords".',
    '',
    'To enable Username Enumeration Protection:',
    '  1. Go to Security > General.',
    '  2. Scroll to "User Enumeration Protection".',
    '  3. Enable the toggle.',
    '  4. Click Save.',
  ];
}

// ── Risk assessment ────────────────────────────────────────────────────────────

function buildAttackProtectionRiskAssessment() {
  return {
    teaSeverity: 'HIGH',
    changeRisk:  'LOW',
    summary:
      'Breached Password Detection prevents users with compromised passwords from remaining ' +
      'vulnerable to credential stuffing. Username Enumeration Protection prevents attackers ' +
      'from building a target list of valid accounts through probing. Both are low-blast-radius, ' +
      'high-security-value controls.',
    preChangeChecks: [
      'No prerequisites — both settings are safe to enable without a grace period.',
      'Note: Breached Password Detection with "Force password change" will immediately prompt affected users to reset on next login — this is the intended behaviour.',
      'Username Enumeration Protection changes only error messaging — no user workflow is disrupted.',
    ],
    blastRadius:
      'Breached Password Detection with "Force password change" action will require affected ' +
      'users to change their password on next login — this is expected security behaviour, not a false positive. ' +
      'Username Enumeration Protection changes error messaging but does not affect legitimate sign-in flows. ' +
      'Breached password checks use a privacy-preserving k-anonymity model — the plaintext password is never sent externally.',
    rolloutSteps: [
      'Step 1 — Enable Breached Password Detection with "Warn and force change" action.',
      'Step 2 — Enable Username Enumeration Protection.',
      'Step 3 — Monitor System Log for security.breached_credential.detected events (see postChangeMonitoring queries).',
      'Step 4 — Review forced password change volume to gauge breach exposure.',
    ],
    postChangeMonitoring: {
      description:
        'After enabling Breached Password Detection, watch for users being forced to reset their passwords. ' +
        'A high volume in the first 24 hours indicates significant credential exposure in your user base.',
      logQueries: [
        {
          description: 'Breached credentials detected',
          filter: 'eventType eq "security.breached_credential.detected"',
          timeWindow: 'first 30 days post-change',
          note: 'Each event is a user with a known-breached password. High volume indicates significant credential exposure.',
        },
        {
          description: 'Password resets triggered by breached credential detection',
          filter: 'eventType eq "user.account.reset_password"',
          timeWindow: 'first 7 days post-change',
          note: 'An increase after enabling detection is expected and healthy — these are users with compromised passwords now being forced to reset.',
        },
      ],
    },
    rollback:
      'Both settings can be toggled independently at any time from the Admin Console.',
  };
}

// ── Tool registration ─────────────────────────────────────────────────────────

function registerAttackProtectionTools(server) {
  server.tool(
    'okta_get_attack_protection',
    'Audit Okta Attack Protection settings — checks whether Breached Password Detection ' +
    '(verifies user passwords against known breach databases) and Username Enumeration ' +
    'Protection (prevents user account discovery via error message differences) are enabled. ' +
    'Both are high-value, low-impact controls. Returns current status via the attack protection ' +
    'API and feature flags, with remediation guidance.',
    {},
    async () => {
      if (process.env.OFFLINE_MODE === 'true') {
        return buildMcpOffline({
          remediation: {
            terraform:         buildAttackProtectionTerraform(),
            logQueries:        buildAttackProtectionLogQueries(),
            adminConsoleSteps: buildAttackProtectionAdminSteps(),
            riskAssessment:    buildAttackProtectionRiskAssessment(),
          },
        });
      }
      try {
        const client = await createOktaClient();
        const [attackProtection, features] = await Promise.all([
          fetchAttackProtection(client),
          fetchFeatures(client),
        ]);

        const audit = auditAttackProtection({ attackProtection, features });

        return buildMcpOk({
          ...audit,
          remediation: {
            terraform: buildAttackProtectionTerraform(),
            logQueries: buildAttackProtectionLogQueries(),
            adminConsoleSteps: buildAttackProtectionAdminSteps(),
            riskAssessment: buildAttackProtectionRiskAssessment(),
          },
        });
      } catch (err) {
        return buildMcpError(err);
      }
    },
  );
}

module.exports = { registerAttackProtectionTools };
