'use strict';

const { buildMcpOk, buildMcpError, buildMcpOffline } = require('./resolver-utils');
const { createOktaClient } = require('../auth/okta-client');

// Shared Signals Framework provider API (current, requires okta.securityEventsProviders.read)
const SSF_PROVIDERS_PATH = '/api/v1/ssf/providers';
// Risk provider API — deprecated Dec 31, 2024; retained here as fallback for older tenants
const RISK_PROVIDERS_PATH = '/api/v1/risk/providers';
// Authentication policies
const AUTH_POLICIES_PATH = '/api/v1/policies?type=ACCESS_POLICY';

// Known EDR vendor name fragments for provider detection
const EDR_NAME_FRAGMENTS = [
  'CROWDSTRIKE', 'CROWD_STRIKE',
  'CARBON_BLACK', 'CARBONBLACK', 'VMW',
  'CYLANCE',
  'SENTINELONE', 'SENTINEL_ONE',
  'DEFENDER', 'MICROSOFT_DEFENDER',
  'TANIUM',
  'JAMF',
  'CISCO', 'SECURE_ENDPOINT', 'AMP',
  'PALO_ALTO', 'CORTEX',
  'SOPHOS',
  'TREND_MICRO',
  'WEBROOT',
  'MALWAREBYTES',
  'EDR', 'ENDPOINT_DETECTION',
];

// Keywords in authentication policy rule conditions that indicate EDR/device signal usage
const EDR_POLICY_KEYWORDS = [
  'edr', 'endpointdetection', 'devicesignal', 'device_signal',
  'risk_score', 'riskscore', 'crowdstrike', 'sentinelone',
  'carbonblack', 'defender',
];

// ── Fetchers ───────────────────────────────────────────────────────────────────

async function fetchSSFProviders(client) {
  try {
    const { data } = await client.get(SSF_PROVIDERS_PATH);
    return {
      available: true,
      providers: Array.isArray(data) ? data : (data.providers || []),
    };
  } catch (err) {
    const status = err.response?.status;
    if (status === 404 || status === 403) {
      return {
        available: false,
        reason: `API returned ${status} — Shared Signals Framework endpoint may not be available on this tenant.`,
      };
    }
    return { available: false, reason: err.message };
  }
}

async function fetchRiskProviders(client) {
  try {
    const { data } = await client.get(RISK_PROVIDERS_PATH);
    return { available: true, providers: Array.isArray(data) ? data : [] };
  } catch (err) {
    const status = err.response?.status;
    if (status === 404 || status === 403) {
      return { available: false, reason: `API returned ${status}` };
    }
    return { available: false, reason: err.message };
  }
}

async function fetchAuthPolicies(client) {
  try {
    const { data } = await client.get(AUTH_POLICIES_PATH);
    return { available: true, policies: Array.isArray(data) ? data : [] };
  } catch (err) {
    const status = err.response?.status;
    if (status === 404 || status === 403) {
      return { available: false, reason: `API returned ${status}` };
    }
    return { available: false, reason: err.message };
  }
}

// ── Audit helpers ──────────────────────────────────────────────────────────────

function detectEDRProviders(providers) {
  return providers.filter((p) =>
    EDR_NAME_FRAGMENTS.some((fragment) => {
      const nameUpper = (p.name || '').toUpperCase();
      const typeUpper = (p.type || '').toUpperCase();
      const idUpper = (p.id || '').toUpperCase();
      return nameUpper.includes(fragment) || typeUpper.includes(fragment) || idUpper.includes(fragment);
    })
  );
}

function ruleUsesEDRSignals(rule) {
  const raw = JSON.stringify(rule.conditions || {}).toLowerCase();
  return EDR_POLICY_KEYWORDS.some((kw) => raw.includes(kw));
}

function auditDeviceIntegration({ ssfProviders, riskProviders, authPolicies }) {
  const findings = [];

  const allSSFProviders = ssfProviders.available ? ssfProviders.providers : [];
  const allRiskProviders = riskProviders.available ? riskProviders.providers : [];
  const edrFromSSF = detectEDRProviders(allSSFProviders);
  const edrFromRisk = detectEDRProviders(allRiskProviders);
  const allDetectedEDR = [...edrFromSSF, ...edrFromRisk];
  const hasEDRIntegration = allDetectedEDR.length > 0;

  //  — No EDR / endpoint security integration
  if (!hasEDRIntegration) {
    findings.push({
      id: 'NO_EDR_INTEGRATION',
      severity: 'MODERATE',
      description:
        'No Endpoint Detection and Response (EDR) or Shared Signals Framework (SSF) provider is ' +
        'configured. Without EDR integration, Okta cannot receive device health signals from ' +
        'security tools such as CrowdStrike, Microsoft Defender, or Carbon Black. ' +
        'Sign-in requests from compromised endpoints are indistinguishable from legitimate ones.',
      recommendation:
        'Configure an EDR provider under Security > Device Integrations > Endpoint Detection and Response, ' +
        'or integrate via the Okta Shared Signals Framework (SSF) to route security events to Okta\'s risk engine.',
    });
  }

  //  — Auth policies not consuming EDR/device signals
  const allRules = authPolicies.available
    ? (authPolicies.policies || []).flatMap((p) =>
      (p.rules || []).map((r) => ({ ...r, policyId: p.id, policyName: p.name }))
    )
    : [];

  const rulesWithEDRSignals = allRules.filter(ruleUsesEDRSignals);

  if (hasEDRIntegration && rulesWithEDRSignals.length === 0 && authPolicies.available) {
    findings.push({
      id: 'EDR_SIGNALS_NOT_USED_IN_AUTH_POLICIES',
      severity: 'MODERATE',
      description:
        'An EDR provider is configured, but no Authentication Policy rules incorporate EDR device ' +
        'signals. The EDR integration provides no runtime protection until authentication policies ' +
        'are tuned to challenge or block sign-ins from high-risk devices.',
      recommendation:
        'Update Authentication Policies to require additional MFA or deny access when EDR signals ' +
        'indicate a high-risk device state (e.g., active malware, policy violation, unmanaged device).',
    });
  }

  if (!hasEDRIntegration && rulesWithEDRSignals.length === 0 && authPolicies.available) {
    findings.push({
      id: 'NO_DEVICE_SIGNAL_AUTH_RULES',
      severity: 'MODERATE',
      description:
        'No Authentication Policy rules use Endpoint Detection and Response (EDR) or device risk ' +
        'signals. The Okta Policy Engine is not receiving device security context for sign-in decisions.',
      recommendation:
        'First configure an EDR provider, then update Authentication Policy rules ' +
        'to require additional authentication when device risk signals indicate compromise.',
    });
  }

  return {
    findingCount: findings.length,
    findings,
    edrStatus: {
      hasEDRIntegration,
      ssfProviders: ssfProviders.available
        ? allSSFProviders.map((p) => ({ id: p.id, name: p.name, type: p.type, status: p.status }))
        : null,
      riskProviders: riskProviders.available
        ? allRiskProviders.map((p) => ({ id: p.id, name: p.name, type: p.type, status: p.status }))
        : null,
      detectedEDRProviders: allDetectedEDR.map((p) => ({ id: p.id, name: p.name, type: p.type })),
      authPolicyRulesUsingEDRSignals: rulesWithEDRSignals.length,
    },
    apiCoverage: {
      ssfAvailable: ssfProviders.available,
      ssfFailReason: ssfProviders.available ? null : ssfProviders.reason,
      riskProvidersAvailable: riskProviders.available,
      authPoliciesAvailable: authPolicies.available,
    },
  };
}

// ── Terraform ─────────────────────────────────────────────────────────────────

function buildDeviceIntegrationTerraform() {
  return `# Terraform — Okta Device Integration / EDR
#
# EDR providers are configured in the Okta Admin Console under:
#   Security > Device Integrations > Endpoint Detection and Response
#
# The Terraform Okta provider may not fully support all EDR integration resources.
# Check: https://registry.terraform.io/providers/okta/okta/latest/docs
#
# For SSF (Shared Signals Framework) receivers — if your EDR vendor sends via SSF:
#   https://developer.okta.com/docs/guides/ssf-receiver/main/

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

# Example: Authentication policy rule requiring re-authentication when EDR risk is elevated.
# Requires an EDR provider to be configured first.
#
# resource "okta_app_signon_policy_rule" "edr_high_risk_reauth" {
#   policy_id = "<YOUR_POLICY_ID>"
#   name      = "Require Re-auth for High EDR Risk"
#   priority  = 1
#   status    = "ACTIVE"
#
#   # Require MFA when device EDR risk score is elevated
#   constraints = jsonencode([{
#     knowledge = {
#       types            = ["password"]
#       reauthenticateIn = "PT0S"
#     }
#   }])
#
#   # Okta Custom Expression for EDR risk signal (adjust to your EDR vendor's signal format)
#   custom_expression = "device.management.edrSignal.riskScore >= 70"
# }
`;
}

// ── Log queries ───────────────────────────────────────────────────────────────

function buildDeviceIntegrationLogQueries() {
  return [
    {
      description: 'User risk level change events',
      filter: 'eventType eq "user.risk.change"',
      timeWindow: 'last 30 days',
      note: 'Fires when a user\'s risk level changes. After configuring an EDR provider, EDR-driven risk elevations appear here as user.risk.change events.',
    },
    {
      description: 'Sign-in authentication blocked by device/EDR policy',
      filter: 'eventType eq "user.authentication.auth_via_mfa" AND outcome.reason co "Device"',
      timeWindow: 'last 7 days',
      note: 'After updating auth policies to use EDR signals, blocked authentications from non-compliant devices appear here.',
    },
    {
      description: 'Security events provider configuration changes (SSF audit trail)',
      filter: 'eventType sw "security.events.provider."',
      timeWindow: 'last 90 days',
      note: 'Audit trail for SSF/security events provider lifecycle: security.events.provider.create/activate/deactivate/update/delete.',
    },
    {
      description: 'Okta Verify device activations and enrollments (EDR enrichment)',
      filter: 'eventType eq "device.lifecycle.activate" OR eventType eq "device.enrollment.create"',
      timeWindow: 'last 7 days',
      note: 'After enabling EDR, new device activations and enrollments will carry EDR signal data in their debug context.',
    },
    {
      description: 'Sign-on policy evaluation — verify device signals reach the policy engine',
      filter: 'eventType eq "policy.evaluate_sign_on"',
      timeWindow: 'last 24 hours',
      note: 'Inspect debugContext.debugData for device signal data to confirm EDR signals are flowing to the policy engine.',
    },
  ];
}

// ── Admin console steps ───────────────────────────────────────────────────────

function buildEDRIntegrationAdminSteps() {
  return [
    'Sign in to the Okta Admin Console.',
    'Go to Security > Device Integrations > Endpoint Detection and Response.',
    'Click "Add EDR Integration" and select your vendor:',
    '  CrowdStrike Falcon    — requires CrowdStrike API credentials (Client ID + Secret)',
    '  Carbon Black Cloud    — requires VMware Carbon Black API credentials',
    '  Microsoft Defender    — requires Entra ID app registration',
    '  SentinelOne           — requires SentinelOne API token',
    '  (see full list at https://help.okta.com/en-us/content/topics/identity-engine/devices/edr-integration-main.htm)',
    'Configure API credentials from your EDR vendor console.',
    'Test the connection and verify device signals are flowing.',
    'Once EDR is active, update Authentication Policies:',
    '  Go to Security > Authentication Policies.',
    '  Edit a policy and add a rule for elevated EDR risk:',
    '    - Condition: device EDR risk signal is HIGH or a policy violation is detected',
    '    - Action: require MFA re-authentication or DENY access',
    'Test by verifying System Log shows device signals in policy evaluation events.',
    'Resources:',
    '  EDR integration setup    : https://help.okta.com/en-us/content/topics/identity-engine/devices/edr-integration-main.htm',
    '  Available EDR signals    : https://help.okta.com/en-us/content/topics/identity-engine/devices/edr-integration-available-signals.htm',
  ];
}

// ── Risk assessment ───────────────────────────────────────────────────────────

function buildDeviceIntegrationRiskAssessment() {
  return {
    teaSeverity: 'MODERATE',
    changeRisk:  'MODERATE',
    summary:
      'EDR integration enriches Okta\'s policy engine with real-time endpoint security context. ' +
      'A device flagged as compromised by CrowdStrike, Defender, or similar can be blocked or ' +
      'challenged at the Okta authentication layer before the attacker reaches the application. ' +
      'Key defence against T1557 (adversary-in-the-middle) and T1539 (steal web session cookie) — ' +
      'an attacker may have valid credentials but the compromised device itself is flagged by EDR.',
    preChangeChecks: [
      'Deploy Okta Verify to all managed devices before connecting the EDR provider — Okta Verify is required to collect device health signals.',
      'Coordinate with your security team to understand EDR false positive rates before enforcing Okta policy actions.',
      'Identify whether any unmanaged or BYOD devices are used for Okta sign-in — they will not have EDR coverage and may be excluded from policy enforcement.',
      'Confirm the EDR provider is generating meaningful signals by reviewing device.lifecycle events over the last 30 days.',
    ],
    blastRadius:
      'EDR false positives can block or challenge legitimate users on flagged devices. ' +
      'The blast radius depends on how aggressively EDR flags devices and the accuracy of EDR tuning. ' +
      'Initial deployment should use REAUTHENTICATE (not DENY) on medium EDR risk ' +
      'until you have confidence in the false positive rate. ' +
      'Only DENY on the highest severity EDR signals (active compromise, malware executing).',
    rolloutSteps: [
      'Step 1 — Deploy Okta Verify to managed devices (required to collect device health signals).',
      'Step 2 — Configure EDR provider under Security > Device Integrations.',
      'Step 3 — Verify devices are enrolling in Okta Verify (device.lifecycle.activate events in System Log).',
      'Step 4 — Add authentication policy rules: REAUTHENTICATE on medium EDR risk (not DENY).',
      'Step 5 — Monitor for EDR false positives over 2–4 weeks.',
      'Step 6 — Add authentication policy rules: DENY on high EDR risk after monitoring confirms low false positive rate.',
      'Step 7 — Enable ITP Session Protection to terminate sessions when risk increases post-authentication.',
    ],
    postChangeMonitoring: {
      description:
        'After wiring EDR signals to authentication policy rules, watch for REAUTHENTICATE or DENY outcomes ' +
        'on legitimate users. Coordinate with the security team to distinguish EDR false positives from real incidents.',
      logQueries: [
        {
          description: 'Authentication policy DENY events linked to device risk',
          filter: 'eventType eq "user.session.start" AND outcome.result eq "DENY"',
          timeWindow: 'first 14 days post-change',
          note: 'Each DENY here could be a real threat or an EDR false positive. Investigate actor and device context for each event.',
        },
        {
          description: 'Device enrollment events (Okta Verify activation)',
          filter: 'eventType eq "device.lifecycle.activate"',
          timeWindow: 'first 14 days post-change',
          note: 'Shows devices being enrolled in Okta Verify. Note: Okta does not emit events for individual EDR health signal updates — verify EDR signal flow by checking device context in user.session.start events.',
        },
      ],
    },
    rollback:
      'Remove the EDR provider from Security > Device Integrations. Authentication policy rules ' +
      'referencing EDR signals will need to be updated separately. No user data is affected.',
  };
}

// ── Tool registration ─────────────────────────────────────────────────────────

function registerDeviceIntegrationTools(server) {
  server.tool(
    'okta_get_device_integration_config',
    'Audit Okta Device Integration and Endpoint Detection and Response (EDR) configuration. ' +
    'Checks: (1) Whether an EDR vendor or Shared Signals Framework (SSF) provider is connected; ' +
    '(2) Whether Authentication Policy rules incorporate EDR device signals to challenge or block ' +
    'high-risk devices. ' +
    'Returns findings with supported EDR vendor setup guidance and authentication policy recommendations.',
    {},
    async () => {
      if (process.env.OFFLINE_MODE === 'true') {
        return buildMcpOffline({
          remediation: {
            terraform:         buildDeviceIntegrationTerraform(),
            logQueries:        buildDeviceIntegrationLogQueries(),
            adminConsoleSteps: buildEDRIntegrationAdminSteps(),
            riskAssessment:    buildDeviceIntegrationRiskAssessment(),
          },
        });
      }
      try {
        const client = await createOktaClient();
        const [ssfProviders, riskProviders, authPolicies] = await Promise.all([
          fetchSSFProviders(client),
          fetchRiskProviders(client),
          fetchAuthPolicies(client),
        ]);

        const audit = auditDeviceIntegration({ ssfProviders, riskProviders, authPolicies });

        return buildMcpOk({
          summary: {
            findingCount: audit.findingCount,
            hasEDRIntegration: audit.edrStatus.hasEDRIntegration,
            apiCoverage: audit.apiCoverage,
          },
          findings: audit.findings,
          edrStatus: audit.edrStatus,
          supportedEDRVendors: [
            { vendor: 'CrowdStrike Falcon',    docs: 'https://help.okta.com/en-us/content/topics/identity-engine/devices/edr-integration-main.htm' },
            { vendor: 'VMware Carbon Black',   docs: 'https://help.okta.com/en-us/content/topics/identity-engine/devices/edr-integration-main.htm' },
            { vendor: 'Microsoft Defender',    docs: 'https://help.okta.com/en-us/content/topics/identity-engine/devices/edr-integration-main.htm' },
            { vendor: 'SentinelOne',           docs: 'https://help.okta.com/en-us/content/topics/identity-engine/devices/edr-integration-main.htm' },
          ],
          remediation: {
            terraform: buildDeviceIntegrationTerraform(),
            logQueries: buildDeviceIntegrationLogQueries(),
            adminConsoleSteps: buildEDRIntegrationAdminSteps(),
            riskAssessment: buildDeviceIntegrationRiskAssessment(),
          },
        });
      } catch (err) {
        return buildMcpError(err);
      }
    },
  );
}

module.exports = {
  registerDeviceIntegrationTools,
  auditDeviceIntegration,
  buildDeviceIntegrationLogQueries,
  buildDeviceIntegrationRiskAssessment,
};
