'use strict';

const { buildMcpOk, buildMcpError, buildMcpOffline, buildMcpReadOnly } = require('./resolver-utils');
const { createOktaClient } = require('../auth/okta-client');

// ── API paths ─────────────────────────────────────────────────────────────────

// Okta Management API: Attack Protection settings (OIE)
const ATTACK_PROTECTION_PATH = '/api/v1/attack_protection';
// Okta Management API: Org-level settings
const ORG_SETTINGS_PATH = '/api/v1/org';

// Feature names used to match against /api/v1/features response
const UNKNOWN_DEVICE_FEATURE_NAMES = [
  'UNKNOWN_DEVICE_LOCKOUT_PROTECTION',
  'UNKNOWN_DEVICE',
  'DETECT_LOCKOUTS_UNKNOWN_DEVICES',
];

const SUSPICIOUS_ACTIVITY_FEATURE_NAMES = [
  'SUSPICIOUS_ACTIVITY_REPORTING',
  'REPORT_SUSPICIOUS_ACTIVITY',
  'END_USER_SUSPICIOUS_ACTIVITY',
];

// ── Settings fetchers ─────────────────────────────────────────────────────────

async function fetchAttackProtectionSettings(client) {
  try {
    const { data } = await client.get(ATTACK_PROTECTION_PATH);
    return { available: true, data };
  } catch (err) {
    const status = err.response?.status;
    if (status === 404 || status === 403) {
      return { available: false, reason: `API returned ${status} — attack protection endpoint may require OIE or specific scopes.` };
    }
    return { available: false, reason: err.message };
  }
}

async function fetchFeatures(client) {
  try {
    const { data } = await client.get('/api/v1/features');
    return { available: true, features: data };
  } catch (err) {
    return { available: false, reason: err.message, features: [] };
  }
}

async function fetchOrgSettings(client) {
  try {
    const { data } = await client.get(ORG_SETTINGS_PATH);
    return { available: true, data };
  } catch (err) {
    return { available: false, reason: err.message };
  }
}

// ── Audit helpers ──────────────────────────────────────────────────────────────

function matchFeature(features, nameList) {
  return features.find((f) =>
    nameList.some((n) => f.name?.toUpperCase().includes(n) || f.id?.toUpperCase().includes(n))
  ) || null;
}

function auditSecuritySettings({ attackProtection, features, orgSettings }) {
  const findings = [];
  const featureList = features.available ? (features.features || []) : [];

  //  — Block suspicious password attempts from unknown devices
  const unknownDeviceFeature = matchFeature(featureList, UNKNOWN_DEVICE_FEATURE_NAMES);
  const unknownDeviceStatus = unknownDeviceFeature?.status || null;
  const unknownDeviceEnabled =
    unknownDeviceStatus === 'ENABLED' ||
    attackProtection.data?.unknownDevice?.action === 'BLOCK';

  if (!unknownDeviceEnabled) {
    findings.push({
      id: 'UNKNOWN_DEVICE_BLOCKING',
      severity: 'LOW',
      description:
        '"Block suspicious password attempts from unknown devices" is not enabled. ' +
        'When a new device attempts excessive failed logins, Okta should lock attempts ' +
        'from that device while allowing sign-ins from known devices.',
      recommendation:
        'Enable "Block suspicious password attempts from unknown devices" in Security > General.',
      apiPath: `${ATTACK_PROTECTION_PATH} / /api/v1/features`,
      detectedVia: unknownDeviceFeature ? 'features API' : 'not detected via API — manual check required',
    });
  }

  // Report suspicious activity via email
  const suspiciousActivityFeature = matchFeature(featureList, SUSPICIOUS_ACTIVITY_FEATURE_NAMES);
  const suspiciousActivityStatus = suspiciousActivityFeature?.status || null;
  const suspiciousActivityEnabled =
    suspiciousActivityStatus === 'ENABLED' ||
    orgSettings.data?.settings?.app?.interstitialMinWaitTime !== undefined; // proxy heuristic

  if (!suspiciousActivityEnabled) {
    findings.push({
      id: 'SUSPICIOUS_ACTIVITY_REPORTING',
      severity: 'LOW',
      description:
        '"Report suspicious activity via email" is not enabled. ' +
        'This feature adds a "Report Suspicious Activity" link to notification emails, ' +
        'allowing users to escalate unexpected sign-in events to your security team.',
      recommendation:
        'Enable "Report suspicious activity via email" in Security > General.',
      apiPath: '/api/v1/features',
      detectedVia: suspiciousActivityFeature ? 'features API' : 'not detected via API — manual check required',
    });
  }

  return {
    findingCount: findings.length,
    findings,
    rawStatus: {
      attackProtection: attackProtection.available
        ? { available: true, summary: attackProtection.data }
        : { available: false, reason: attackProtection.reason },
      unknownDeviceFeature: unknownDeviceFeature
        ? { id: unknownDeviceFeature.id, name: unknownDeviceFeature.name, status: unknownDeviceFeature.status }
        : null,
      suspiciousActivityFeature: suspiciousActivityFeature
        ? { id: suspiciousActivityFeature.id, name: suspiciousActivityFeature.name, status: suspiciousActivityFeature.status }
        : null,
    },
  };
}

// ── Terraform builder ──────────────────────────────────────────────────────────

function buildSecurityGeneralTerraform() {
  return `# Terraform — Okta Security General settings
#
# Provider setup:
#   https://developer.okta.com/docs/guides/terraform-enable-org-access/main/
#
# NOTE: "Block suspicious password attempts from unknown devices" and
# "Report suspicious activity via email" are configured in the Okta Admin Console
# under Security > General. These settings may not be directly available via the
# Terraform Okta provider — verify current provider support at:
#   https://registry.terraform.io/providers/okta/okta/latest/docs
#
# For ThreatInsight (related setting), use the okta_threat_insight_settings resource:
#   https://registry.terraform.io/providers/okta/okta/latest/docs/resources/threat_insight_settings

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
  scopes      = ["okta.orgs.manage"]
  private_key = "<PATH_OR_CONTENT_OF_PRIVATE_KEY>"
}

# If available as a feature toggle in your tenant,
# enable via okta_org_configuration or org settings resources.
# Check: https://registry.terraform.io/providers/okta/okta/latest/docs/resources/org_configuration
resource "okta_org_configuration" "settings" {
  company_name = "<YOUR_COMPANY_NAME>"

  # These fields control end-user security notifications:
  # end_user_dashboard_touch_point_variant, opt_out_of_communicating_with_okta_support_tools
  # Consult provider docs for the exact attribute that maps to your tenant's setting.
}
`;
}

// ── Log queries ────────────────────────────────────────────────────────────────

function buildSecurityGeneralLogQueries() {
  return [
    {
      description: 'Suspicious activity reports from end users',
      filter: 'eventType eq "user.account.report_suspicious_activity_by_enduser"',
      timeWindow: 'last 30 days',
      note: 'After enabling suspicious activity reporting, user-submitted reports appear here. A volume spike may indicate an active attack.',
    },
    {
      description: 'Security setting changes — audit trail',
      filter: 'eventType sw "security."',
      timeWindow: 'last 90 days',
      note: 'Broad filter matching all security.* events. Useful for auditing when Security > General settings changed.',
    },
    {
      description: 'Attack protection configuration updates',
      filter: 'eventType eq "security.attack_protection.settings.update"',
      timeWindow: 'last 90 days',
      note: 'Tracks changes to attack protection settings including unknown device blocking.',
    },
    {
      description: 'Unknown device lockout events',
      filter: 'eventType eq "user.account.lock"',
      timeWindow: 'last 7 days',
      note: 'After enabling unknown device blocking, lockout events from suspicious new devices will appear here.',
    },
    {
      description: 'ThreatInsight detections (related security control)',
      filter: 'eventType eq "security.threat.detected"',
      timeWindow: 'last 7 days',
      note: 'ThreatInsight and unknown device blocking are complementary controls — monitor both.',
    },
  ];
}

// ── Admin console steps ────────────────────────────────────────────────────────

function buildUnknownDeviceAdminSteps() {
  return [
    'Sign in to the Okta Admin Console.',
    'Go to Security > General.',
    'Scroll to the "Attack Protection" section.',
    'Find "Block suspicious password attempts from unknown devices".',
    'Toggle it to Enabled.',
    'Click Save.',
    'Verify the change: Reports > System Log, filter eventType eq "security.attack_protection.settings.update".',
    'NOTE: This feature detects when excessive failed password attempts originate from a new/unknown ' +
    'device and blocks further attempts from that device — while keeping access open from known devices.',
  ];
}

function buildSuspiciousActivityAdminSteps() {
  return [
    'Sign in to the Okta Admin Console.',
    'Go to Security > General.',
    'Scroll to the "Security Notifications" section.',
    'Find "Report suspicious activity via email".',
    'Toggle it to Enabled.',
    'Click Save.',
    'Verify: Users will now see a "Report Suspicious Activity" link in Okta notification emails.',
    'After enabling, monitor Reports > System Log for user.account.report_suspicious_activity_by_enduser events.',
  ];
}

// ── Risk assessment ────────────────────────────────────────────────────────────

function buildSecurityGeneralRiskAssessment() {
  return {
    teaSeverity: 'LOW',
    changeRisk:  'LOW',
    summary:
      'Both settings in this module are low-implementation-impact and have no adverse user effect. ' +
      '"Block suspicious password attempts from unknown devices" adds a targeted defence against ' +
      'distributed brute force without disrupting legitimate users. ' +
      '"Report suspicious activity via email" creates a human reporting channel for your security team.',
    preChangeChecks: [
      'No prerequisites for either setting — both are safe to enable immediately.',
      'Unknown device blocking targets only new/unknown devices triggering excessive failures — legitimate users on known devices are never blocked.',
    ],
    blastRadius:
      'Enabling unknown device blocking may result in additional lockout events for devices that are new ' +
      'or rotate IPs frequently (e.g., mobile users on cellular networks). These are genuine security signals, ' +
      'not false positives — investigate each lockout. ' +
      '"Report suspicious activity via email" adds a link to notification emails — users on read-only ' +
      'email addresses may receive unexpected emails, but this is a security improvement.',
    rolloutSteps: [
      'Step 1 — Enable "Block suspicious password attempts from unknown devices".',
      'Step 2 — Enable "Report suspicious activity via email".',
      'Step 3 — Monitor System Log for lockout and suspicious activity report events.',
      'Step 4 — Review ThreatInsight settings (okta_get_threatinsight_config) as a complementary control.',
    ],
    postChangeMonitoring: {
      description:
        'After enabling these settings, watch for any unusual spike in device lockouts and confirm ' +
        'suspicious activity reports are flowing through to your security team.',
      logQueries: [
        {
          description: 'Unknown device blocking events',
          filter: 'eventType eq "user.account.lock" AND outcome.reason co "unknown device"',
          timeWindow: 'first 7 days post-change',
          note: 'Each event here is a new/unknown device that exceeded the password attempt threshold.',
        },
        {
          description: 'User-submitted suspicious activity reports',
          filter: 'eventType eq "user.account.report_suspicious_activity_by_enduser"',
          timeWindow: 'first 30 days post-change',
          note: 'These events appear when a user clicks "Report Suspicious Activity" in a notification email. Should increase after enabling the feature.',
        },
      ],
    },
    rollback:
      'Both settings can be disabled immediately from Security > General with no session impact.',
  };
}

// ── Tool registration ─────────────────────────────────────────────────────────

function registerSecurityGeneralTools(server) {
  server.tool(
    'okta_get_security_general_settings',
    'Audit Okta Security > General settings relevant to the TEA report. ' +
    'Checks: "Block suspicious password attempts from unknown devices" and ' +
    '"Report suspicious activity via email". ' +
    'Reads from the attack protection API and features API with graceful fallback when ' +
    'endpoints are not available — manual verification steps are always returned.',
    {},
    async () => {
      if (process.env.OFFLINE_MODE === 'true') {
        return buildMcpOffline({
          remediation: {
            terraform:         buildSecurityGeneralTerraform(),
            logQueries:        buildSecurityGeneralLogQueries(),
            adminConsoleSteps: {
              unknownDeviceBlocking:       buildUnknownDeviceAdminSteps(),
              suspiciousActivityReporting: buildSuspiciousActivityAdminSteps(),
            },
            riskAssessment:    buildSecurityGeneralRiskAssessment(),
          },
        });
      }
      try {
        const client = await createOktaClient();

        const [attackProtection, features, orgSettings] = await Promise.all([
          fetchAttackProtectionSettings(client),
          fetchFeatures(client),
          fetchOrgSettings(client),
        ]);

        const audit = auditSecuritySettings({ attackProtection, features, orgSettings });

        return buildMcpOk({
          summary: {
            findingCount: audit.findingCount,
            apiCoverage: {
              attackProtectionAvailable: attackProtection.available,
              featuresAvailable: features.available,
              orgSettingsAvailable: orgSettings.available,
            },
            note: !attackProtection.available && !features.available
              ? 'Security General settings could not be read via API — use manual console steps below to verify and remediate.'
              : null,
          },
          findings: audit.findings,
          rawStatus: audit.rawStatus,
          remediation: {
            terraform: buildSecurityGeneralTerraform(),
            logQueries: buildSecurityGeneralLogQueries(),
            adminConsoleSteps: {
              unknownDeviceBlocking: buildUnknownDeviceAdminSteps(),
              suspiciousActivityReporting: buildSuspiciousActivityAdminSteps(),
            },
            riskAssessment: buildSecurityGeneralRiskAssessment(),
          },
        });
      } catch (err) {
        return buildMcpError(err);
      }
    },
  );

  server.tool(
    'okta_enable_suspicious_device_blocking',
    'Attempt to enable "Block suspicious password attempts from unknown devices" ' +
    'via the Okta attack protection API (MITRE T1110). ' +
    'If the API endpoint is not available on this tenant, returns manual admin console ' +
    'steps to enable the setting directly. Write operation — confirm before calling.',
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
        let apiResult = null;
        let apiAvailable = false;

        try {
          const { data: current } = await client.get(ATTACK_PROTECTION_PATH);
          const payload = {
            ...current,
            unknownDevice: {
              ...(current.unknownDevice || {}),
              action: 'BLOCK',
            },
          };
          const { data: updated } = await client.post(ATTACK_PROTECTION_PATH, payload);
          apiResult = updated;
          apiAvailable = true;
        } catch (apiErr) {
          const status = apiErr.response?.status;
          if (status !== 404 && status !== 405) {
            throw apiErr;
          }
          // Endpoint not available — fall through to manual steps
        }

        return buildMcpOk({
          message: apiAvailable
            ? 'Unknown device blocking enabled via attack protection API.'
            : 'Attack protection API not available on this tenant — follow manual steps below to enable this setting.',
          apiAvailable,
          apiResult,
          remediation: {
            terraform: buildSecurityGeneralTerraform(),
            logQueries: buildSecurityGeneralLogQueries(),
            adminConsoleSteps: buildUnknownDeviceAdminSteps(),
            riskAssessment: buildSecurityGeneralRiskAssessment(),
          },
        });
      } catch (err) {
        return buildMcpError(err);
      }
    },
  );

  server.tool(
    'okta_enable_suspicious_activity_reporting',
    'Attempt to enable "Report suspicious activity via email" via the Okta features API ' +
    '(). If the API endpoint is not available, returns manual admin console ' +
    'steps to enable the setting directly. Write operation — confirm before calling.',
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
        let apiResult = null;
        let apiAvailable = false;

        try {
          const { data: allFeatures } = await client.get('/api/v1/features');
          const feature = matchFeature(allFeatures, SUSPICIOUS_ACTIVITY_FEATURE_NAMES);

          if (feature && feature.status !== 'ENABLED') {
            const { data: enabled } = await client.post(
              `/api/v1/features/${feature.id}/lifecycle/enable`,
              {},
            );
            apiResult = enabled;
            apiAvailable = true;
          } else if (feature && feature.status === 'ENABLED') {
            apiResult = feature;
            apiAvailable = true;
            return buildMcpOk({
              message: '"Report suspicious activity via email" is already enabled.',
              apiAvailable: true,
              apiResult,
              remediation: {
                terraform: buildSecurityGeneralTerraform(),
                logQueries: buildSecurityGeneralLogQueries(),
                adminConsoleSteps: buildSuspiciousActivityAdminSteps(),
                riskAssessment: buildSecurityGeneralRiskAssessment(),
              },
            });
          }
          // Feature not found in features API — fall through to manual steps
        } catch (apiErr) {
          const status = apiErr.response?.status;
          if (status !== 404 && status !== 405 && status !== 403) {
            throw apiErr;
          }
        }

        return buildMcpOk({
          message: apiAvailable
            ? 'Suspicious activity reporting enabled via features API.'
            : '"Report suspicious activity via email" feature not found via API — follow manual steps below.',
          apiAvailable,
          apiResult,
          remediation: {
            terraform: buildSecurityGeneralTerraform(),
            logQueries: buildSecurityGeneralLogQueries(),
            adminConsoleSteps: buildSuspiciousActivityAdminSteps(),
            riskAssessment: buildSecurityGeneralRiskAssessment(),
          },
        });
      } catch (err) {
        return buildMcpError(err);
      }
    },
  );
}

module.exports = {
  registerSecurityGeneralTools,
  auditSecuritySettings,
  buildSecurityGeneralLogQueries,
  buildSecurityGeneralRiskAssessment,
  matchFeature,
};
