'use strict';

const { z } = require('zod');
const { buildMcpOk, buildMcpError, buildMcpOffline, buildMcpReadOnly } = require('./resolver-utils');
const { createOktaClient } = require('../auth/okta-client');

const DEVICE_ASSURANCE_PATH = '/api/v1/device-assurances';

// Appendix B recommended checks from the TEA report.
// Each entry maps a platform + field to a human-readable validation name.
const RECOMMENDED_CHECKS = [
  // Jailbreak / Rooted detection
  { platform: 'ANDROID', checkName: 'Device Jailbreak Android',       field: 'jailbreak',             description: 'Restrict Android Rooted/Jailbroken Devices' },
  { platform: 'IOS',     checkName: 'Device Jailbreak iOS',           field: 'jailbreak',             description: 'Restrict iOS Jailbroken Devices' },
  // Disk Encryption
  { platform: 'ANDROID', checkName: 'Device Disk Encryption Android', field: 'diskEncryptionType',    description: 'Require Disk Encryption for Android Devices' },
  { platform: 'MACOS',   checkName: 'Device Disk Encryption macOS',   field: 'diskEncryptionType',    description: 'Require Disk Encryption for macOS Devices' },
  { platform: 'WINDOWS', checkName: 'Device Disk Encryption Windows', field: 'diskEncryptionType',    description: 'Require Disk Encryption for Windows Devices' },
  // Screen Lock
  { platform: 'ANDROID', checkName: 'Device Screen Lock Android',     field: 'screenLockType',        description: 'Require Screen Lock for Android Devices' },
  { platform: 'IOS',     checkName: 'Device Screen Lock iOS',         field: 'screenLockType',        description: 'Require Screen Lock for iOS Devices' },
  { platform: 'MACOS',   checkName: 'Device Screen Lock macOS',       field: 'screenLockType',        description: 'Require Screen Lock for macOS Devices' },
  { platform: 'WINDOWS', checkName: 'Device Screen Lock Windows',     field: 'screenLockType',        description: 'Require Screen Lock for Windows Devices' },
  // Secure Hardware
  { platform: 'ANDROID', checkName: 'Device Secure Hardware Android', field: 'secureHardwarePresent', description: 'Require Secure Hardware for Android Devices' },
  { platform: 'MACOS',   checkName: 'Device Secure Hardware macOS',   field: 'secureHardwarePresent', description: 'Require Secure Hardware for macOS Devices' },
  { platform: 'WINDOWS', checkName: 'Device Secure Hardware Windows', field: 'secureHardwarePresent', description: 'Require Secure Hardware for Windows Devices' },
  // OS Version
  { platform: 'ANDROID', checkName: 'Device Version Android',         field: 'osVersion',             description: 'Require the latest OS Version for Android Devices' },
  { platform: 'IOS',     checkName: 'Device Version iOS',             field: 'osVersion',             description: 'Require the latest OS Version for iOS Devices' },
  { platform: 'MACOS',   checkName: 'Device Version macOS',           field: 'osVersion',             description: 'Require the latest OS Version for macOS Devices' },
  { platform: 'WINDOWS', checkName: 'Device Version Windows',         field: 'osVersion',             description: 'Require the latest OS Version for Windows Devices' },
];

// ── Fetchers ───────────────────────────────────────────────────────────────────

async function fetchDeviceAssurancePolicies(client) {
  try {
    const { data } = await client.get(DEVICE_ASSURANCE_PATH);
    return { available: true, policies: Array.isArray(data) ? data : [] };
  } catch (err) {
    const status = err.response?.status;
    if (status === 404 || status === 403) {
      return {
        available: false,
        reason: `API returned ${status} — Device Assurance requires okta.deviceAssurance.read scope and the feature must be enabled for this tenant.`,
      };
    }
    return { available: false, reason: err.message };
  }
}

// ── Audit helpers ──────────────────────────────────────────────────────────────

function policyCoversCheck(policy, field) {
  switch (field) {
    case 'jailbreak':
      // jailbreak: false means jailbreak IS blocked (the secure state)
      return policy.jailbreak === false;
    case 'secureHardwarePresent':
      return policy.secureHardwarePresent === true;
    case 'diskEncryptionType':
      return Boolean(policy.diskEncryptionType?.include?.length);
    case 'screenLockType':
      return Boolean(policy.screenLockType?.include?.length);
    case 'osVersion':
      return Boolean(policy.osVersion?.minimum);
    default:
      return false;
  }
}

function auditDeviceAssurance(policies) {
  const findings = [];

  const policiesByPlatform = {
    ANDROID: policies.filter((p) => p.platform?.toUpperCase() === 'ANDROID'),
    IOS: policies.filter((p) => p.platform?.toUpperCase() === 'IOS'),
    MACOS: policies.filter((p) => p.platform?.toUpperCase() === 'MACOS'),
    WINDOWS: policies.filter((p) => p.platform?.toUpperCase() === 'WINDOWS'),
  };

  const coveredChecks = [];
  const missingChecks = [];

  for (const check of RECOMMENDED_CHECKS) {
    const platformPolicies = policiesByPlatform[check.platform] || [];
    const covered = platformPolicies.some((p) => policyCoversCheck(p, check.field));

    if (covered) {
      coveredChecks.push(check.checkName);
    } else {
      missingChecks.push({
        checkName: check.checkName,
        platform: check.platform,
        field: check.field,
        description: check.description,
        policiesFoundForPlatform: platformPolicies.length,
      });
    }
  }

  if (policies.length === 0) {
    findings.push({
      id: 'NO_DEVICE_ASSURANCE_POLICIES',
      severity: 'MODERATE',
      description:
        'No Device Assurance policies are configured. All devices are permitted to access Okta ' +
        'without any device security requirements — jailbroken, unencrypted, or outdated devices ' +
        'can authenticate freely.',
      recommendation:
        'Create Device Assurance policies for all platforms (Android, iOS, macOS, Windows) covering ' +
        'the Appendix B checks, then enforce them via Authentication Policy rules.',
    });
  } else if (missingChecks.length > 0) {
    findings.push({
      id: 'DEVICE_ASSURANCE_MISSING_CHECKS',
      severity: 'MODERATE',
      description:
        `${missingChecks.length} of ${RECOMMENDED_CHECKS.length} recommended device assurance checks ` +
        'from Appendix B are not covered by any policy. Devices failing these checks may still authenticate.',
      recommendation:
        'Update existing Device Assurance policies or create new ones to cover all Appendix B checks. ' +
        'Ensure policies are assigned in Authentication Policy rules.',
      missingChecks,
    });
  }

  return {
    findingCount: findings.length,
    findings,
    summary: {
      totalPolicies: policies.length,
      policiesByPlatform: Object.fromEntries(
        Object.entries(policiesByPlatform).map(([plat, pols]) => [plat, pols.length])
      ),
      recommendedChecksTotal: RECOMMENDED_CHECKS.length,
      coveredChecksCount: coveredChecks.length,
      missingChecksCount: missingChecks.length,
    },
    policies: policies.map((p) => ({
      id: p.id,
      name: p.name,
      platform: p.platform,
      status: p.status,
      checks: {
        jailbreak: p.jailbreak,
        diskEncryptionType: p.diskEncryptionType,
        screenLockType: p.screenLockType,
        secureHardwarePresent: p.secureHardwarePresent,
        osVersion: p.osVersion,
      },
    })),
    appendixBCoverage: RECOMMENDED_CHECKS.map((c) => ({
      checkName: c.checkName,
      platform: c.platform,
      description: c.description,
      covered: coveredChecks.includes(c.checkName),
    })),
  };
}

// ── Default policy payloads per platform ──────────────────────────────────────

function buildDeviceAssurancePayload(platform, name, osVersionMinimum) {
  const PLATFORM_DEFAULTS = {
    ANDROID: {
      jailbreak: false,
      secureHardwarePresent: true,
      diskEncryptionType: { include: ['USER', 'FULL'] },
      screenLockType: { include: ['BIOMETRIC', 'PASSCODE'] },
      osVersion: { minimum: osVersionMinimum || '12' },
    },
    IOS: {
      jailbreak: false,
      screenLockType: { include: ['BIOMETRIC', 'PASSCODE'] },
      osVersion: { minimum: osVersionMinimum || '16.0' },
    },
    MACOS: {
      secureHardwarePresent: true,
      diskEncryptionType: { include: ['ALL_INTERNAL_VOLUMES'] },
      screenLockType: { include: ['BIOMETRIC', 'PASSCODE'] },
      osVersion: { minimum: osVersionMinimum || '13.0.0' },
    },
    WINDOWS: {
      secureHardwarePresent: true,
      diskEncryptionType: { include: ['ALL_INTERNAL_VOLUMES'] },
      screenLockType: { include: ['BIOMETRIC', 'PASSCODE'] },
      osVersion: { minimum: osVersionMinimum || '10.0.22000.0' },
    },
  };

  const platformUpper = platform.toUpperCase();
  return {
    name: name || `${platformUpper.charAt(0) + platformUpper.slice(1).toLowerCase()} Device Assurance`,
    platform: platformUpper,
    ...(PLATFORM_DEFAULTS[platformUpper] || {}),
  };
}

// ── Terraform ─────────────────────────────────────────────────────────────────

function buildDeviceAssuranceTerraform(platform) {
  const p = (platform || 'ANDROID').toUpperCase();

  const PLATFORM_RESOURCE = {
    ANDROID: `resource "okta_policy_device_assurance_android" "android" {
  name = "Android Device Assurance"

  #  — Appendix B recommended checks
  jailbreak               = false
  secure_hardware_present = true

  disk_encryption_type = {
    include = ["USER", "FULL"]
  }

  screen_lock_type = {
    include = ["BIOMETRIC", "PASSCODE"]
  }

  os_version = {
    minimum = "12"  # Adjust to your supported minimum
  }
}`,
    IOS: `resource "okta_policy_device_assurance_ios" "ios" {
  name = "iOS Device Assurance"

  jailbreak = false

  screen_lock_type = {
    include = ["BIOMETRIC", "PASSCODE"]
  }

  os_version = {
    minimum = "16.0.0"
  }
}`,
    MACOS: `resource "okta_policy_device_assurance_macos" "macos" {
  name = "macOS Device Assurance"

  secure_hardware_present = true

  disk_encryption_type = {
    include = ["ALL_INTERNAL_VOLUMES"]
  }

  screen_lock_type = {
    include = ["BIOMETRIC", "PASSCODE"]
  }

  os_version = {
    minimum = "13.0.0"
  }
}`,
    WINDOWS: `resource "okta_policy_device_assurance_windows" "windows" {
  name = "Windows Device Assurance"

  secure_hardware_present = true

  disk_encryption_type = {
    include = ["ALL_INTERNAL_VOLUMES"]
  }

  screen_lock_type = {
    include = ["BIOMETRIC", "PASSCODE"]
  }

  os_version = {
    minimum = "10.0.22000.0"
  }
}`,
  };

  return `# Terraform — Okta Device Assurance Policies
#  — Update Device Assurance Policies (Appendix B)
#
# Resource references:
#   https://registry.terraform.io/providers/okta/okta/latest/docs/resources/policy_device_assurance_android
#   https://registry.terraform.io/providers/okta/okta/latest/docs/resources/policy_device_assurance_ios
#   https://registry.terraform.io/providers/okta/okta/latest/docs/resources/policy_device_assurance_macos
#   https://registry.terraform.io/providers/okta/okta/latest/docs/resources/policy_device_assurance_windows
#
# After creating policies, assign them in Authentication Policy rules:
#   https://help.okta.com/en-us/content/topics/identity-engine/devices/device-assurance.htm

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
  scopes      = ["okta.deviceAssurance.manage"]
  private_key = "<PATH_OR_CONTENT_OF_PRIVATE_KEY>"
}

${PLATFORM_RESOURCE[p] || PLATFORM_RESOURCE.ANDROID}
`;
}

// ── Log queries ───────────────────────────────────────────────────────────────

function buildDeviceAssuranceLogQueries() {
  return [
    {
      description: 'Device assurance policy evaluation failures — blocked devices',
      filter: 'eventType eq "policy.evaluate_sign_on" AND outcome.reason co "Device assurance"',
      timeWindow: 'last 7 days',
      note: 'After assigning device assurance to authentication policies, blocked sign-ins from non-compliant devices appear here.',
    },
    {
      description: 'Device assurance policy changes — audit trail',
      filter: 'eventType sw "device.assurance."',
      timeWindow: 'last 90 days',
      note: 'Tracks creation, updates, and deletions of device assurance policies (device.assurance.policy.add/update/delete).',
    },
    {
      description: 'Okta Verify device enrollments — signals health data collection',
      filter: 'eventType eq "device.enrollment.create" OR eventType eq "device.lifecycle.activate"',
      timeWindow: 'last 7 days',
      note: 'Okta Verify must be installed on devices for health signals (disk encryption, screen lock, OS version) to be reported.',
    },
    {
      description: 'Sign-on policy evaluation with device context',
      filter: 'eventType eq "user.authentication.sso"',
      timeWindow: 'last 24 hours',
      note: 'Check debugContext.debugData for device health signals to verify device assurance is being evaluated.',
    },
    {
      description: 'Authentication policy denials — non-compliant device access attempts',
      filter: 'eventType eq "user.authentication.auth_via_mfa" AND outcome.result eq "FAILURE"',
      timeWindow: 'last 7 days',
      note: 'Failed MFA authentications from non-compliant devices will appear here after policy enforcement.',
    },
  ];
}

// ── Admin console steps ───────────────────────────────────────────────────────

function buildDeviceAssuranceAdminSteps() {
  return [
    'Sign in to the Okta Admin Console.',
    'Go to Security > Device Assurance Policies.',
    'Click "Add a Policy" and select the platform:',
    '  Android  — Enable: Jailbreak/Root protection, Disk Encryption, Screen Lock, Secure Hardware, OS Version minimum',
    '  iOS      — Enable: Jailbreak protection, Screen Lock, OS Version minimum',
    '  macOS    — Enable: Disk Encryption (FileVault), Screen Lock, Secure Hardware (T2/Apple Silicon), OS Version minimum',
    '  Windows  — Enable: Disk Encryption (BitLocker), Screen Lock, Secure Hardware (TPM), OS Version minimum',
    'Save each device assurance policy.',
    'Go to Security > Authentication Policies.',
    'Edit each policy that should enforce device compliance and click "Add Rule":',
    '  - Under "Device", select the device assurance policy for the appropriate platform.',
    '  - Set the action: ALLOW only if device assurance is met; DENY otherwise.',
    'Consider a phased rollout: start in report-only mode before enforcing.',
    'Communicate the compliance deadline to users — they must install Okta Verify and meet OS/encryption requirements.',
    'Resources: https://help.okta.com/en-us/content/topics/identity-engine/devices/device-assurance.htm',
    'Appendix B reference: https://help.okta.com/en-us/content/topics/identity-engine/devices/device-assurance.htm',
  ];
}

// ── Risk assessment ───────────────────────────────────────────────────────────

function buildDeviceAssuranceRiskAssessment() {
  return {
    teaSeverity: 'MODERATE',
    changeRisk:  'MODERATE',
    summary:
      'Device Assurance ensures only compliant devices access Okta-protected resources. ' +
      'Without it, a compromised device (jailbroken, unencrypted, outdated OS) can be used to ' +
      'access all apps the user is assigned to. This is meaningful defence against ' +
      'T1110 (brute force from compromised endpoints), T1451 (SIM swapping on mobile devices), ' +
      'and T1557 (adversary-in-the-middle using compromised device to bypass MFA).',
    preChangeChecks: [
      'Inventory the device platforms in use across your user population (Android, iOS, macOS, Windows).',
      'Confirm Okta Verify is deployed to managed devices — Device Assurance requires the Okta Verify app to collect device health signals.',
      'Identify BYOD populations: personal devices may not meet corporate OS version or encryption requirements.',
      'Set OS version minimums conservatively (one major version behind latest) to avoid blocking most of the fleet.',
      'Run the device.lifecycle.activate queries to understand how many devices are already enrolled in Okta Verify.',
    ],
    blastRadius:
      'Enforcing device assurance blocks users on non-compliant devices. Common blockers: ' +
      'devices running old OS versions, BYOD devices without disk encryption, devices not enrolled ' +
      'in Okta Verify. The blast radius scales with how strictly the OS version minimum is set ' +
      'and how many unmanaged or BYOD devices exist in your tenant. ' +
      'Plan a grace period and user communication campaign before enforcing.',
    rolloutSteps: [
      'Step 1 — Create device assurance policies for all platforms using Appendix B checks.',
      'Step 2 — Deploy Okta Verify to managed devices to collect device health signals.',
      'Step 3 — Run in report-only mode for 2–4 weeks to identify non-compliant device populations.',
      'Step 4 — Communicate compliance requirements and set a remediation deadline.',
      'Step 5 — Enable enforcement in authentication policies after the grace period.',
      'Step 6 — Monitor System Log for blocked sign-ins (see postChangeMonitoring queries).',
    ],
    postChangeMonitoring: {
      description:
        'After enabling enforcement, monitor for unexpected sign-in failures from legitimate users ' +
        'on non-compliant devices. Watch for a spike in help desk tickets about device access issues.',
      logQueries: [
        {
          description: 'Sign-in failures due to device assurance policy',
          filter: 'eventType eq "user.session.start" AND outcome.result eq "DENY" AND outcome.reason co "device"',
          timeWindow: 'first 7 days post-enforcement',
          note: 'Each DENY here is a user blocked by device assurance. Review actor.displayName to identify impacted users.',
        },
        {
          description: 'Device enrollment events',
          filter: 'eventType eq "device.lifecycle.activate"',
          timeWindow: 'first 14 days post-change',
          note: 'A rising trend here means users are enrolling their devices to meet the new requirement.',
        },
      ],
    },
    rollback:
      'Remove the device assurance policy assignment from authentication policy rules to stop ' +
      'enforcement immediately. The device assurance policies themselves can remain in place.',
  };
}

// ── Tool registration ─────────────────────────────────────────────────────────

function registerDeviceAssuranceTools(server) {
  server.tool(
    'okta_list_device_assurance_policies',
    'Audit Okta Device Assurance policies against TEA report Appendix B recommendations. ' +
    'Lists all policies across platforms (Android, iOS, macOS, Windows) and flags missing checks: ' +
    'jailbreak detection, disk encryption, screen lock, secure hardware presence, and OS version minimums. ' +
    'Returns a per-check coverage matrix mapped to the Appendix B table.',
    {},
    async () => {
      if (process.env.OFFLINE_MODE === 'true') {
        return buildMcpOffline({
          remediation: {
            terraform:         buildDeviceAssuranceTerraform('ANDROID'),
            logQueries:        buildDeviceAssuranceLogQueries(),
            adminConsoleSteps: buildDeviceAssuranceAdminSteps(),
            riskAssessment:    buildDeviceAssuranceRiskAssessment(),
          },
        });
      }
      try {
        const client = await createOktaClient();
        const { available, policies, reason } = await fetchDeviceAssurancePolicies(client);

        if (!available) {
          return buildMcpOk({
            summary: {
              apiAvailable: false,
              reason,
              note: 'Re-authenticate with okta.deviceAssurance.read scope and verify Device Assurance is enabled for this tenant.',
            },
            findings: [{
              id: 'DEVICE_ASSURANCE_API_UNAVAILABLE',
              severity: 'MODERATE',
              description: `Cannot read Device Assurance policies: ${reason}`,
              recommendation: 'Verify Device Assurance is enabled for this Okta tenant and re-authenticate with okta.deviceAssurance.read scope.',
            }],
            remediation: {
              terraform: buildDeviceAssuranceTerraform('ANDROID'),
              logQueries: buildDeviceAssuranceLogQueries(),
              adminConsoleSteps: buildDeviceAssuranceAdminSteps(),
              riskAssessment: buildDeviceAssuranceRiskAssessment(),
            },
          });
        }

        const audit = auditDeviceAssurance(policies);

        return buildMcpOk({
          ...audit,
          remediation: {
            terraform: buildDeviceAssuranceTerraform('ANDROID'),
            logQueries: buildDeviceAssuranceLogQueries(),
            adminConsoleSteps: buildDeviceAssuranceAdminSteps(),
            riskAssessment: buildDeviceAssuranceRiskAssessment(),
          },
        });
      } catch (err) {
        return buildMcpError(err);
      }
    },
  );

  server.tool(
    'okta_create_device_assurance_policy',
    'Create an Okta Device Assurance policy for a given platform with TEA Appendix B recommended checks. ' +
    'Supports Android, iOS, macOS, and Windows. Defaults include jailbreak detection, disk encryption, ' +
    'screen lock, secure hardware presence, and OS version minimum. ' +
    'After creation, assign the policy in Security > Authentication Policies to enforce it. ' +
    'Write operation — confirm before calling.',
    {
      platform: z.enum(['ANDROID', 'IOS', 'MACOS', 'WINDOWS'])
        .describe('Device platform to create the assurance policy for.'),
      name: z.string().optional()
        .describe('Policy name. Defaults to "<Platform> Device Assurance".'),
      osVersionMinimum: z.string().optional()
        .describe('Minimum OS version (e.g., "13.0.0" for macOS). Uses secure defaults if omitted.'),
    },
    async ({ platform, name, osVersionMinimum }) => {
      if (process.env.OFFLINE_MODE === 'true') {
        return buildMcpOffline({ skipped: true, message: 'Write operations are not available in offline mode.' });
      }
      if (process.env.PROD_MODE === 'true') {
        return buildMcpReadOnly();
      }
      try {
        const client = await createOktaClient();
        const payload = buildDeviceAssurancePayload(platform, name, osVersionMinimum);

        const { data: created } = await client.post(DEVICE_ASSURANCE_PATH, payload);

        return buildMcpOk({
          message: `Device Assurance policy "${created.name}" created for ${platform}.`,
          policyId: created.id,
          policyName: created.name,
          platform: created.platform,
          appliedChecks: {
            jailbreak: created.jailbreak,
            diskEncryptionType: created.diskEncryptionType,
            screenLockType: created.screenLockType,
            secureHardwarePresent: created.secureHardwarePresent,
            osVersion: created.osVersion,
          },
          nextSteps: [
            'Assign this policy in Security > Authentication Policies > [Your Policy] > Add Rule.',
            'Under "Device", select this device assurance policy to enforce it.',
            `Policy ID: ${created.id}`,
          ],
          remediation: {
            terraform: buildDeviceAssuranceTerraform(platform),
            logQueries: buildDeviceAssuranceLogQueries(),
            adminConsoleSteps: buildDeviceAssuranceAdminSteps(),
            riskAssessment: buildDeviceAssuranceRiskAssessment(),
          },
        });
      } catch (err) {
        return buildMcpError(err);
      }
    },
  );
}

module.exports = {
  registerDeviceAssuranceTools,
  auditDeviceAssurance,
  buildDeviceAssuranceLogQueries,
  buildDeviceAssuranceRiskAssessment,
  buildDeviceAssurancePayload,
  RECOMMENDED_CHECKS,
};
