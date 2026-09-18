'use strict';

const { buildMcpOk, buildMcpError, buildMcpOffline } = require('./resolver-utils');
const { createOktaClient } = require('../auth/okta-client');

// IDP type strings that indicate an Identity Verification provider
const IDV_IDP_TYPES = ['IDENTITY_VERIFICATION', 'IDV'];

// Known IDV vendor name fragments for detection in the IDP list
const IDV_PROVIDER_NAME_FRAGMENTS = [
  'PERSONA',
  'INCODE',
  'CLEAR',
  'IDEMIA',
  'JUMIO',
  'ONFIDO',
  'STRIPE_IDENTITY', 'STRIPE',
  'IDENTITY_VERIFICATION', 'IDENTITYVERIFICATION',
  'ID_VERIFICATION', 'IDVERIFY',
];

// ── Fetchers ───────────────────────────────────────────────────────────────────

async function fetchIdentityProviders(client) {
  try {
    const { data } = await client.get('/api/v1/idps');
    return { available: true, idps: Array.isArray(data) ? data : [] };
  } catch (err) {
    const status = err.response?.status;
    if (status === 404 || status === 403) {
      return {
        available: false,
        reason: `API returned ${status} — IDPs endpoint requires okta.idps.read scope.`,
      };
    }
    return { available: false, reason: err.message };
  }
}

async function fetchEnrollmentPolicies(client) {
  try {
    const { data } = await client.get('/api/v1/policies?type=PROFILE_ENROLLMENT');
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

function isIDVProvider(idp) {
  const nameUpper = (idp.name || '').toUpperCase();
  const typeUpper = (idp.type || '').toUpperCase();
  return (
    IDV_IDP_TYPES.some((t) => typeUpper.includes(t)) ||
    IDV_PROVIDER_NAME_FRAGMENTS.some((f) => nameUpper.includes(f) || typeUpper.includes(f))
  );
}

function auditIdentityProofing({ idps, enrollmentPolicies }) {
  const findings = [];

  const idvProviders = idps.available ? idps.idps.filter(isIDVProvider) : [];

  if (idvProviders.length === 0) {
    findings.push({
      id: 'NO_IDENTITY_PROOFING_PROVIDER',
      severity: 'MODERATE',
      description:
        'No Identity Proofing Provider (Identity Verification / IDV) is configured on any policy. ' +
        'Without IDV, sensitive self-service flows such as password reset, MFA device enrollment, ' +
        'and account recovery cannot verify that the person acting is the legitimate account owner. ' +
        'This leaves the tenant vulnerable to social-engineering-driven account takeover.',
      recommendation:
        'Add an Identity Proofing Provider (e.g., Persona, Incode, Clear) under Security > Identity Providers. ' +
        'Then configure Profile Enrollment and recovery policies to require identity proofing for high-risk operations.',
    });
  }

  // If providers exist but no enrollment policy references them
  const enrollmentPoliciesWithIDV = enrollmentPolicies.available
    ? enrollmentPolicies.policies.filter((p) => {
      const raw = JSON.stringify(p).toLowerCase();
      return (
        raw.includes('identityproofing') ||
        raw.includes('identity_proofing') ||
        raw.includes('idv') ||
        raw.includes('verif')
      );
    })
    : [];

  if (idvProviders.length > 0 && enrollmentPoliciesWithIDV.length === 0 && enrollmentPolicies.available) {
    findings.push({
      id: 'IDENTITY_PROOFING_NOT_ENFORCED_IN_POLICIES',
      severity: 'MODERATE',
      description:
        'An Identity Proofing Provider is configured, but no Profile Enrollment or recovery policies ' +
        'require identity verification. Users can still enroll and recover accounts without proving ' +
        'their identity, negating the protection the IDV provider offers.',
      recommendation:
        'Edit Profile Enrollment policies (Security > Profile Enrollment) to require identity proofing ' +
        'for device registration, password reset, and authenticator enrollment.',
    });
  }

  return {
    findingCount: findings.length,
    findings,
    idvProviders: idvProviders.map((p) => ({
      id: p.id,
      name: p.name,
      type: p.type,
      status: p.status,
    })),
    allIdps: idps.available ? idps.idps.length : null,
    enrollmentPoliciesWithIDV: enrollmentPoliciesWithIDV.length,
    apiCoverage: {
      idpsAvailable: idps.available,
      idpsFailReason: idps.available ? null : idps.reason,
      enrollmentPoliciesAvailable: enrollmentPolicies.available,
    },
  };
}

// ── Terraform ─────────────────────────────────────────────────────────────────

function buildIdentityProofingTerraform() {
  return `# Terraform — Okta Identity Proofing (IDV)
#  — Add Identity Proofing Provider
#
# Identity Verification providers are configured as Okta Identity Providers (IDPs)
# with special IDV capabilities. Configuration is vendor-specific.
#
# Supported providers:
#   Persona : https://developer.okta.com/docs/guides/add-id-verification-idp/persona/main/
#   Incode  : https://developer.okta.com/docs/guides/add-id-verification-idp/incode/main/
#   Clear   : https://developer.okta.com/docs/guides/add-id-verification-idp/clear/main/
#
# Provider docs:
#   https://registry.terraform.io/providers/okta/okta/latest/docs

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
  scopes      = ["okta.idps.manage", "okta.policies.manage"]
  private_key = "<PATH_OR_CONTENT_OF_PRIVATE_KEY>"
}

# Example: Persona Identity Verification IDP
# Exact resource type varies by provider version — consult provider docs before applying.
#
# resource "okta_idp_identity_verification" "persona" {
#   name          = "Persona Identity Verification"
#   client_id     = "<PERSONA_CLIENT_ID>"
#   client_secret = "<PERSONA_CLIENT_SECRET>"
#   status        = "ACTIVE"
# }
#
# resource "okta_policy_profile_enrollment" "default" {
#   name   = "Default Policy"
#   status = "ACTIVE"
#
#   rules {
#     name                           = "Require Identity Verification"
#     profile_attributes             = ["email", "login"]
#     identity_provider_id           = okta_idp_identity_verification.persona.id
#     identity_verification_required = true
#   }
# }
`;
}

// ── Log queries ───────────────────────────────────────────────────────────────

function buildIdentityProofingLogQueries() {
  return [
    {
      description: 'Identity verification attempts',
      filter: 'eventType sw "user.identity_verification"',
      timeWindow: 'last 30 days',
      note: 'Matches user.identity_verification (completion) and user.identity_verification.start (prompt). Monitor success/failure rates after adding an IDV provider.',
    },
    {
      description: 'Password self-service reset events — should require IDV',
      filter: 'eventType eq "user.account.reset_password"',
      timeWindow: 'last 30 days',
      note: 'Fires on every Okta password reset (admin-initiated and self-service). Password reset is the highest-risk self-service action — require IDV for all of these.',
    },
    {
      description: 'New MFA device enrollments — should require IDV',
      filter: 'eventType eq "user.mfa.factor.activate" OR eventType eq "user.mfa.factor.update"',
      timeWindow: 'last 30 days',
      note: 'New authenticator enrollments are a primary attack vector — attacker enrolls their own device. Require IDV.',
    },
    {
      description: 'Identity Provider (IDP) configuration changes',
      filter: 'eventType sw "system.idp."',
      timeWindow: 'last 90 days',
      note: 'Audit trail for IDV provider configuration changes.',
    },
    {
      description: 'Profile enrollment events — unenforced self-service flows',
      filter: 'eventType sw "user.account.unlock" OR eventType eq "user.lifecycle.create"',
      timeWindow: 'last 7 days',
      note: 'user.account.unlock covers all self-service unlock flows; user.lifecycle.create fires on new user creation via self-service registration. Monitor both for flows completing without IDV.',
    },
  ];
}

// ── Admin console steps ───────────────────────────────────────────────────────

function buildIdentityProofingAdminSteps() {
  return [
    'Sign in to the Okta Admin Console.',
    'Go to Security > Identity Providers.',
    'Click "Add Identity Provider" and select your chosen IDV vendor ' +
    '(Persona, Incode, Clear, IDEMIA, or others).',
    'Configure the provider with API credentials from the IDV vendor.',
    'Save and activate the identity provider.',
    'Go to Security > Profile Enrollment (or Authentication > Enrollment Policies).',
    'Edit the Default Policy or create a new enrollment policy.',
    'In policy rules, enable "Identity Verification" and select the IDV provider you configured.',
    'Apply IDV requirements for high-risk flows:',
    '  - Password reset',
    '  - MFA authenticator enrollment',
    '  - Account recovery / unlock',
    '  - New device registration',
    'Test: initiate a self-service password reset — the user should be redirected to the IDV provider.',
    'Resources:',
    '  - Persona: https://developer.okta.com/docs/guides/add-id-verification-idp/persona/main/',
    '  - All IDV providers: https://developer.okta.com/docs/guides/add-id-verification-idp/main/',
  ];
}

// ── Risk assessment ───────────────────────────────────────────────────────────

function buildIdentityProofingRiskAssessment() {
  return {
    teaSeverity: 'MODERATE',
    changeRisk:  'MODERATE',
    summary:
      'Without Identity Proofing, an attacker who knows a user\'s email can reset their password ' +
      'or enroll their own MFA device via self-service flows. IDV ensures the person performing ' +
      'a sensitive action is the legitimate account owner by comparing a government-issued ID against ' +
      'a live selfie or biometric check. This mitigates T1566 (phishing-driven account recovery) ' +
      'and T1136 (create accounts / enroll attacker-controlled devices).',
    preChangeChecks: [
      'Select an IDV vendor and obtain API credentials (Persona, Incode, Clear, or another supported provider).',
      'Test IDV completion with a representative sample of users before enforcing — include users with international IDs.',
      'Define the help desk escalation path for users who cannot complete IDV (accessibility needs, ID format issues).',
      'Confirm you are applying IDV to high-risk flows only: password reset and new device enrollment.',
    ],
    blastRadius:
      'Adding IDV adds friction to self-service flows. Users with poor photo quality, international ID ' +
      'formats, or accessibility needs may fail the check and be unable to complete recovery. ' +
      'The blast radius is proportional to the fraction of users who will struggle with IDV — ' +
      'test with a pilot group before enforcing org-wide. ' +
      'Provide a supervised help desk path for edge cases so users are never permanently locked out.',
    rolloutSteps: [
      'Step 1 — Select an IDV vendor and configure the provider in Security > Identity Providers.',
      'Step 2 — Apply IDV to password reset policies first (highest-risk flow).',
      'Step 3 — Run a pilot with 5–10% of users and review IDV success/failure rates.',
      'Step 4 — Apply IDV to new MFA device enrollment policies.',
      'Step 5 — Roll out to remaining users once IDV success rate is acceptable.',
      'Step 6 — Monitor IDV event rates (see postChangeMonitoring queries).',
    ],
    postChangeMonitoring: {
      description:
        'After enabling IDV on self-service flows, track verification success and failure rates. ' +
        'A high failure rate signals that users are struggling and may need help desk support.',
      logQueries: [
        {
          description: 'Identity proofing verification events',
          filter: 'eventType sw "user.identity_verification."',
          timeWindow: 'first 14 days post-change',
          note: 'Check outcome.result for SUCCESS vs FAILURE. High failure rate needs investigation — check ID format coverage with vendor.',
        },
        {
          description: 'Admin-assisted password resets (proxy for IDV failures)',
          filter: 'eventType eq "user.account.reset_password" AND actor.type eq "User" AND actor.id ne target.id',
          timeWindow: 'first 14 days post-change',
          note: 'An increase in admin-assisted resets after enabling IDV suggests users cannot complete self-service.',
        },
      ],
    },
    rollback:
      'Remove the IDV requirement from enrollment and recovery policies. The IDV provider IDP can ' +
      'remain configured but inactive. No user data is affected.',
  };
}

// ── Tool registration ─────────────────────────────────────────────────────────

function registerIdentityProofingTools(server) {
  server.tool(
    'okta_get_identity_proofing_config',
    'Audit Identity Proofing (IDV) configuration for . ' +
    'Checks whether an Identity Proofing Provider (Persona, Incode, Clear, etc.) is configured ' +
    'and whether Profile Enrollment / recovery policies enforce identity verification. ' +
    'Without IDV, self-service password reset and MFA enrollment can be exploited by attackers ' +
    'to take over accounts (T1566 / Phishing, T1136 / Create Accounts). ' +
    'Returns findings with supported IDV vendors and step-by-step setup guidance.',
    {},
    async () => {
      if (process.env.OFFLINE_MODE === 'true') {
        return buildMcpOffline({
          remediation: {
            terraform:         buildIdentityProofingTerraform(),
            logQueries:        buildIdentityProofingLogQueries(),
            adminConsoleSteps: buildIdentityProofingAdminSteps(),
            riskAssessment:    buildIdentityProofingRiskAssessment(),
          },
        });
      }
      try {
        const client = await createOktaClient();
        const [idps, enrollmentPolicies] = await Promise.all([
          fetchIdentityProviders(client),
          fetchEnrollmentPolicies(client),
        ]);

        const audit = auditIdentityProofing({ idps, enrollmentPolicies });

        return buildMcpOk({
          summary: {
            findingCount: audit.findingCount,
            idvProvidersConfigured: audit.idvProviders.length,
            totalIdpsConfigured: audit.allIdps,
            enrollmentPoliciesWithIDV: audit.enrollmentPoliciesWithIDV,
            apiCoverage: audit.apiCoverage,
          },
          findings: audit.findings,
          idvProviders: audit.idvProviders,
          supportedProviders: [
            {
              name: 'Persona',
              docs: 'https://developer.okta.com/docs/guides/add-id-verification-idp/persona/main/',
            },
            {
              name: 'Incode',
              docs: 'https://developer.okta.com/docs/guides/add-id-verification-idp/incode/main/',
            },
            {
              name: 'Clear',
              docs: 'https://developer.okta.com/docs/guides/add-id-verification-idp/clear/main/',
            },
          ],
          remediation: {
            terraform: buildIdentityProofingTerraform(),
            logQueries: buildIdentityProofingLogQueries(),
            adminConsoleSteps: buildIdentityProofingAdminSteps(),
            riskAssessment: buildIdentityProofingRiskAssessment(),
          },
        });
      } catch (err) {
        return buildMcpError(err);
      }
    },
  );
}

module.exports = {
  registerIdentityProofingTools,
  auditIdentityProofing,
  buildIdentityProofingLogQueries,
  buildIdentityProofingRiskAssessment,
};
