'use strict';

const { z } = require('zod');
const { buildMcpOk, buildMcpError, buildMcpOffline, buildMcpReadOnly } = require('./resolver-utils');
const { createOktaClient } = require('../auth/okta-client');

const OKTA_VERIFY_KEY        = 'okta_verify';
const PHONE_NUMBER_KEY       = 'phone_number';
const SECURITY_QUESTION_KEY  = 'security_question';
const WEBAUTHN_KEY           = 'webauthn';
const FASTPASS_METHOD_TYPE   = 'signed_nonce'; // method type nested inside the Okta Verify authenticator
const NUMBER_CHALLENGE_ENABLED = 'ENABLED'; // tool-facing enum value

// Okta stores number challenge as settings.channelBinding.required — not as a
// top-level numberChallenge field. These are the actual API values.
const CHANNEL_BINDING_ALWAYS = 'ALWAYS'; // "Always" in Admin Console
const CHANNEL_BINDING_NEVER = 'NEVER';   // "Never" in Admin Console
const CHANNEL_BINDING_STYLE = 'NUMBER_CHALLENGE';

// "Higher Security Methods" enrollment restriction:
//   settings.enrollmentSecurityLevel = "HIGH" → "Higher security methods" in Admin Console
//                                      "ANY"  → "Any method" (QR code and SMS/email link allowed)
const ENROLLMENT_SECURITY_LEVEL_HIGH = 'HIGH';
const ENROLLMENT_SECURITY_LEVEL_ANY  = 'ANY';

// ── Helpers ───────────────────────────────────────────────────────────────────

function findOktaVerifyAuthenticator(authenticators) {
  return authenticators.find((a) => a.key === OKTA_VERIFY_KEY) || null;
}

function auditOktaVerify(authenticator) {
  // Number Challenge requires BOTH channelBinding.style == "NUMBER_CHALLENGE" (TEA check)
  // AND channelBinding.required == "ALWAYS" (ensures it is always enforced, not only on high-risk).
  const channelBindingRequired = authenticator.settings?.channelBinding?.required ?? CHANNEL_BINDING_NEVER;
  const channelBindingStyle    = authenticator.settings?.channelBinding?.style    ?? null;
  const numberChallengeEnabled =
    channelBindingStyle === CHANNEL_BINDING_STYLE &&
    channelBindingRequired === CHANNEL_BINDING_ALWAYS;

  // "Higher Security Methods" enrollment restriction — restricts Okta Verify enrollment to
  // same-device and device-to-device Bluetooth only (disallows QR code, SMS, and email links).
  // Field confirmed via live API: settings.enrollmentSecurityLevel = "HIGH" | "ANY".
  const enrollmentSecurityLevel = authenticator.settings?.enrollmentSecurityLevel ?? null;
  const higherSecurityMethodsEnabled = enrollmentSecurityLevel !== null
    ? enrollmentSecurityLevel === ENROLLMENT_SECURITY_LEVEL_HIGH
    : null; // null = field absent in API response (older tenant or unexpected schema)

  const findings = [];

  //  — Number Challenge not fully enabled
  if (!numberChallengeEnabled) {
    const styleOk    = channelBindingStyle === CHANNEL_BINDING_STYLE;
    const requiredOk = channelBindingRequired === CHANNEL_BINDING_ALWAYS;
    findings.push({
      id: 'NUMBER_CHALLENGE_DISABLED',
      severity: 'MODERATE',
      description:
        `Okta Verify Number Challenge is not fully enabled. ` +
        `style="${channelBindingStyle ?? 'unset'}" (expected "${CHANNEL_BINDING_STYLE}"), ` +
        `required="${channelBindingRequired}" (expected "${CHANNEL_BINDING_ALWAYS}"). ` +
        `${!styleOk ? 'The channel binding style must be set to NUMBER_CHALLENGE. ' : ''}` +
        `${!requiredOk ? `required must be "${CHANNEL_BINDING_ALWAYS}" — "${CHANNEL_BINDING_NEVER}" or "HIGH_RISK_ONLY" leaves users vulnerable to MFA fatigue (push bombing) attacks outside high-risk contexts. ` : ''}`,
      recommendation:
        `Set settings.channelBinding.style to "${CHANNEL_BINDING_STYLE}" and ` +
        `settings.channelBinding.required to "${CHANNEL_BINDING_ALWAYS}".`,
    });
  }

  //  — Higher Security Methods enrollment restriction not enabled
  if (!higherSecurityMethodsEnabled) {
    findings.push({
      id: 'OKTA_VERIFY_HIGHER_SECURITY_METHODS_DISABLED',
      severity: 'MODERATE',
      description:
        higherSecurityMethodsEnabled === null
          ? `Okta Verify enrollment method restriction cannot be determined — settings.enrollmentSecurityLevel is absent from the API response. ` +
            'Without "Higher Security Methods" (enrollmentSecurityLevel = "HIGH"), users can enroll Okta Verify via QR code or SMS/email link. ' +
            'These out-of-band channels allow an attacker who intercepts an enrollment link or QR code to register Okta Verify on an attacker-controlled device. ' +
            'Verify via Admin Console: Security > Authenticators > Okta Verify > Edit > Enrollment options.'
          : `Okta Verify enrollment is set to "Any method" (enrollmentSecurityLevel = "${enrollmentSecurityLevel}"). ` +
            'Users can enroll Okta Verify using a QR code or SMS/email link — out-of-band enrollment channels ' +
            'that an attacker could exploit by intercepting the enrollment URL or QR code. ' +
            'Restrict to "Higher security methods" (same-device and Bluetooth only) to eliminate these vectors.',
      recommendation:
        'Set settings.enrollmentSecurityLevel to "HIGH" to enable the "Higher Security Methods" restriction. ' +
        'Use okta_update_okta_verify_settings with higherSecurityMethods: true, or ' +
        'navigate to Security > Authenticators > Okta Verify > Edit > Enrollment options > select "Higher security methods".',
    });
  }

  return {
    authenticatorId: authenticator.id,
    authenticatorName: authenticator.name,
    key: authenticator.key,
    status: authenticator.status,
    findingCount: findings.length,
    findings,
    current: {
      channelBindingStyle,
      channelBindingRequired,
      numberChallengeEnabled,
      userVerification: authenticator.settings?.userVerification,
      enrollmentSecurityLevel: enrollmentSecurityLevel ?? 'not returned by API',
      higherSecurityMethodsEnabled,
    },
  };
}

function auditPhoneAuthenticator(authenticators) {
  const phone = authenticators.find((a) => a.key === PHONE_NUMBER_KEY);
  if (!phone || phone.status !== 'ACTIVE') return { present: !!phone, active: false, findings: [] };

  return {
    present: true,
    active: true,
    authenticatorId: phone.id,
    authenticatorName: phone.name,
    status: phone.status,
    findings: [{
      id: 'SMS_PHONE_AUTHENTICATOR_ACTIVE',
      severity: 'HIGH',
      description:
        'The Phone (SMS OTP / voice call) authenticator is active. ' +
        'SMS OTPs are interceptable via SIM swapping (MITRE T1451) and SS7 protocol attacks — ' +
        'the public switched telephone network provides no cryptographic authentication guarantees. ' +
        'NIST SP 800-63B classifies SMS as a "restricted" authenticator due to these vulnerabilities.',
      recommendation:
        'Disable SMS and phone-based authentication methods. ' +
        'Migrate affected users to phishing-resistant factors: Okta FastPass or WebAuthn/FIDO2.',
    }],
  };
}

function auditSecurityQuestionAuthenticator(authenticators) {
  const sq = authenticators.find((a) => a.key === SECURITY_QUESTION_KEY);
  if (!sq || sq.status !== 'ACTIVE') return { present: !!sq, active: false, findings: [] };

  return {
    present: true,
    active: true,
    authenticatorId: sq.id,
    authenticatorName: sq.name,
    status: sq.status,
    findings: [{
      id: 'SECURITY_QUESTION_AUTHENTICATOR_ACTIVE',
      severity: 'MODERATE',
      description:
        'Security Questions are active as an MFA method. Security question answers are ' +
        'frequently obtainable via spearphishing, social media research, or credential breach dumps. ' +
        'The limited pool of standard questions makes answers guessable from publicly available information ' +
        'about a user (T1566 / Phishing, T1110 / Brute Force).',
      recommendation:
        'Remove Security Questions as an authenticator for all flows. ' +
        'Replace with Okta FastPass or WebAuthn/FIDO2.',
    }],
  };
}

function auditWebAuthnAuthenticator(authenticators) {
  const wa = authenticators.find((a) => a.key === WEBAUTHN_KEY);
  if (wa?.status === 'ACTIVE') return { present: true, active: true, findings: [] };

  return {
    present: !!wa,
    active: false,
    authenticatorId: wa?.id ?? null,
    status: wa?.status ?? null,
    findings: [{
      id: 'WEBAUTHN_NOT_ACTIVE',
      severity: 'HIGH',
      description:
        'WebAuthn/FIDO2 (Security Key) is not active. ' +
        'WebAuthn is a phishing-resistant, hardware-bound authenticator — the private key never leaves the device ' +
        'and cryptographic binding to the origin domain makes it immune to AiTM (adversary-in-the-middle) and real-time phishing attacks. ' +
        'Without WebAuthn or FastPass, users can only use factors that can be proxied (TOTP, push) or intercepted (SMS). ' +
        'WebAuthn satisfies AAL3 under NIST SP 800-63B.',
      recommendation:
        'Enable the WebAuthn authenticator under Security > Authenticators and enroll users in ' +
        'a FIDO2-compatible security key (YubiKey, Passkey, Windows Hello, Touch ID, etc.). ' +
        'Add WebAuthn to Authentication Policies as an allowed or required factor.',
    }],
  };
}

function auditFastPass(oktaVerify) {
  if (!oktaVerify) return { present: false, active: false, findings: [] };

  // FastPass is the signed_nonce method nested inside the Okta Verify authenticator.
  // The Okta API returns methods as an array: [{type, status, settings}, ...].
  // Defensively also handle the object form {signed_nonce: {status}} in case of API variation.
  const methods = oktaVerify.methods;
  let fastPassActive = false;

  if (Array.isArray(methods)) {
    fastPassActive = methods.some(
      (m) => m.type === FASTPASS_METHOD_TYPE && m.status === 'ACTIVE',
    );
  } else if (methods && typeof methods === 'object') {
    const fp = methods[FASTPASS_METHOD_TYPE] || methods.signedNonce;
    fastPassActive = fp?.status === 'ACTIVE';
  }

  if (fastPassActive) return { present: true, active: true, findings: [] };

  return {
    present: true,
    active: false,
    findings: [{
      id: 'FASTPASS_NOT_ENABLED',
      severity: 'MODERATE',
      description:
        'Okta FastPass (signed_nonce method on Okta Verify) is not enabled. ' +
        'FastPass is Okta\'s phishing-resistant, passwordless authenticator — it uses device-bound cryptographic keys ' +
        'so credentials are never transmitted, making it immune to real-time phishing and AiTM attacks (T1566, T1557). ' +
        'FastPass requires Okta Verify on managed devices and meets AAL2 without a password. ' +
        'IMPORTANT: FastPass only provides phishing resistance when it is also enforced by Authentication Policy — ' +
        'without a possession constraint of phishingResistant: "REQUIRED", sign-ins may fall back to push notifications ' +
        'or TOTP even when FastPass is enrolled.',
      recommendation:
        'Step 1 — Enable FastPass by activating the signed_nonce method on the Okta Verify authenticator ' +
        '(Security > Authenticators > Okta Verify > Edit > Enable FastPass). ' +
        'Step 2 — Deploy Okta Verify to managed devices so users can enroll FastPass. ' +
        'Step 3 — Enforce FastPass by setting phishingResistant: "REQUIRED" on the possession constraint ' +
        'in Authentication Policy rules. Without Step 3, FastPass is available but not enforced — ' +
        'users may still authenticate via non-phishing-resistant factors.',
    }],
  };
}

// ── Terraform builder ──────────────────────────────────────────────────────────

function buildAuthenticatorTerraform(authenticator) {
  const settings = authenticator.settings || {};
  // Use the actual Okta API field structure — channelBinding.required, not numberChallenge
  const settingsJson = JSON.stringify({
    userVerification: settings.userVerification || 'PREFERRED',
    channelBinding: {
      style: settings.channelBinding?.style || CHANNEL_BINDING_STYLE,
      required: CHANNEL_BINDING_ALWAYS,
    },
    enrollmentSecurityLevel: ENROLLMENT_SECURITY_LEVEL_HIGH,
  }, null, 2).replace(/\n/g, '\n    ');

  return `# Terraform — Okta Verify authenticator (: Number Challenge)
#
# Provider setup:
#   https://developer.okta.com/docs/guides/terraform-enable-org-access/main/
# Resource reference:
#   https://registry.terraform.io/providers/okta/okta/latest/docs/resources/authenticator
#
# Number Challenge requires the end user to match the number displayed on the login
# screen with the number in their Okta Verify app — prevents MFA fatigue/push bombing.

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
  scopes      = ["okta.authenticators.manage"]
  private_key = "<PATH_OR_CONTENT_OF_PRIVATE_KEY>"
}

# Authenticator ID: ${authenticator.id}
resource "okta_authenticator" "okta_verify" {
  key    = "${OKTA_VERIFY_KEY}"
  name   = "${authenticator.name}"
  status = "${authenticator.status || 'ACTIVE'}"

  #  — numberChallenge prevents push bombing (MFA fatigue attacks)
  settings = jsonencode(${settingsJson})
}
`;
}

function buildWebAuthnTerraform() {
  return `# Terraform — Enable WebAuthn/FIDO2 authenticator
#
# Provider setup:
#   https://developer.okta.com/docs/guides/terraform-enable-org-access/main/
# Resource reference:
#   https://registry.terraform.io/providers/okta/okta/latest/docs/resources/authenticator
#
# WebAuthn is a phishing-resistant, hardware-bound FIDO2 authenticator (YubiKey, Passkey,
# Windows Hello, Touch ID, etc.). Private keys are device-bound and never transmitted.
# NIST SP 800-63B AAL3 compliant.
#
# After enabling, add WebAuthn to Authentication Policy rules by setting:
#   phishingResistant: "REQUIRED" on the possession constraint.

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
  scopes      = ["okta.authenticators.manage"]
  private_key = "<PATH_OR_CONTENT_OF_PRIVATE_KEY>"
}

resource "okta_authenticator" "webauthn" {
  key    = "${WEBAUTHN_KEY}"
  name   = "Security Key or Biometric"
  status = "ACTIVE"
}
`;
}

function buildFastPassTerraform(authenticatorId, currentSettings) {
  const settingsJson = JSON.stringify({
    userVerification: currentSettings?.userVerification || 'PREFERRED',
    channelBinding: {
      style: currentSettings?.channelBinding?.style || CHANNEL_BINDING_STYLE,
      required: currentSettings?.channelBinding?.required || CHANNEL_BINDING_ALWAYS,
    },
  }, null, 2).replace(/\n/g, '\n    ');

  return `# Terraform — Enable Okta FastPass on Okta Verify authenticator
#
# FastPass (signed_nonce method) is Okta's phishing-resistant, passwordless authenticator.
# It uses device-bound cryptographic keys — credentials are never transmitted.
# NIST SP 800-63B AAL2 compliant, immune to AiTM and real-time phishing.
#
# FastPass is phishing-resistant ONLY when BOTH conditions are met:
#   1. FastPass is enabled (signed_nonce method is ACTIVE on the Okta Verify authenticator), AND
#   2. Authentication Policy rules enforce phishingResistant: "REQUIRED" on the possession constraint.
#
# Without condition 2, sign-ins may satisfy via push notifications or TOTP even when FastPass is enrolled.
#
# Prerequisites:
#   1. Okta Verify deployed to managed devices (MDM-enrolled or via manual install)
#   2. Devices enrolled in Okta Verify with the FastPass method active
#   3. Authentication Policy rules with phishingResistant: "REQUIRED" on the possession constraint
#
# Authenticator ID: ${authenticatorId || '<OKTA_VERIFY_AUTHENTICATOR_ID>'}
resource "okta_authenticator" "okta_verify" {
  key    = "${OKTA_VERIFY_KEY}"
  name   = "Okta Verify"
  status = "ACTIVE"

  # settings must include channelBinding (Number Challenge) to preserve that setting.
  # FastPass enablement is done via the Admin Console (Security > Authenticators > Okta Verify > Edit).
  # The Terraform okta_authenticator resource does not directly expose the signed_nonce method toggle —
  # use the Admin Console or the Okta API (PUT /api/v1/authenticators/{id}) to enable FastPass.
  settings = jsonencode(${settingsJson})
}
`;
}

function buildPhoneTerraform(authenticatorId) {
  return `# Terraform — Disable Phone (SMS / voice call) authenticator
#
# Provider setup:
#   https://developer.okta.com/docs/guides/terraform-enable-org-access/main/
# Resource reference:
#   https://registry.terraform.io/providers/okta/okta/latest/docs/resources/authenticator
#
# IMPORTANT — before applying:
#   1. Remove "Phone" from all Authentication Policy rules that list it as an allowed factor.
#   2. Remove "Phone" from all Enrollment Policy "Optional" and "Required" lists.
#   3. Users enrolled with Phone as their ONLY factor will lose MFA access — run an
#      enrollment report and help them enroll Okta Verify or WebAuthn before deactivating.

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
  scopes      = ["okta.authenticators.manage"]
  private_key = "<PATH_OR_CONTENT_OF_PRIVATE_KEY>"
}

# Authenticator ID: ${authenticatorId || '<PHONE_AUTHENTICATOR_ID>'}
resource "okta_authenticator" "phone" {
  key    = "${PHONE_NUMBER_KEY}"
  name   = "Phone"
  status = "INACTIVE"
}
`;
}

function buildSecurityQuestionTerraform(authenticatorId) {
  return `# Terraform — Disable Security Question authenticator
#
# Provider setup:
#   https://developer.okta.com/docs/guides/terraform-enable-org-access/main/
# Resource reference:
#   https://registry.terraform.io/providers/okta/okta/latest/docs/resources/authenticator
#
# IMPORTANT — before applying:
#   1. Remove "Security Question" from all Authentication Policy rules.
#   2. Remove "Security Question" from all Enrollment Policy lists.
#   3. Users using Security Question as their ONLY recovery factor will lose
#      self-service account recovery — help them enroll email or Okta Verify first.

# Authenticator ID: ${authenticatorId || '<SECURITY_QUESTION_AUTHENTICATOR_ID>'}
resource "okta_authenticator" "security_question" {
  key    = "${SECURITY_QUESTION_KEY}"
  name   = "Security Question"
  status = "INACTIVE"
}
`;
}

// ── Log queries ────────────────────────────────────────────────────────────────

function buildWebAuthnLogQueries() {
  return [
    {
      description: 'WebAuthn factor enrollments',
      filter: 'eventType eq "user.mfa.factor.activate"',
      timeWindow: 'last 30 days',
      note: 'Filter results by "Security Key" or "WebAuthn" in displayMessage to track enrollment growth after enabling.',
    },
    {
      description: 'WebAuthn authenticator activation audit',
      filter: 'eventType eq "security.authenticator.lifecycle.activate"',
      timeWindow: 'last 7 days',
      note: 'Confirms the WebAuthn authenticator was activated in the org.',
    },
  ];
}

function buildFastPassLogQueries() {
  return [
    {
      description: 'Okta Verify device enrollments (FastPass prerequisite)',
      filter: 'eventType eq "device.lifecycle.activate"',
      timeWindow: 'last 30 days',
      note: 'Each event here is a device enrolling in Okta Verify — FastPass requires device enrollment. Monitor growth after enabling.',
    },
    {
      description: 'Okta Verify authenticator update (FastPass toggle)',
      filter: 'eventType eq "security.authenticator.lifecycle.update"',
      timeWindow: 'last 7 days',
      note: 'Fires when Okta Verify settings are changed — confirms FastPass was enabled on the authenticator.',
    },
  ];
}

function buildPhoneLogQueries() {
  return [
    {
      description: 'SMS OTP verification messages sent (active usage baseline)',
      filter: 'eventType eq "system.sms.send_factor_verify_message"',
      timeWindow: 'last 30 days',
      note: 'Volume of SMS OTPs sent for MFA. Run before disabling to quantify how many users rely on this factor.',
    },
    {
      description: 'Voice call MFA challenges sent (active usage baseline)',
      filter: 'eventType eq "system.voice.send_mfa_challenge_call"',
      timeWindow: 'last 30 days',
      note: 'Volume of voice call MFA challenges. Run before disabling to identify users who use phone call as their factor.',
    },
    {
      description: 'Phone authenticator deactivation audit',
      filter: 'eventType eq "security.authenticator.lifecycle.deactivate"',
      timeWindow: 'last 7 days',
      note: 'Confirms the Phone authenticator was deactivated. Check actor for who made the change.',
    },
  ];
}

function buildSecurityQuestionLogQueries() {
  return [
    {
      description: 'Security Question factor enrollments (active usage baseline)',
      filter: 'eventType eq "user.mfa.factor.activate"',
      timeWindow: 'last 30 days',
      note: 'Filter results by target.displayName containing "Security Question" to quantify enrollment before disabling.',
    },
    {
      description: 'Security Question authenticator deactivation audit',
      filter: 'eventType eq "security.authenticator.lifecycle.deactivate"',
      timeWindow: 'last 7 days',
      note: 'Confirms the Security Question authenticator was deactivated.',
    },
  ];
}

function buildAuthenticatorLogQueries() {
  return [
    {
      description: 'Okta Verify push notifications sent — volume baseline',
      filter: 'eventType eq "system.push.send_factor_verify_push"',
      timeWindow: 'last 7 days',
      note: 'Fires whenever a push is sent for verification. Use this to monitor push volume and confirm Number Challenge is in use (debugContext.debugData.pushWithNumberChallengeResponseType) — each push should require the user to match the on-screen number.',
    },
    {
      description: 'Denied Okta Verify push attempts — push bombing indicators',
      filter: 'eventType eq "user.authentication.auth_via_mfa" AND debugContext.debugData.pushOnlyResponseType eq "OV_RESPONSE_DENY"',
      timeWindow: 'last 30 days',
      note: 'Okta push event denied/failed MFA via Okta Verify. A spike may indicate a push bombing attack.',
    },
    {
      description: 'Authenticator configuration changes — audit trail',
      filter: 'eventType eq "security.authenticator.lifecycle.update"',
      timeWindow: 'last 90 days',
      note: 'Tracks when Okta Verify settings were changed and by whom.',
    },
    {
      description: 'MFA activity via Number Challenge — post-change baseline',
      filter: 'debugContext.debugData.pushWithNumberChallengeResponseType pr',
      timeWindow: 'last 7 days',
      note: 'Monitor after enabling Number Challenge and check for failures (debugContext.debugData.pushWithNumberChallengeResponseType ne "OV_WITH_CHALLENGE_RESPONSE_VALID").',
    },
    {
      description: 'Okta FastPass usage',
      filter: 'eventType eq "user.authentication.auth_via_mfa" and debugContext.debugData.factor eq "SIGNED_NONCE" and outcome.result eq "SUCCESS"',
      timeWindow: 'last 7 days',
      note: 'Check Okta FastPass usage after enabling. Each event indicates a successful FastPass authentication.  Go to the Okta Admin console -> Reports -> MFA Activity for details on phishing resistant users and events.',
    },
  ];
}

function buildWebAuthnAdminSteps() {
  return [
    'Sign in to the Okta Admin Console.',
    '── Step 1: Enable the WebAuthn authenticator ──',
    '  Go to Security > Authenticators.',
    '  Click "Add Authenticator" and select "Passkey (FIDO2 WebAuthn)".',
    '  Click Add.',
    '── Step 2: Add WebAuthn to Enrollment Policies ──',
    '  Go to Security > Authentication Policies > Okta account management.',
    '  Edit the relevant enrollment policy using a custom expression as described here: https://help.okta.com/oie/en-us/content/topics/identity-engine/policies/oamp-configure-first-pr-enrollment.htm.',
    '  Users can then self-enroll using any FIDO2-compatible device (YubiKey, Windows Hello, Touch ID, etc.).',
    '── Step 3: Require WebAuthn in Authentication Policies ──',
    '  Go to Security > Authentication Policies.',
    '  For high-value apps: edit the policy rule and set possession constraint phishingResistant = Required.',
    '  This forces WebAuthn or FastPass — other factors like SMS or TOTP will not satisfy the rule.',
    '── Step 4: Verify ──',
    '  Go to Reports > System Log and filter: eventType eq "security.authenticator.lifecycle.activate".',
    '  Confirm the WebAuthn activation event appears.',
    '  Test by enrolling a security key or biometric on a test user and verifying sign-in.',
  ];
}

function buildFastPassAdminSteps() {
  return [
    'Sign in to the Okta Admin Console.',
    '── Step 1: Enable FastPass on the Okta Verify authenticator ──',
    '  Go to Security > Authenticators.',
    '  Find "Okta Verify" and click Actions > Edit.',
    '  In the Okta Verify settings, find the "FastPass" or "Passwordless" section.',
    '  Enable "Okta FastPass"',
    '  Then find the "Users can enroll in Okta Verify using" and set it to "Higher Security Methods". This restricts enrollment to same-device or Bluetooth only, preventing QR code or SMS/email link enrollment.',
    '── Step 2: Deploy Okta Verify to managed devices ──',
    '  Use your MDM (Jamf, Intune, etc.) to push Okta Verify to managed macOS, Windows, iOS, and Android devices.',
    '  Users must enroll their device in Okta Verify with FastPass after installation.',
    '── Step 3: Enforce phishing resistance in Authentication Policies ──',
    '  NOTE: Steps 1 and 2 make FastPass AVAILABLE but do NOT yet make sign-ins phishing-resistant.',
    '  Without this step, users with FastPass enrolled may still complete sign-ins via push or TOTP.',
    '  Go to Security > Authentication Policies.',
    '  Edit policy rules for apps that require phishing-resistant authentication.',
    '  Add a possession constraint with phishingResistant: Required.',
    '  FastPass and WebAuthn/FIDO2 satisfy this constraint — push notifications and TOTP do not.',
    '  Use okta_update_authentication_policy_rule with requirePhishingResistantPossession: true to apply via API.',
    '── Step 4: Monitor enrollment and enforcement ──',
    '  Go to Reports > System Log and filter: eventType eq "device.lifecycle.activate".',
    '  Rising device enrollment confirms users are enrolling FastPass.',
    '  Filter on eventType eq "user.authentication.sso" and verify FastPass is the satisfying factor.',
  ];
}

function buildWebAuthnRiskAssessment() {
  return {
    teaSeverity: 'HIGH',
    changeRisk:  'LOW',
    summary:
      'WebAuthn/FIDO2 is a phishing-resistant, hardware-bound authenticator that defends against ' +
      'AiTM (T1557), credential phishing (T1566), and MFA bypass attacks. Private keys are device-bound ' +
      'and the origin binding prevents credential use on lookalike domains. ' +
      'Enabling WebAuthn is additive — it does not disrupt existing authentication flows.',
    preChangeChecks: [
      'Confirm your Okta edition supports WebAuthn (OIE required).',
      'Identify which FIDO2-compatible devices and security keys users have available (YubiKey, Windows Hello, Touch ID, Passkeys).',
      'Plan enrollment: users need a FIDO2-capable device and browser to complete WebAuthn enrollment.',
      'No prerequisites to activate — enabling WebAuthn does not affect existing sign-in flows until added to policy rules.',
    ],
    blastRadius:
      'Enabling WebAuthn has no blast radius — it is additive. ' +
      'Existing users continue to sign in with their current factors. ' +
      'Only after Authentication Policy rules are updated to require phishingResistant: "REQUIRED" ' +
      'will users without WebAuthn or FastPass be prompted or blocked.',
    rolloutSteps: [
      'Step 1 — Enable WebAuthn authenticator (no user impact).',
      'Step 2 — Add WebAuthn to enrollment policy as Optional (users can enroll at will).',
      'Step 3 — Run an enrollment campaign and monitor adoption via user.mfa.factor.activate events.',
      'Step 4 — Once sufficient enrollment, update Authentication Policy rules to prefer or require phishingResistant.',
      'Step 5 — Monitor for failed sign-ins from users without phishing-resistant factors.',
    ],
    postChangeMonitoring: {
      description:
        'After enabling WebAuthn, track enrollment growth. After adding it to policy rules, ' +
        'watch for users unable to meet the phishing-resistant requirement.',
      logQueries: [
        {
          description: 'WebAuthn enrollment events',
          filter: 'eventType eq "user.mfa.factor.activate"',
          timeWindow: 'first 30 days post-enablement',
          note: 'Filter by "Security Key" or "WebAuthn" in displayMessage. Rising enrollment confirms users are adopting the factor.',
        },
        {
          description: 'Authentication policy denials from missing phishing-resistant factor',
          filter: 'eventType eq "user.session.start" AND outcome.result eq "DENY"',
          timeWindow: 'first 48 hours post-policy-change',
          note: 'After setting phishingResistant: REQUIRED, users without WebAuthn or FastPass will be denied. Identify them and help them enroll.',
        },
      ],
    },
    rollback:
      'Deactivate WebAuthn from Security > Authenticators without affecting any existing user sessions. ' +
      'Reverse any Authentication Policy changes that referenced phishingResistant.',
  };
}

function buildFastPassRiskAssessment() {
  return {
    teaSeverity: 'MODERATE',
    changeRisk:  'MODERATE',
    summary:
      'Okta FastPass is phishing-resistant when both conditions are met: ' +
      '(1) FastPass is enabled on the Okta Verify authenticator (signed_nonce method is ACTIVE), AND ' +
      '(2) Authentication Policy rules enforce phishingResistant: "REQUIRED" on the possession constraint. ' +
      'FastPass uses device-bound cryptographic keys — no credential is transmitted — making it immune to ' +
      'real-time phishing (T1566) and AiTM attacks (T1557) when enforced. ' +
      'Without the policy enforcement (condition 2), users may complete sign-ins via push notifications or TOTP ' +
      'even when FastPass is enrolled — those methods are not phishing-resistant.',
    preChangeChecks: [
      'Confirm Okta Verify is already deployed to managed devices — FastPass requires Okta Verify.',
      'Verify OIE (Identity Engine) is enabled on the tenant — FastPass requires OIE.',
      'Identify which device platforms need FastPass: macOS, Windows, iOS, Android all supported.',
      'Plan the rollout of Okta Verify if not already deployed and consider usage of MDM.',
      'Identify which Authentication Policies will also need phishingResistant: "REQUIRED" enforcement — ' +
        'enabling FastPass alone does not make sign-ins phishing-resistant without policy enforcement.',
    ],
    blastRadius:
      'Enabling FastPass on the Okta Verify authenticator is additive — existing users continue ' +
      'to authenticate normally. FastPass only provides phishing resistance once: ' +
      '(1) users enroll their device in Okta Verify with FastPass, AND ' +
      '(2) Authentication Policy rules are updated to require phishingResistant: "REQUIRED". ' +
      'Until both are true, FastPass is available but may not be the factor that satisfies sign-in.',
    rolloutSteps: [
      'Step 1 — Enable FastPass on the Okta Verify authenticator (Security > Authenticators > Okta Verify > Edit).',
      'Step 2 — Communicate to users and guide FastPass enrollment on their managed devices.',
      'Step 3 — Monitor device enrollment growth (device.lifecycle.activate events).',
      'Step 4 — Once enrollment is sufficient, enforce FastPass by setting phishingResistant: "REQUIRED" ' +
        'on Authentication Policy possession constraints. Without this step, FastPass is available but ' +
        'sign-ins may still use non-phishing-resistant factors.',
    ],
    postChangeMonitoring: {
      description:
        'After enabling FastPass, watch for device enrollment growth. FastPass adoption ' +
        'is measured by device.lifecycle.activate events and by users completing sign-ins without a password.',
      logQueries: [
        {
          description: 'Device enrollments in Okta Verify (FastPass adoption)',
          filter: 'eventType eq "device.lifecycle.activate"',
          timeWindow: 'first 30 days post-enablement',
          note: 'Rising enrollment means users are setting up FastPass on their devices.',
        },
        {
          description: 'Okta Verify authenticator settings update (confirms FastPass enabled)',
          filter: 'eventType eq "security.authenticator.lifecycle.update"',
          timeWindow: 'last 1 hour',
          note: 'Fires when Okta Verify settings are saved. Confirms FastPass was toggled on.',
        },
      ],
    },
    rollback:
      'Disable FastPass by editing the Okta Verify authenticator settings. ' +
      'Existing device enrollments are not removed — users revert to push or TOTP. ' +
      'Reverse any Authentication Policy changes that required phishingResistant.',
  };
}

function buildPhoneAdminSteps() {
  return [
    'Sign in to the Okta Admin Console.',
    '── Step 1: Identify affected users ──',
    '  Run Reports > System Log: filter eventType eq "system.sms.send_factor_verify_message" (last 30 days).',
    '  Users appearing here rely on SMS MFA. Help them enroll Okta Verify before proceeding.',
    '── Step 2: Remove Phone from Authentication Policies ──',
    '  Go to Security > Authentication Policies.',
    '  Review every policy rule that lists "Phone" as an allowed factor and remove it.',
    '── Step 3: Remove Phone from Enrollment Policies ──',
    '  Go to Security > Authenticators > Enrollment.',
    '  Edit each enrollment policy and remove "Phone" from the Required and Optional lists.',
    '── Step 4: Deactivate the Phone authenticator ──',
    '  Go to Security > Authenticators.',
    '  Find "Phone" in the list and click Actions > Deactivate.',
    '  Confirm deactivation in the dialog.',
    '── Step 5: Verify ──',
    '  Go to Reports > System Log and filter: eventType eq "security.authenticator.lifecycle.deactivate".',
    '  Confirm the Phone authenticator deactivation event appears.',
    '  Monitor System Log for the next 48 hours for any MFA failures indicating users who relied on Phone.',
  ];
}

function buildSecurityQuestionAdminSteps() {
  return [
    'Sign in to the Okta Admin Console.',
    '── Step 1: Identify affected users ──',
    '  Run Reports > System Log: filter eventType eq "user.mfa.factor.activate" (last 30 days).',
    '  Filter results by "Security Question" in displayMessage to see enrolled users.',
    '── Step 2: Remove Security Question from Authentication Policies ──',
    '  Go to Security > Authentication Policies.',
    '  Review every policy rule that lists "Security Question" as an allowed factor and remove it.',
    '── Step 3: Remove Security Question from Enrollment Policies ──',
    '  Go to Security > Authenticators > Enrollment.',
    '  Edit each enrollment policy and remove "Security Question" from the Required and Optional lists.',
    '── Step 4: Deactivate the Security Question authenticator ──',
    '  Go to Security > Authenticators.',
    '  Find "Security Question" in the list and click Actions > Deactivate.',
    '  Confirm deactivation in the dialog.',
    '── Step 5: Verify ──',
    '  Go to Reports > System Log and filter: eventType eq "security.authenticator.lifecycle.deactivate".',
    '  Confirm the Security Question deactivation event appears.',
  ];
}

function buildPhoneRiskAssessment() {
  return {
    teaSeverity: 'HIGH',
    changeRisk:  'MODERATE',
    summary:
      'SMS OTP and phone call authentication are vulnerable to SIM swapping, SS7 interception, ' +
      'and real-time phishing (AiTM). NIST SP 800-63B classifies them as "restricted" authenticators. ' +
      'Disabling them closes a widely-exploited account takeover path but requires migrating all users ' +
      'currently enrolled with Phone as their only MFA factor.',
    preChangeChecks: [
      'Run the SMS usage log query (system.sms.send_factor_verify_message) to measure how many users actively use Phone MFA.',
      'Identify users who have Phone as their ONLY enrolled MFA factor — they will lose MFA access when Phone is disabled.',
      'Run a factor enrollment campaign for those users before deactivating: enroll them in Okta Verify or WebAuthn.',
      'Remove Phone from all Authentication and Enrollment policy rules before deactivating the authenticator.',
    ],
    blastRadius:
      'Users with Phone as their only MFA factor will be unable to authenticate after deactivation. ' +
      'The blast radius is proportional to the number of users enrolled exclusively in Phone MFA. ' +
      'Communicate the change and the migration deadline before deactivating.',
    rolloutSteps: [
      'Step 1 — Baseline: run SMS/voice log queries to quantify active usage.',
      'Step 2 — Identify and migrate users with Phone as their only factor.',
      'Step 3 — Remove Phone from all Authentication and Enrollment policy rules.',
      'Step 4 — Deactivate the Phone authenticator via Security > Authenticators.',
      'Step 5 — Monitor for MFA failures over 48 hours (see postChangeMonitoring queries).',
    ],
    postChangeMonitoring: {
      description:
        'After deactivating Phone, watch for MFA failures from users who still had it enrolled. ' +
        'A spike in denied sign-ins or help desk tickets signals users who were missed during migration.',
      logQueries: [
        {
          description: 'Sign-in failures post-deactivation (users who relied on Phone)',
          filter: 'eventType eq "user.session.start" AND outcome.result eq "DENY"',
          timeWindow: 'first 48 hours post-change',
          note: 'Each DENY here could be a user who only had Phone enrolled. Check actor and assist with factor enrollment.',
        },
        {
          description: 'Confirm no SMS OTPs are being sent post-deactivation',
          filter: 'eventType eq "system.sms.send_factor_verify_message"',
          timeWindow: 'first 48 hours post-change',
          note: 'Should drop to zero immediately after deactivation. Any events here indicate Phone was not fully removed from all policies.',
        },
      ],
    },
    rollback:
      'Reactivate the Phone authenticator from Security > Authenticators > Actions > Activate. ' +
      'Re-add Phone to the relevant Authentication and Enrollment policy rules. ' +
      'Reactivation takes effect immediately.',
  };
}

function buildSecurityQuestionRiskAssessment() {
  return {
    teaSeverity: 'MODERATE',
    changeRisk:  'LOW',
    summary:
      'Security Questions are a knowledge-based authenticator with a weak security profile — ' +
      'answers are often derivable from public sources (social media, data breaches, targeted research). ' +
      'Disabling them is low change risk because few users rely on them exclusively for MFA ' +
      'and they are rarely used as primary authentication.',
    preChangeChecks: [
      'Check enrollment: run user.mfa.factor.activate events filtered by "Security Question" to see how many users have it enrolled.',
      'Identify users who rely on Security Question for self-service account recovery — they will need an alternative recovery method.',
      'Remove Security Question from all Authentication and Enrollment policy rules before deactivating.',
    ],
    blastRadius:
      'Users with Security Question as their only recovery or MFA factor will lose access to those flows. ' +
      'This is typically a small population. Ensure email or Okta Verify is available as a recovery alternative.',
    rolloutSteps: [
      'Step 1 — Identify enrolled users (user.mfa.factor.activate log query).',
      'Step 2 — Remove Security Question from all policy rules.',
      'Step 3 — Deactivate via Security > Authenticators > Actions > Deactivate.',
      'Step 4 — Monitor for recovery failures (see postChangeMonitoring queries).',
    ],
    postChangeMonitoring: {
      description:
        'After deactivating Security Question, watch for account recovery failures. ' +
        'An increase in admin-assisted resets is the primary signal that users relied on it for recovery.',
      logQueries: [
        {
          description: 'Admin-assisted password resets post-deactivation',
          filter: 'eventType eq "user.account.reset_password"',
          timeWindow: 'first 14 days post-change',
          note: 'An increase in admin-actor resets after deactivation could mean users cannot complete self-service recovery without Security Question.',
        },
        {
          description: 'Confirm Security Question deactivated',
          filter: 'eventType eq "security.authenticator.lifecycle.deactivate"',
          timeWindow: 'last 1 hour',
          note: 'Confirms the deactivation event was recorded.',
        },
      ],
    },
    rollback:
      'Reactivate the Security Question authenticator from Security > Authenticators. ' +
      'Re-add to relevant policy rules. Reactivation takes effect immediately.',
  };
}

// ── Admin console steps ────────────────────────────────────────────────────────

function buildAuthenticatorAdminSteps() {
  return [
    'Sign in to the Okta Admin Console.',
    'Go to Security > Authenticators.',
    'Find "Okta Verify" in the authenticator list and click "Actions" > "Edit".',
    'In the Okta Verify settings, find the "Push notification" section.',
    'Enable "Number challenge" — this requires the user to match the number shown on ' +
    'the sign-in screen with the number in their Okta Verify app.',
    'Click Save.',
    'Communicate the change to users: they will now see a number on screen when approving ' +
    'a push notification and must match it in the Okta Verify app.',
    'Verify via Reports > System Log: filter eventType eq "security.authenticator.lifecycle.update".',
  ];
}

function buildHigherSecurityMethodsAdminSteps() {
  return [
    'Sign in to the Okta Admin Console.',
    '── Step 1: Enable "Higher Security Methods" enrollment restriction ──',
    '  Go to Security > Authenticators.',
    '  Find "Okta Verify" and click Actions > Edit.',
    '  Scroll to the "Enrollment options" section.',
    '  Select "Higher security methods" (instead of "Any method").',
    '  Click Save.',
    '── What this changes ──',
    '  BEFORE: Users can enroll Okta Verify by scanning a QR code shown in the browser,',
    '          or by clicking an SMS or email enrollment link.',
    '  AFTER:  Users can only enroll using Same Device (browser and Okta Verify on the same device)',
    '          or Device-to-Device Bootstrap (Bluetooth pairing between two devices).',
    '  QR code and SMS/email link enrollment are disabled — an attacker who intercepts an',
    '  enrollment URL or QR code cannot register Okta Verify on an attacker-controlled device.',
    '── Step 2: Verify ──',
    '  Go to Reports > System Log and filter: eventType eq "security.authenticator.lifecycle.update".',
    '  Confirm an update event appears after saving.',
    '  Test by attempting a new Okta Verify enrollment — only same-device and Bluetooth options should appear.',
    '── Note: existing enrollments are not affected ──',
    '  Existing Okta Verify enrollments remain active. Only new enrollments are restricted.',
    '  Users who previously enrolled via QR code keep their enrollment.',
  ];
}

function buildHigherSecurityMethodsLogQueries() {
  return [
    {
      description: 'Okta Verify authenticator settings update (confirms enrollment restriction changed)',
      filter: 'eventType eq "security.authenticator.lifecycle.update"',
      timeWindow: 'last 1 hour',
      note: 'Fires when Okta Verify settings are saved. Check the event detail for enrollment options change.',
    },
    {
      description: 'Okta Verify enrollment events by method type',
      filter: 'eventType eq "user.mfa.factor.activate"',
      timeWindow: 'last 30 days',
      note: 'Review Okta Verify enrollments. After enabling Higher Security Methods, no QR code or SMS-link enrollments should appear.',
    },
    {
      description: 'Failed Okta Verify enrollments (users attempting disallowed channels)',
      filter: 'eventType eq "user.mfa.factor.activate" AND outcome.result eq "FAILURE"',
      timeWindow: 'first 7 days post-change',
      note: 'A spike in failed enrollments after enabling Higher Security Methods may indicate users on devices that do not support same-device enrollment.',
    },
  ];
}

function buildHigherSecurityMethodsRiskAssessment() {
  return {
    teaSeverity: 'MODERATE',
    changeRisk:  'LOW',
    summary:
      '"Higher Security Methods" restricts Okta Verify enrollment to same-device and device-to-device ' +
      'Bluetooth only — eliminating QR code and SMS/email link enrollment vectors. ' +
      'An attacker who intercepts a QR code (e.g., from a shared screen, a screenshot) or an ' +
      'SMS/email enrollment link can register Okta Verify on an attacker-controlled device without this restriction. ' +
      'Existing enrollments are not revoked — only new enrollments are restricted.',
    preChangeChecks: [
      'Confirm users have devices that support same-device enrollment (desktop or mobile with Okta Verify installed).',
      'Identify any shared or kiosk devices where same-device enrollment is impractical.',
      'Verify that FastPass (signed_nonce) is enabled — same-device enrollment is the primary FastPass enrollment path.',
      'Notify users about the enrollment method change before enabling.',
    ],
    blastRadius:
      'Existing Okta Verify enrollments are not affected. Only new enrollments are restricted. ' +
      'Users who need to re-enroll (e.g., after a device replacement) must use same-device or Bluetooth — ' +
      'they cannot use QR code or SMS/email link. Help desk volume may increase from users ' +
      'who do not have a compatible device or are unfamiliar with same-device enrollment.',
    rolloutSteps: [
      'Step 1 — Confirm FastPass is enabled (same-device enrollment is the primary FastPass path).',
      'Step 2 — Communicate the enrollment method change to users and IT help desk.',
      'Step 3 — Enable "Higher security methods" in Security > Authenticators > Okta Verify > Edit.',
      'Step 4 — Test with a pilot user on a fresh device to confirm same-device enrollment works.',
      'Step 5 — Monitor enrollment failures for the first 7 days (see postChangeMonitoring queries).',
    ],
    postChangeMonitoring: {
      description:
        'After enabling, watch for failed enrollment attempts — they indicate users on ' +
        'devices that do not support same-device enrollment.',
      logQueries: [
        {
          description: 'Okta Verify enrollment failures post-change',
          filter: 'eventType eq "user.mfa.factor.activate" AND outcome.result eq "FAILURE"',
          timeWindow: 'first 7 days post-change',
          note: 'A spike here suggests users cannot complete same-device enrollment. Check device types and assist with Okta Verify installation.',
        },
        {
          description: 'Successful Okta Verify enrollments post-change',
          filter: 'eventType eq "user.mfa.factor.activate"',
          timeWindow: 'first 7 days post-change',
          note: 'Confirms users are successfully enrolling via the new restriction. Compare volume to pre-change baseline.',
        },
      ],
    },
    rollback:
      'Re-select "Any method" in Security > Authenticators > Okta Verify > Edit > Enrollment options. ' +
      'Takes effect immediately — QR code and SMS/email link enrollment are restored.',
  };
}

// ── Risk assessment ────────────────────────────────────────────────────────────

function buildAuthenticatorRiskAssessment() {
  return {
    teaSeverity: 'MODERATE',
    changeRisk:  'LOW',
    summary:
      'Number Challenge is a highly effective defence against MFA fatigue attacks (T1621 / Push Bombing). ' +
      'Without it, a threat actor with a user\'s credentials can repeatedly push MFA requests until ' +
      'the user accidentally or intentionally approves one. Number Challenge breaks this attack completely ' +
      'because the user must see the matching number on the legitimate sign-in screen — ' +
      'an out-of-band push approval is impossible.',
    preChangeChecks: [
      'Confirm Okta Verify is the primary authenticator in use — Number Challenge only applies to Okta Verify push notifications.',
      'Check that the Okta Verify app version deployed to users supports Number Challenge (requires Okta Verify 7.x or later).',
      'Prepare a user communication explaining the new confirmation step before enabling.',
    ],
    blastRadius:
      'Number Challenge adds an extra confirmation step but does not block legitimate sign-ins. ' +
      'Users who habitually approve pushes without reading the notification will need to adjust their behaviour. ' +
      'The change is intuitive for most users — the Okta Verify app displays the challenge number prominently.',
    rolloutSteps: [
      'Step 1 — Enable Number Challenge in Security > Authenticators > Okta Verify.',
      'Step 2 — Send user communication explaining the new confirmation step before it goes live.',
      'Step 3 — Monitor for denied pushes and confused users (see postChangeMonitoring queries).',
    ],
    postChangeMonitoring: {
      description:
        'After enabling Number Challenge, watch for a temporary spike in denied pushes as users adapt. ' +
        'An elevated deny rate after the first week suggests additional user communication is needed.',
      logQueries: [
        {
          description: 'Push notification denied / failed events (users rejecting or failing Number Challenge) — OIE',
          filter: 'eventType eq "user.authentication.auth_via_mfa" AND outcome.result eq "FAILURE"',
          timeWindow: 'first 14 days post-change',
          note: 'OIE equivalent for denied/failed Okta Verify push.',
        },
        {
          description: 'Okta Verify factor deactivations (unenrollment monitor)',
          filter: 'eventType eq "user.mfa.factor.deactivate"',
          timeWindow: 'first 14 days post-change',
          note: 'Monitor for any increase in Okta Verify unenrollments — a spike may mean frustrated users are removing the app.',
        },
      ],
    },
    rollback:
      'Disabling Number Challenge in the Okta Verify settings immediately removes the ' +
      'requirement. Takes effect on the next push request.',
  };
}

// ── Tool registration ─────────────────────────────────────────────────────────

function registerAuthenticatorTools(server) {
  server.tool(
    'okta_list_authenticators',
    'List all Okta authenticators with a TEA-aligned security audit covering six checks: ' +
    '(1) Okta Verify Number Challenge — flags if push bombing protection is disabled (T1621, MODERATE); ' +
    '(2) Okta Verify Higher Security Methods — flags if QR code and SMS/email link enrollment are allowed (MODERATE); ' +
    '(3) WebAuthn/FIDO2 — flags if phishing-resistant hardware authenticator is not active (T1566/T1557, HIGH); ' +
    '(4) FastPass — flags if Okta\'s phishing-resistant passwordless authenticator is not enabled; ' +
    'note that FastPass is only phishing-resistant when ALSO enforced by an Authentication Policy possession constraint (phishingResistant: "REQUIRED") — enabling FastPass alone does not prevent fallback to push/TOTP (T1566/T1557, MODERATE); ' +
    '(5) Phone/SMS — flags if SMS/voice call MFA is active and should be disabled (T1451 SIM swap, HIGH); ' +
    '(6) Security Questions — flags if knowledge-based MFA is active and should be disabled (T1110/T1566, MODERATE). ' +
    'Returns per-authenticator audit results with Terraform HCL, admin console steps, and remediation guidance.',
    {},
    async () => {
      if (process.env.OFFLINE_MODE === 'true') {
        const defaultAuth  = { id: '<OKTA_VERIFY_ID>',        settings: {}, methods: [] };
        const phoneStub    = { id: '<PHONE_AUTHENTICATOR_ID>' };
        const sqStub       = { id: '<SECURITY_QUESTION_ID>'  };
        return buildMcpOffline({
          remediation: {
            terraform: [
              buildAuthenticatorTerraform(defaultAuth),
              buildWebAuthnTerraform(),
              buildFastPassTerraform('<OKTA_VERIFY_ID>', {}),
              buildPhoneTerraform(phoneStub.id),
              buildSecurityQuestionTerraform(sqStub.id),
            ].join('\n'),
            logQueries: [
              ...buildAuthenticatorLogQueries(),
              ...buildHigherSecurityMethodsLogQueries(),
              ...buildWebAuthnLogQueries(),
              ...buildFastPassLogQueries(),
              ...buildPhoneLogQueries(),
              ...buildSecurityQuestionLogQueries(),
            ],
            adminConsoleSteps: {
              oktaVerify:             buildAuthenticatorAdminSteps(),
              higherSecurityMethods:  buildHigherSecurityMethodsAdminSteps(),
              webAuthn:               buildWebAuthnAdminSteps(),
              fastPass:               buildFastPassAdminSteps(),
              phone:                  buildPhoneAdminSteps(),
              securityQuestion:       buildSecurityQuestionAdminSteps(),
            },
            riskAssessment: {
              oktaVerify:             buildAuthenticatorRiskAssessment(),
              higherSecurityMethods:  buildHigherSecurityMethodsRiskAssessment(),
              webAuthn:               buildWebAuthnRiskAssessment(),
              fastPass:               buildFastPassRiskAssessment(),
              phone:                  buildPhoneRiskAssessment(),
              securityQuestion:       buildSecurityQuestionRiskAssessment(),
            },
          },
        });
      }
      try {
        const client = await createOktaClient();
        const { data: authenticators } = await client.get('/api/v1/authenticators');

        const oktaVerify    = findOktaVerifyAuthenticator(authenticators);
        const ovAudit       = oktaVerify ? auditOktaVerify(oktaVerify) : null;
        const webAuthnAudit = auditWebAuthnAuthenticator(authenticators);
        const fastPassAudit = auditFastPass(oktaVerify);
        const phoneAudit    = auditPhoneAuthenticator(authenticators);
        const sqAudit       = auditSecurityQuestionAuthenticator(authenticators);

        const allFindings = [
          ...(ovAudit?.findings    ?? []),
          ...webAuthnAudit.findings,
          ...fastPassAudit.findings,
          ...phoneAudit.findings,
          ...sqAudit.findings,
        ];

        return buildMcpOk({
          summary: {
            totalAuthenticators:       authenticators.length,
            totalFindingCount:         allFindings.length,
            highFindings:              allFindings.filter((f) => f.severity === 'HIGH').length,
            // High-assurance phishing-resistant factors (should be enabled)
            oktaVerifyPresent:                 Boolean(oktaVerify),
            oktaVerifyFindings:                ovAudit ? ovAudit.findingCount : 0,
            oktaVerifyNumberChallenge:         ovAudit ? ovAudit.current.numberChallengeEnabled : null,
            // null = API cannot confirm enrollment restriction (manual Admin Console check required)
            oktaVerifyHigherSecurityMethods:   ovAudit ? ovAudit.current.higherSecurityMethodsEnabled : null,
            webAuthnActive:                    webAuthnAudit.active,
            fastPassActive:                    fastPassAudit.active,
            // Weak factors (should be disabled)
            phoneActive:               phoneAudit.active,
            securityQuestionActive:    sqAudit.active,
          },
          authenticators: authenticators.map((a) => ({
            id: a.id, key: a.key, name: a.name, type: a.type, status: a.status,
            methods: a.methods ?? null,
          })),
          findings: allFindings,
          oktaVerifyAudit:       ovAudit,
          webAuthnAudit,
          fastPassAudit,
          phoneAudit,
          securityQuestionAudit: sqAudit,
          remediation: {
            terraform: [
              oktaVerify          ? buildAuthenticatorTerraform(oktaVerify) : null,
              !webAuthnAudit.active ? buildWebAuthnTerraform() : null,
              !fastPassAudit.active ? buildFastPassTerraform(oktaVerify?.id, oktaVerify?.settings) : null,
              phoneAudit.active   ? buildPhoneTerraform(phoneAudit.authenticatorId) : null,
              sqAudit.active      ? buildSecurityQuestionTerraform(sqAudit.authenticatorId) : null,
            ].filter(Boolean).join('\n') || null,
            logQueries: [
              ...buildAuthenticatorLogQueries(),
              // Include Higher Security Methods queries when not confirmed enabled
              ...(ovAudit?.current?.higherSecurityMethodsEnabled !== true ? buildHigherSecurityMethodsLogQueries() : []),
              ...(!webAuthnAudit.active ? buildWebAuthnLogQueries() : []),
              ...(!fastPassAudit.active ? buildFastPassLogQueries() : []),
              ...(phoneAudit.active     ? buildPhoneLogQueries() : []),
              ...(sqAudit.active        ? buildSecurityQuestionLogQueries() : []),
            ],
            adminConsoleSteps: {
              oktaVerify:            buildAuthenticatorAdminSteps(),
              higherSecurityMethods: buildHigherSecurityMethodsAdminSteps(),
              webAuthn:              !webAuthnAudit.active ? buildWebAuthnAdminSteps() : null,
              fastPass:              !fastPassAudit.active ? buildFastPassAdminSteps() : null,
              phone:                 phoneAudit.active     ? buildPhoneAdminSteps() : null,
              securityQuestion:      sqAudit.active        ? buildSecurityQuestionAdminSteps() : null,
            },
            riskAssessment: {
              oktaVerify:            oktaVerify            ? buildAuthenticatorRiskAssessment() : null,
              higherSecurityMethods: buildHigherSecurityMethodsRiskAssessment(),
              webAuthn:              !webAuthnAudit.active  ? buildWebAuthnRiskAssessment() : null,
              fastPass:              !fastPassAudit.active  ? buildFastPassRiskAssessment() : null,
              phone:                 phoneAudit.active      ? buildPhoneRiskAssessment() : null,
              securityQuestion:      sqAudit.active         ? buildSecurityQuestionRiskAssessment() : null,
            },
          },
        });
      } catch (err) {
        return buildMcpError(err);
      }
    },
  );

  server.tool(
    'okta_update_okta_verify_settings',
    'Update Okta Verify authenticator settings: enable Number Challenge (anti-push-bombing, T1621), ' +
    'enable Higher Security Methods enrollment restriction (eliminates QR code and SMS/email link enrollment vectors), ' +
    'enable FastPass (phishing-resistant passwordless when also enforced by Authentication Policy — ' +
    'enabling FastPass alone does not prevent fallback to push/TOTP without phishingResistant: "REQUIRED" in policy, T1566/T1557), ' +
    'or set the userVerification level. ' +
    'FastPass is enabled/disabled via the methods lifecycle API independently of settings. ' +
    'Finds the Okta Verify authenticator automatically. ' +
    'Write operation — confirm with the admin before calling.',
    {
      numberChallenge: z.enum(['ENABLED', 'DISABLED']).optional()
        .describe('Enable Number Challenge for push requests. Recommended: "ENABLED".'),
      higherSecurityMethods: z.boolean().optional()
        .describe(
          'Enable "Higher Security Methods" enrollment restriction. When true, sets enrollmentSecurityLevel = "HIGH" — ' +
          'users can only enroll Okta Verify via same-device or device-to-device Bluetooth. ' +
          'QR code, SMS, and email link enrollment are disabled. ' +
          'Existing enrollments are not affected.',
        ),
      userVerification: z.enum(['REQUIRED', 'PREFERRED', 'DISCOURAGED']).optional()
        .describe('Level of user verification for Okta Verify: REQUIRED (biometric/PIN always), PREFERRED, or DISCOURAGED.'),
      fastPass: z.enum(['ENABLED', 'DISABLED']).optional()
        .describe(
          'Enable or disable Okta FastPass (signed_nonce method). ' +
          'ENABLED calls POST /api/v1/authenticators/{id}/methods/signed_nonce/lifecycle/activate. ' +
          'DISABLED calls the deactivate lifecycle endpoint. ' +
          'NOTE: enabling FastPass makes it available, but phishing resistance only takes effect when ' +
          'Authentication Policy rules also set phishingResistant: "REQUIRED" on the possession constraint. ' +
          'Without that policy enforcement, sign-ins may still satisfy via push notifications or TOTP.',
        ),
      authenticatorId: z.string().optional()
        .describe('Okta Verify authenticator ID. Omit to auto-detect from the authenticators list.'),
    },
    async ({ numberChallenge, higherSecurityMethods, userVerification, fastPass, authenticatorId }) => {
      if (process.env.OFFLINE_MODE === 'true') {
        return buildMcpOffline({ skipped: true, message: 'Write operations are not available in offline mode.' });
      }
      if (process.env.PROD_MODE === 'true') {
        return buildMcpReadOnly();
      }
      if (numberChallenge === undefined && higherSecurityMethods === undefined && userVerification === undefined && fastPass === undefined) {
        return buildMcpError(new Error(
          'Provide at least one setting to update: numberChallenge, higherSecurityMethods, userVerification, or fastPass.',
        ));
      }

      try {
        const client = await createOktaClient();

        let targetId = authenticatorId;
        let authenticator;

        if (targetId) {
          const { data } = await client.get(`/api/v1/authenticators/${targetId}`);
          authenticator = data;
        } else {
          const { data: all } = await client.get('/api/v1/authenticators');
          authenticator = findOktaVerifyAuthenticator(all);
          if (!authenticator) {
            return buildMcpError(new Error(
              'Okta Verify authenticator not found. ' +
              'Use okta_list_authenticators to confirm it is enrolled, ' +
              'or supply authenticatorId directly.',
            ));
          }
          targetId = authenticator.id;
        }

        if (authenticator.key !== OKTA_VERIFY_KEY) {
          return buildMcpError(new Error(
            `Authenticator "${targetId}" has key "${authenticator.key}", not "${OKTA_VERIFY_KEY}". ` +
            'This tool only updates the Okta Verify authenticator.',
          ));
        }

        // Build the PUT body preserving all current settings except appInstanceId
        // (Okta-internal field that causes settings updates to be silently discarded).
        // The tool's numberChallenge ENABLED/DISABLED param maps to the actual Okta API
        // field: settings.channelBinding.required = "ALWAYS" / "NEVER".
        const currentSettings = authenticator.settings || {};
        const { appInstanceId: _internal, ...spreadableSettings } = currentSettings;
        const writableSettings = { ...spreadableSettings };

        if (numberChallenge !== undefined) {
          writableSettings.channelBinding = {
            style: spreadableSettings.channelBinding?.style ?? CHANNEL_BINDING_STYLE,
            required: numberChallenge === NUMBER_CHALLENGE_ENABLED
              ? CHANNEL_BINDING_ALWAYS
              : CHANNEL_BINDING_NEVER,
          };
        }
        if (higherSecurityMethods !== undefined) {
          writableSettings.enrollmentSecurityLevel = higherSecurityMethods
            ? ENROLLMENT_SECURITY_LEVEL_HIGH
            : ENROLLMENT_SECURITY_LEVEL_ANY;
        }
        if (userVerification !== undefined) {
          writableSettings.userVerification = userVerification;
        }

        // Only call PUT settings if settings-related params were given
        if (numberChallenge !== undefined || higherSecurityMethods !== undefined || userVerification !== undefined) {
          await client.put(`/api/v1/authenticators/${targetId}`, {
            key: authenticator.key,
            name: authenticator.name,
            settings: writableSettings,
          });
        }

        // FastPass is a method lifecycle operation — independent of the settings PUT.
        // POST /api/v1/authenticators/{id}/methods/signed_nonce/lifecycle/activate|deactivate
        let fastPassError = null;
        if (fastPass !== undefined) {
          const action = fastPass === 'ENABLED' ? 'activate' : 'deactivate';
          try {
            await client.post(
              `/api/v1/authenticators/${targetId}/methods/${FASTPASS_METHOD_TYPE}/lifecycle/${action}`,
            );
          } catch (fpErr) {
            fastPassError = fpErr?.response?.data?.errorSummary ?? fpErr.message;
          }
        }

        // Re-fetch after PUT: Okta's PUT response often returns the pre-update object or
        // omits settings entirely, making it unreliable as an audit source. The GET gives
        // the actual persisted state and surfaces any propagation delay accurately.
        const { data: updated } = await client.get(`/api/v1/authenticators/${targetId}`);

        const fastPassAuditBefore = auditFastPass(authenticator);
        const fastPassAuditAfter  = auditFastPass(updated);

        // The main authenticator endpoint's methods array does not reliably reflect
        // signed_nonce status immediately after a lifecycle call. Query the method
        // endpoint directly to get the true persisted state.
        let fastPassMethodActive = null;
        if (fastPass !== undefined && !fastPassError) {
          try {
            const { data: method } = await client.get(
              `/api/v1/authenticators/${targetId}/methods/${FASTPASS_METHOD_TYPE}`,
            );
            fastPassMethodActive = method.status === 'ACTIVE';
          } catch (_) {
            // method endpoint unavailable — fall back to authenticator-level audit
          }
        }

        const fastPassAfterResolved = fastPassMethodActive !== null
          ? fastPassMethodActive
          : fastPassAuditAfter.active;

        const auditBefore = auditOktaVerify(authenticator);
        const auditAfter = auditOktaVerify(updated);

        const appliedChanges = {};
        if (numberChallenge !== undefined)       { appliedChanges.numberChallenge = numberChallenge; }
        if (higherSecurityMethods !== undefined) { appliedChanges.higherSecurityMethods = higherSecurityMethods; }
        if (userVerification !== undefined)      { appliedChanges.userVerification = userVerification; }
        if (fastPass !== undefined) {
          appliedChanges.fastPass = fastPassError
            ? `ATTEMPTED_${fastPass} (error: ${fastPassError})`
            : fastPass;
        }

        // diagnostics surfaces the exact settings sent and what Okta returned — useful
        // when the change appears to succeed but the setting does not reflect.
        const diagnostics = {
          settingsSent: (numberChallenge !== undefined || higherSecurityMethods !== undefined || userVerification !== undefined) ? writableSettings : null,
          settingsReturnedByOkta: updated.settings ?? null,
          settingsBeforeUpdate: currentSettings,
          fastPassBefore: fastPassAuditBefore.active,
          fastPassAfter:  fastPassAfterResolved,
          ...(fastPassMethodActive !== null ? { fastPassVerifiedViaMethodEndpoint: true } : {}),
          ...(fastPassError ? { fastPassError } : {}),
        };

        const propagationWarning = auditAfter.findingCount > 0
          ? 'PUT succeeded but the re-fetched authenticator still shows findings. ' +
            'Check diagnostics.settingsReturnedByOkta to see what Okta persisted. ' +
            'If numberChallenge is absent or DISABLED after update, the token may lack ' +
            'okta.authenticators.manage scope — re-run okta_login to refresh.'
          : null;

        return buildMcpOk({
          message: `Okta Verify authenticator updated successfully.`,
          authenticatorId: updated.id,
          appliedChanges,
          findingsBefore: auditBefore.findingCount,
          findingsAfter: auditAfter.findingCount,
          remainingFindings: auditAfter.findings,
          fastPass: {
            before: fastPassAuditBefore.active,
            after:  fastPassAfterResolved,
            findings: fastPassAfterResolved ? [] : fastPassAuditAfter.findings,
          },
          diagnostics,
          ...(propagationWarning ? { propagationWarning } : {}),
          remediation: {
            terraform: buildAuthenticatorTerraform(updated),
            logQueries: [
              ...buildAuthenticatorLogQueries(),
              ...(fastPass === 'ENABLED' ? buildFastPassLogQueries() : []),
            ],
            adminConsoleSteps: buildAuthenticatorAdminSteps(),
            riskAssessment: buildAuthenticatorRiskAssessment(),
          },
        });
      } catch (err) {
        return buildMcpError(err);
      }
    },
  );
  server.tool(
    'okta_activate_webauthn',
    'Activate the WebAuthn/FIDO2 (Security Key or Biometric) authenticator in the Okta org. ' +
    'If WebAuthn is already present but INACTIVE, calls POST /api/v1/authenticators/{id}/lifecycle/activate. ' +
    'If WebAuthn is not yet provisioned in the org, creates it via POST /api/v1/authenticators. ' +
    'Enabling WebAuthn is additive — it does not affect existing sign-in flows until Authentication Policy ' +
    'rules are updated to require phishingResistant. ' +
    'Write operation — confirm with the admin before calling.',
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
        const { data: all } = await client.get('/api/v1/authenticators');

        const existing = all.find((a) => a.key === WEBAUTHN_KEY);

        if (existing?.status === 'ACTIVE') {
          return buildMcpOk({
            message: 'WebAuthn/FIDO2 authenticator is already ACTIVE — no change made.',
            authenticatorId: existing.id,
            authenticatorKey: existing.key,
            status: existing.status,
            remediation: {
              terraform: buildWebAuthnTerraform(),
              logQueries: buildWebAuthnLogQueries(),
              adminConsoleSteps: buildWebAuthnAdminSteps(),
              riskAssessment: buildWebAuthnRiskAssessment(),
            },
          });
        }

        let updated;

        if (existing) {
          // Present but INACTIVE — use lifecycle activate
          await client.post(`/api/v1/authenticators/${existing.id}/lifecycle/activate`);
          const { data } = await client.get(`/api/v1/authenticators/${existing.id}`);
          updated = data;
        } else {
          // Not provisioned — create it
          const { data } = await client.post('/api/v1/authenticators', {
            key: WEBAUTHN_KEY,
            name: 'Security Key or Biometric',
            type: 'SECURITY_KEY',
            status: 'ACTIVE',
          });
          updated = data;
        }

        return buildMcpOk({
          message: `WebAuthn/FIDO2 authenticator activated successfully.`,
          authenticatorId: updated.id,
          authenticatorKey: updated.key,
          statusBefore: existing?.status ?? null,
          statusAfter: updated.status,
          nextSteps: [
            'Add WebAuthn to an Enrollment Policy (Security > Authenticators > Enrollment) so users can self-enroll.',
            'For high-value apps, update Authentication Policy rules to set possession constraint phishingResistant = Required.',
            'Run the log queries below to monitor enrollment growth.',
          ],
          remediation: {
            terraform: buildWebAuthnTerraform(),
            logQueries: buildWebAuthnLogQueries(),
            adminConsoleSteps: buildWebAuthnAdminSteps(),
            riskAssessment: buildWebAuthnRiskAssessment(),
          },
        });
      } catch (err) {
        return buildMcpError(err);
      }
    },
  );

  server.tool(
    'okta_deactivate_weak_authenticator',
    'Deactivate an insecure authenticator — either the Phone (SMS/voice call) authenticator ' +
    '(HIGH severity TEA finding: SIM swap / SS7 vulnerable) or the Security Question authenticator ' +
    '(MODERATE severity TEA finding: spearphishing / data leak vulnerable). ' +
    'Calls POST /api/v1/authenticators/{id}/lifecycle/deactivate. ' +
    'IMPORTANT: Remove the authenticator from all Authentication and Enrollment policy rules ' +
    'before deactivating, and ensure affected users have an alternative MFA factor enrolled. ' +
    'Write operation — confirm with the admin before calling.',
    {
      authenticatorKey: z.enum([PHONE_NUMBER_KEY, SECURITY_QUESTION_KEY])
        .describe(
          'Which authenticator to deactivate: ' +
          '"phone_number" (SMS/voice call MFA, HIGH severity) or ' +
          '"security_question" (knowledge-based MFA, MODERATE severity).',
        ),
    },
    async ({ authenticatorKey }) => {
      if (process.env.OFFLINE_MODE === 'true') {
        return buildMcpOffline({ skipped: true, message: 'Write operations are not available in offline mode.' });
      }
      if (process.env.PROD_MODE === 'true') {
        return buildMcpReadOnly();
      }
      try {
        const client = await createOktaClient();
        const { data: all } = await client.get('/api/v1/authenticators');

        const target = all.find((a) => a.key === authenticatorKey);
        if (!target) {
          return buildMcpError(new Error(
            `Authenticator with key "${authenticatorKey}" not found. ` +
            'Use okta_list_authenticators to see all configured authenticators.',
          ));
        }

        if (target.status === 'INACTIVE') {
          return buildMcpOk({
            message: `Authenticator "${target.name}" is already INACTIVE — no change made.`,
            authenticatorId: target.id,
            authenticatorKey: target.key,
            status: target.status,
          });
        }

        await client.post(`/api/v1/authenticators/${target.id}/lifecycle/deactivate`);

        const { data: updated } = await client.get(`/api/v1/authenticators/${target.id}`);
        const riskAssessment = authenticatorKey === PHONE_NUMBER_KEY
          ? buildPhoneRiskAssessment()
          : buildSecurityQuestionRiskAssessment();

        return buildMcpOk({
          message: `Authenticator "${updated.name}" deactivated successfully.`,
          authenticatorId: updated.id,
          authenticatorKey: updated.key,
          statusBefore: target.status,
          statusAfter:  updated.status,
          remediation: {
            logQueries: authenticatorKey === PHONE_NUMBER_KEY
              ? buildPhoneLogQueries()
              : buildSecurityQuestionLogQueries(),
            adminConsoleSteps: authenticatorKey === PHONE_NUMBER_KEY
              ? buildPhoneAdminSteps()
              : buildSecurityQuestionAdminSteps(),
            riskAssessment,
          },
        });
      } catch (err) {
        return buildMcpError(err);
      }
    },
  );
}

module.exports = {
  registerAuthenticatorTools,
  findOktaVerifyAuthenticator,
  auditOktaVerify,
  auditWebAuthnAuthenticator,
  auditFastPass,
  auditPhoneAuthenticator,
  auditSecurityQuestionAuthenticator,
  buildAuthenticatorTerraform,
  buildWebAuthnTerraform,
  buildFastPassTerraform,
  buildPhoneTerraform,
  buildSecurityQuestionTerraform,
  buildAuthenticatorLogQueries,
  buildWebAuthnLogQueries,
  buildFastPassLogQueries,
  buildPhoneLogQueries,
  buildSecurityQuestionLogQueries,
  buildAuthenticatorRiskAssessment,
  buildWebAuthnRiskAssessment,
  buildFastPassRiskAssessment,
  buildPhoneRiskAssessment,
  buildSecurityQuestionRiskAssessment,
};
