'use strict';

const { buildMcpOk, buildMcpError, buildMcpOffline } = require('./resolver-utils');
const { createOktaClient } = require('../auth/okta-client');

// ── Fetchers ───────────────────────────────────────────────────────────────────

async function fetchCaptchas(client) {
  try {
    const { data } = await client.get('/api/v1/captchas');
    return { available: true, captchas: Array.isArray(data) ? data : [] };
  } catch (err) {
    const status = err.response?.status;
    if (status === 404 || status === 403) {
      return {
        available: false,
        reason: `API returned ${status} — CAPTCHA endpoint may require okta.captchas.read scope or OIE.`,
        captchas: [],
      };
    }
    return { available: false, reason: err.message, captchas: [] };
  }
}

async function fetchOrgCaptchaSettings(client) {
  try {
    const { data } = await client.get('/api/v1/org/captcha');
    return { available: true, data };
  } catch (err) {
    const status = err.response?.status;
    if (status === 404 || status === 403) {
      return {
        available: false,
        reason: `API returned ${status} — org CAPTCHA settings endpoint unavailable.`,
        data: null,
      };
    }
    return { available: false, reason: err.message, data: null };
  }
}

// ── Audit ──────────────────────────────────────────────────────────────────────

function auditCaptcha({ captchas, orgSettings }) {
  const findings = [];

  const configuredCaptchas = captchas.available ? captchas.captchas : [];
  const orgData = orgSettings.available ? orgSettings.data : null;

  // Check if CAPTCHA providers are configured
  if (!captchas.available || configuredCaptchas.length === 0) {
    findings.push({
      id: 'CAPTCHA_NOT_CONFIGURED',
      severity: 'INFO',
      description:
        'No CAPTCHA integration is configured. Without CAPTCHA, registration and self-service ' +
        'password recovery flows are vulnerable to automated bot attacks and credential stuffing.',
      recommendation:
        'Configure a CAPTCHA provider (hCaptcha or reCAPTCHA v2) under Security > CAPTCHA, ' +
        'then assign it to self-service registration and recovery flows.',
    });
    return { findingCount: findings.length, findings, rawStatus: { captchas: configuredCaptchas, orgSettings: orgData } };
  }

  // Check if CAPTCHA is assigned to any org flows
  const captchaEnabled =
    orgData?.enabledPages?.selfServiceRegistration ||
    orgData?.enabledPages?.selfServicePasswordReset ||
    orgData?.enabledPages?.signIn;

  if (orgData !== null && !captchaEnabled) {
    findings.push({
      id: 'CAPTCHA_NOT_ASSIGNED_TO_FLOWS',
      severity: 'INFO',
      description:
        `A CAPTCHA provider (${configuredCaptchas.map((c) => c.name).join(', ')}) is configured but ` +
        'not assigned to any self-service flows. CAPTCHA is not active until assigned.',
      recommendation:
        'Assign the CAPTCHA provider to self-service registration and password recovery flows ' +
        'under Security > CAPTCHA > Assign to pages.',
    });
  }

  return {
    findingCount: findings.length,
    findings,
    rawStatus: {
      captchas: configuredCaptchas.map((c) => ({ id: c.id, name: c.name, type: c.type })),
      orgSettings: orgData,
    },
  };
}

// ── Terraform ──────────────────────────────────────────────────────────────────

function buildCaptchaTerraform() {
  return `# Terraform — Okta CAPTCHA Integration
#
# Provider setup:
#   https://developer.okta.com/docs/guides/terraform-enable-org-access/main/
# Resource reference:
#   https://registry.terraform.io/providers/okta/okta/latest/docs/resources/captcha
#   https://registry.terraform.io/providers/okta/okta/latest/docs/resources/captcha_org_wide_settings

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
  scopes      = ["okta.captchas.manage"]
  private_key = "<PATH_OR_CONTENT_OF_PRIVATE_KEY>"
}

# Configure hCaptcha (or use type = "RECAPTCHA_V2" for Google reCAPTCHA v2)
resource "okta_captcha" "main" {
  name       = "Security CAPTCHA"
  type       = "HCAPTCHA"
  site_key   = "<YOUR_HCAPTCHA_SITE_KEY>"
  secret_key = "<YOUR_HCAPTCHA_SECRET_KEY>"
}

# Assign CAPTCHA to self-service flows
resource "okta_captcha_org_wide_settings" "assignment" {
  captcha_id            = okta_captcha.main.id
  enable_for_sign_in    = false  # Set true to add CAPTCHA to login page
  enable_for_password_reset = true
  enable_for_registration   = true
}
`;
}

// ── Log queries ────────────────────────────────────────────────────────────────

function buildCaptchaLogQueries() {
  return [
    {
      description: 'CAPTCHA configuration changes',
      filter: 'eventType sw "captcha."',
      timeWindow: 'last 90 days',
      note: 'Audit trail of CAPTCHA provider configuration changes.',
    },
    {
      description: 'Self-service password reset attempts',
      filter: 'eventType eq "user.account.reset_password"',
      timeWindow: 'last 30 days',
      note: 'Monitor for unusual volume of password reset attempts that may indicate bot activity targeting self-service flows.',
    },
    {
      description: 'Self-service registration attempts',
      filter: 'eventType eq "user.lifecycle.create"',
      timeWindow: 'last 7 days',
      note: 'Unusual registration volume may indicate automated account creation — CAPTCHA should reduce this.',
    },
  ];
}

// ── Admin console steps ────────────────────────────────────────────────────────

function buildCaptchaAdminSteps() {
  return [
    'Sign in to the Okta Admin Console.',
    'Go to Security > CAPTCHA.',
    'Click "Add CAPTCHA" and select a provider:',
    '  • hCaptcha — privacy-focused alternative to reCAPTCHA',
    '  • reCAPTCHA v2 — Google-hosted CAPTCHA',
    'Enter the site key and secret key from your CAPTCHA provider account.',
    'Click Save.',
    'In the CAPTCHA list, click the CAPTCHA you just created.',
    'Under "Assign to pages", enable CAPTCHA for:',
    '  • Self-service password reset',
    '  • Self-service account unlock',
    '  • User registration (if enabled)',
    'Click Save.',
    'Test by navigating to the sign-in page and triggering a forgot-password flow.',
  ];
}

// ── Risk assessment ────────────────────────────────────────────────────────────

function buildCaptchaRiskAssessment() {
  return {
    teaSeverity: 'INFO',
    changeRisk:  'LOW',
    summary:
      'CAPTCHA protects self-service flows (registration, password reset, account unlock) ' +
      'from automated bot attacks. Without it, attackers can programmatically flood these ' +
      'endpoints to enumerate valid users, trigger password reset spam, or conduct ' +
      'account lockout denial-of-service. This is an informational finding — valuable to have ' +
      'but not a direct authentication bypass.',
    preChangeChecks: [
      'Confirm you have a CAPTCHA provider account (hCaptcha or Google reCAPTCHA v2) and the site/secret keys.',
      'Identify which self-service flows are enabled: password reset, registration, account unlock.',
      'Check whether any automated scripts or test suites trigger these self-service flows — they will break.',
    ],
    blastRadius:
      'CAPTCHA adds a user-interaction step to the flows it is assigned to. ' +
      'Automated provisioning scripts or test suites that trigger self-service flows will fail. ' +
      'Do not assign CAPTCHA to the main sign-in page unless SSO/SAML flows have been tested — ' +
      'some integrations cannot handle CAPTCHA challenges.',
    rolloutSteps: [
      'Step 1 — Create CAPTCHA provider integration (hCaptcha or reCAPTCHA).',
      'Step 2 — Assign to self-service password reset and account unlock only (avoid sign-in page initially).',
      'Step 3 — Test affected flows manually to confirm CAPTCHA renders correctly.',
      'Step 4 — Monitor for reduced suspicious reset volume (see postChangeMonitoring queries).',
      'Step 5 — Consider enabling for registration if self-registration is open.',
    ],
    postChangeMonitoring: {
      description:
        'After assigning CAPTCHA to self-service flows, monitor for any spike in help desk tickets ' +
        'from users unable to complete password reset. Check CAPTCHA configuration events in System Log.',
      logQueries: [
        {
          description: 'Self-service password reset volume post-CAPTCHA',
          filter: 'eventType eq "user.account.reset_password"',
          timeWindow: 'first 7 days post-change',
          note: 'Volume should remain stable or decrease slightly. A sharp drop could indicate CAPTCHA is blocking legitimate users.',
        },
        {
          description: 'CAPTCHA configuration changes audit',
          filter: 'eventType sw "captcha."',
          timeWindow: 'last 7 days',
          note: 'Confirms CAPTCHA was enabled and assigned correctly.',
        },
      ],
    },
    rollback:
      'CAPTCHA assignment can be removed at any time from Security > CAPTCHA > Assign to pages.',
  };
}

// ── Tool registration ─────────────────────────────────────────────────────────

function registerCaptchaTools(server) {
  server.tool(
    'okta_get_captcha_config',
    'Audit CAPTCHA configuration — checks whether a CAPTCHA provider (hCaptcha or reCAPTCHA) ' +
    'is configured and assigned to self-service flows (registration, password reset, account unlock). ' +
    'CAPTCHA prevents automated bot attacks on publicly accessible Okta self-service endpoints. ' +
    'Returns configuration status and setup guidance.',
    {},
    async () => {
      if (process.env.OFFLINE_MODE === 'true') {
        return buildMcpOffline({
          remediation: {
            terraform:         buildCaptchaTerraform(),
            logQueries:        buildCaptchaLogQueries(),
            adminConsoleSteps: buildCaptchaAdminSteps(),
            riskAssessment:    buildCaptchaRiskAssessment(),
          },
        });
      }
      try {
        const client = await createOktaClient();
        const [captchas, orgSettings] = await Promise.all([
          fetchCaptchas(client),
          fetchOrgCaptchaSettings(client),
        ]);

        const audit = auditCaptcha({ captchas, orgSettings });

        return buildMcpOk({
          ...audit,
          remediation: {
            terraform: buildCaptchaTerraform(),
            logQueries: buildCaptchaLogQueries(),
            adminConsoleSteps: buildCaptchaAdminSteps(),
            riskAssessment: buildCaptchaRiskAssessment(),
          },
        });
      } catch (err) {
        return buildMcpError(err);
      }
    },
  );
}

module.exports = { registerCaptchaTools };
