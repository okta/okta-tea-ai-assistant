'use strict';

const { buildMcpOk, buildMcpError, buildMcpOffline } = require('./resolver-utils');
const { createOktaClient } = require('../auth/okta-client');

// ── Fetchers ───────────────────────────────────────────────────────────────────

async function fetchIdPs(client) {
  try {
    const { data } = await client.get('/api/v1/idps');
    return { available: true, idps: Array.isArray(data) ? data : [] };
  } catch (err) {
    const status = err.response?.status;
    if (status === 404 || status === 403) {
      return {
        available: false,
        reason: `API returned ${status} — IdP endpoint may require okta.idps.read scope.`,
        idps: [],
      };
    }
    return { available: false, reason: err.message, idps: [] };
  }
}

// ── Audit ──────────────────────────────────────────────────────────────────────

function auditIdPs({ idps }) {
  const findings = [];
  const idpAudits = [];

  for (const idp of idps) {
    const idpFindings = [];
    const accountLinkAction = idp.policy?.accountLink?.action || idp.accountLink?.action;

    // Auto-link enabled — external identity can silently take over an existing Okta account
    if (accountLinkAction && accountLinkAction !== 'DISABLED' && accountLinkAction !== 'CALLOUT') {
      idpFindings.push({
        id: 'IDP_AUTO_LINK_ENABLED',
        severity: 'HIGH',
        description:
          `IdP "${idp.name}" (type: ${idp.type}) has account linking action "${accountLinkAction}". ` +
          'Auto-linking allows an external identity (e.g. a Google or SAML account) to be ' +
          'automatically matched and linked to an existing Okta user account. ' +
          'An attacker who controls an IdP or creates a matching external account can silently ' +
          'gain access to an existing Okta account without knowing its password.',
        recommendation:
          `Set accountLink.action to "DISABLED" for IdP "${idp.name}" to require explicit admin ` +
          'approval before linking external identities to existing accounts. ' +
          'Alternatively, use "CALLOUT" to invoke a hook that applies custom linking logic.',
      });
    }

    idpAudits.push({
      id: idp.id,
      name: idp.name,
      type: idp.type,
      status: idp.status,
      accountLinkAction: accountLinkAction || 'not set',
      findings: idpFindings,
    });

    findings.push(...idpFindings);
  }

  return {
    findingCount: findings.length,
    findings,
    summary: {
      totalIdPs: idps.length,
      idpsWithAutoLink: idpAudits.filter((i) => i.findings.length > 0).length,
      idps: idpAudits,
    },
  };
}

// ── Terraform ──────────────────────────────────────────────────────────────────

function buildIdPTerraform() {
  return `# Terraform — Okta Identity Provider (IdP) Auto-Link Settings
#
# Provider setup:
#   https://developer.okta.com/docs/guides/terraform-enable-org-access/main/
# Resource reference:
#   https://registry.terraform.io/providers/okta/okta/latest/docs/resources/idp_social
#   https://registry.terraform.io/providers/okta/okta/latest/docs/resources/idp_saml
#   https://registry.terraform.io/providers/okta/okta/latest/docs/resources/idp_oidc

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
  scopes      = ["okta.idps.manage"]
  private_key = "<PATH_OR_CONTENT_OF_PRIVATE_KEY>"
}

# Example: Disable auto-linking on a Social IdP (Google)
resource "okta_idp_social" "google" {
  type   = "GOOGLE"
  name   = "Google"
  status = "ACTIVE"

  client_id     = "<YOUR_GOOGLE_CLIENT_ID>"
  client_secret = "<YOUR_GOOGLE_CLIENT_SECRET>"
  scopes        = ["openid", "email", "profile"]

  # Prevent automatic account linking — require explicit admin approval
  account_link_action = "DISABLED"

  # When account_link_action is DISABLED, set username and matching rules
  username_template   = "idpuser.email"
  subject_match_type  = "EMAIL"
}

# Example: Disable auto-linking on a SAML IdP
# resource "okta_idp_saml" "enterprise_sso" {
#   name   = "Enterprise SSO"
#   status = "ACTIVE"
#
#   account_link_action = "DISABLED"
#   # ... other SAML settings
# }
`;
}

// ── Log queries ────────────────────────────────────────────────────────────────

function buildIdPLogQueries() {
  return [
    {
      description: 'IdP authentication events (proxy for auto-link activity)',
      filter: 'eventType eq "user.authentication.auth_via_IDP"',
      timeWindow: 'last 30 days',
      note: 'All IdP-mediated authentications. Note: Okta does not emit a dedicated account-link event — use this to baseline IdP authentication volume before and after changing auto-link settings.',
    },
    {
      description: 'New user provisioning via IdP (JIT)',
      filter: 'eventType eq "user.lifecycle.create"',
      timeWindow: 'last 7 days',
      note: 'Users created via JIT provisioning from an IdP. A spike after disabling auto-link may mean new IdP users are failing to get accounts — check JIT provisioning configuration.',
    },
    {
      description: 'IdP configuration changes',
      filter: 'eventType sw "system.idp."',
      timeWindow: 'last 90 days',
      note: 'Audit trail of IdP create, update, activate, and deactivate events.',
    },
  ];
}

// ── Admin console steps ────────────────────────────────────────────────────────

function buildIdPAdminSteps() {
  return [
    'Sign in to the Okta Admin Console.',
    'Go to Security > Identity Providers.',
    'For each IdP listed with auto-linking enabled:',
    '  1. Click the IdP name.',
    '  2. Go to the "Settings" tab.',
    '  3. Under "Account matching", find "Account Link Policy".',
    '  4. Set to "Disabled" to prevent automatic account linking.',
    '     OR set to "Callout" if you need custom linking logic via a hook.',
    '  5. Click Save.',
    '',
    'After disabling auto-link:',
    '  • New IdP users without a matching Okta account will need to be provisioned via JIT ' +
    '    provisioning rules or manual admin action.',
    '  • Existing linked accounts are not affected by this change.',
    '  • Review the "General" tab for JIT Provisioning settings to ensure new users are ' +
    '    correctly handled.',
  ];
}

// ── Risk assessment ────────────────────────────────────────────────────────────

function buildIdPRiskAssessment() {
  return {
    teaSeverity: 'MODERATE',
    changeRisk:  'MODERATE',
    summary:
      'IdP auto-linking allows an external identity to silently claim an existing Okta account ' +
      'if the email addresses match. An attacker who can create or control an account at a ' +
      'linked external IdP (e.g. a Google account with the target\'s email) can bypass Okta ' +
      'passwords and MFA entirely.',
    preChangeChecks: [
      'Check System Log for recent auto-link events to understand how many users rely on this flow.',
      'Confirm whether JIT provisioning is configured and working before disabling auto-link — new IdP users need an alternative path to get an Okta account.',
      'Identify which applications use IdP-initiated sign-in and whether they depend on auto-linking for new user registration.',
    ],
    blastRadius:
      'Disabling auto-linking prevents new external IdP users from silently linking to existing Okta accounts. ' +
      'Existing linked accounts are not affected — only new linking attempts are blocked. ' +
      'JIT provisioning must be configured to handle new users, and existing user flows that relied on ' +
      'auto-linking for registration may need to be reviewed.',
    rolloutSteps: [
      'Step 1 — Audit current IdP auto-link settings with this tool.',
      'Step 2 — Review System Log for recent auto-link events to understand current usage.',
      'Step 3 — Configure JIT provisioning to handle new IdP users before disabling auto-link.',
      'Step 4 — Disable auto-link on all IdPs or switch to CALLOUT for custom logic.',
      'Step 5 — Monitor for failed IdP sign-ins from new users (see postChangeMonitoring queries).',
    ],
    postChangeMonitoring: {
      description:
        'After disabling auto-link, watch for new IdP users who cannot sign in because they have no Okta account ' +
        'and JIT provisioning is not handling them correctly.',
      logQueries: [
        {
          description: 'IdP sign-in failures post-change',
          filter: 'eventType eq "user.authentication.auth_via_social" AND outcome.result eq "FAILURE"',
          timeWindow: 'first 14 days post-change',
          note: 'Failures here after disabling auto-link may indicate new users who need JIT provisioning configured.',
        },
        {
          description: 'IdP authentication volume (auto-link proxy)',
          filter: 'eventType eq "user.authentication.auth_via_IDP"',
          timeWindow: 'first 14 days post-change',
          note: 'Note: Okta does not emit a dedicated auto-link event. Monitor authentication volume via IdP instead — failures from new users who cannot auto-link will appear as sign-in failures rather than link events.',
        },
      ],
    },
    rollback:
      'Account link action can be changed back at any time from the IdP settings page.',
  };
}

// ── Tool registration ─────────────────────────────────────────────────────────

function registerIdPConfigTools(server) {
  server.tool(
    'okta_get_idp_config',
    'Audit Okta Identity Provider (IdP) configurations — checks whether any IdPs have ' +
    'account auto-linking enabled. Auto-linking allows an external identity (Google, SAML, OIDC) ' +
    'to automatically claim an existing Okta account by matching email address, bypassing ' +
    'Okta credentials and MFA. Returns per-IdP audit results and remediation guidance.',
    {},
    async () => {
      if (process.env.OFFLINE_MODE === 'true') {
        return buildMcpOffline({
          remediation: {
            terraform:         buildIdPTerraform(),
            logQueries:        buildIdPLogQueries(),
            adminConsoleSteps: buildIdPAdminSteps(),
            riskAssessment:    buildIdPRiskAssessment(),
          },
        });
      }
      try {
        const client = await createOktaClient();
        const result = await fetchIdPs(client);

        if (!result.available) {
          return buildMcpOk({
            available: false,
            reason: result.reason,
            findings: [{
              id: 'IDP_API_UNAVAILABLE',
              severity: 'INFO',
              description: `Identity Providers API unavailable: ${result.reason}`,
              recommendation: 'Verify manually under Security > Identity Providers in the Admin Console.',
            }],
          });
        }

        if (result.idps.length === 0) {
          return buildMcpOk({
            summary: { totalIdPs: 0, idpsWithAutoLink: 0, idps: [] },
            findingCount: 0,
            findings: [],
            note: 'No Identity Providers are configured on this tenant.',
          });
        }

        const audit = auditIdPs(result);

        return buildMcpOk({
          ...audit,
          remediation: {
            terraform: buildIdPTerraform(),
            logQueries: buildIdPLogQueries(),
            adminConsoleSteps: buildIdPAdminSteps(),
            riskAssessment: buildIdPRiskAssessment(),
          },
        });
      } catch (err) {
        return buildMcpError(err);
      }
    },
  );
}

module.exports = { registerIdPConfigTools };
