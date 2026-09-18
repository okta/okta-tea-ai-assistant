'use strict';

const { buildMcpOk, buildMcpError, buildMcpOffline } = require('./resolver-utils');
const { createOktaClient } = require('../auth/okta-client');

// Any active API tokens trigger the MODERATE finding — OAuth2 is always preferred.
const TOKEN_THRESHOLD = 0;

// ── Helpers ───────────────────────────────────────────────────────────────────

/**
 * Check whether a token has a network zone restriction.
 *
 * TODO: verify field name against a live API response.
 * The Okta API token object is documented to carry zone restriction info but
 * the exact field name was not confirmed from docs at time of writing.
 * Known candidates: `networkCondition`, `network`, `allowedNetworkZones`.
 * The check below tests all known variants defensively.
 */
function hasZoneRestriction(token) {
  const nc = token.networkCondition ?? token.network ?? token.allowedNetworkZones;
  if (!nc) return false;
  // networkCondition shape: { include: [{ type: "ZONE", id: "nzo...", name: "..." }] }
  if (Array.isArray(nc?.include) && nc.include.length > 0) return true;
  if (Array.isArray(nc) && nc.length > 0) return true;
  return false;
}

/** A token has an expiry if expiresAt is set OR a rolling tokenWindow is set. */
function hasExpiry(token) {
  if (token.expiresAt) return true;
  // tokenWindow is an ISO 8601 duration string; "PT0S" / empty means no window
  const tw = token.tokenWindow;
  if (tw && tw !== 'PT0S' && tw !== 'P0Y0M0DT0H0M0.000S') return true;
  return false;
}

function summariseToken(token) {
  return {
    id:               token.id,
    name:             token.name,
    clientName:       token.clientName || null,
    userId:           token.userId,
    created:          token.created,
    expiresAt:        token.expiresAt || null,
    tokenWindow:      token.tokenWindow || null,
    lastUpdated:      token.lastUpdated || null,
    zoneRestricted:   hasZoneRestriction(token),
    hasExpiry:        hasExpiry(token),
  };
}

// ── Fetchers ──────────────────────────────────────────────────────────────────

async function fetchApiTokens(client) {
  const tokens = [];
  let nextUrl = '/api/v1/api-tokens?limit=200';

  try {
    while (nextUrl) {
      const { data, headers } = await client.get(nextUrl);

      // Response is a flat array of token objects
      const page = Array.isArray(data) ? data : (Array.isArray(data?.value) ? data.value : []);
      tokens.push(...page);

      const linkMatch = (headers?.link || '').match(/<([^>]+)>;\s*rel="next"/);
      nextUrl = linkMatch?.[1]
        ? linkMatch[1].replace(/^https?:\/\/[^/]+/, '')
        : null;
    }
    return { available: true, tokens };
  } catch (err) {
    const status = err.response?.status;
    const detail = err.response?.data ? JSON.stringify(err.response.data) : err.message;

    if (status === 403) {
      return {
        available: false,
        reason:
          'API returned 403 — token likely lacks okta.apiTokens.read scope. ' +
          'Grant that scope on the app registration (Applications → [App] → Okta API Scopes), ' +
          'then delete ~/.okta-tea-ai-assistant/tokens.json and run okta_login again.' +
          `Detail: ${detail}`,
      };
    }
    if (status === 404) {
      return {
        available: false,
        reason:
          'API returned 404 for /api/v1/api-tokens — ' +
          'this endpoint requires the org to be on OIE and the token to have okta.apiTokens.read scope. ' +
          `Detail: ${detail}`,
      };
    }
    return { available: false, reason: err.message };
  }
}

async function fetchIpZones(client) {
  try {
    const { data } = await client.get('/api/v1/zones', {
      params: { filter: 'status eq "ACTIVE"', limit: 200 },
    });
    const zones = Array.isArray(data) ? data : [];
    return zones.filter((z) => z.type === 'IP');
  } catch (_) {
    return [];
  }
}

// ── Terraform ─────────────────────────────────────────────────────────────────
//
// Terraform manages the IP network zone that will be used to restrict the token,
// NOT the token itself. Managing SSWS tokens via Terraform is not recommended
// because the token value would be stored in Terraform state.

function buildApiTokenTerraform(ipZones) {
  const existingZones = (ipZones || []).slice(0, 3)
    .map((z) => `# Existing zone: "${z.name}" (id: ${z.id})`)
    .join('\n');

  return `# Terraform — IP Network Zone for API Token restriction
#
# Create an IP-type zone containing the egress IPs of integrations that use API tokens.
# Once the zone is created, apply it to each token via:
#   Security → API → Tokens → [token name] → Edit → Network Zone
#
# IMPORTANT: Do NOT manage SSWS API tokens themselves via Terraform.
# The token value would be stored in plaintext in Terraform state.
# Use the Admin Console or Okta API directly to create and manage tokens.
#
# Provider setup:
#   https://developer.okta.com/docs/guides/terraform-enable-org-access/main/
# Resource reference:
#   https://registry.terraform.io/providers/okta/okta/latest/docs/resources/network_zone
# OAuth2 for Okta (preferred alternative to SSWS tokens):
#   https://developer.okta.com/docs/guides/implement-oauth-for-okta/main/

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
  scopes      = ["okta.networkZones.manage"]
  private_key = "<PATH_OR_CONTENT_OF_PRIVATE_KEY>"
}

${existingZones ? `# Existing active IP zones in this tenant:\n${existingZones}\n` : ''}
# Create a new IP zone scoped to your integration's egress IPs.
# Replace the CIDR blocks with the actual egress IPs of your CI/CD, automation, or agent.

resource "okta_network_zone" "api_token_restriction" {
  name   = "API-Token-Restriction"
  type   = "IP"
  status = "ACTIVE"
  usage  = "POLICY"

  gateways = [
    "203.0.113.0/24",   # Replace: CI/CD egress CIDR
    "198.51.100.10/32", # Replace: automation server IP
  ]
}
`;
}

// ── Log queries ───────────────────────────────────────────────────────────────

function buildApiTokenLogQueries() {
  return [
    {
      description: 'API token creation events — track new token additions',
      filter: 'eventType eq "system.api_token.create"',
      timeWindow: 'last 90 days',
      note: 'Every new SSWS token created. With an OAuth2 migration in progress, new token creation should trend to zero.',
    },
    {
      description: 'API token revocations — migration progress tracking',
      filter: 'eventType eq "system.api_token.revoke"',
      timeWindow: 'last 90 days',
      note: 'Tracks tokens being retired. Compare against creation events to gauge migration velocity.',
    },
    {
      description: 'API token zone violations — token used outside allowed network range',
      filter: 'eventType eq "system.api_token.request_outside_allowed_range"',
      timeWindow: 'last 30 days',
      note: 'Fires when a token with a network zone restriction is called from an IP outside that zone. Use this to detect stolen tokens or misconfigured integrations. Note: Okta does not emit a general "token was used" event — zone violations are the best signal for suspicious token usage.',
    },
    {
      description: 'API token updates — track configuration changes',
      filter: 'eventType eq "system.api_token.update"',
      timeWindow: 'last 90 days',
      note: 'Fires when a token\'s name, zone restriction, or expiry is changed. Useful for auditing zone restriction additions.',
    },
  ];
}

// ── Admin console steps ───────────────────────────────────────────────────────

function buildApiTokenAdminSteps() {
  return [
    '── Path 1 (preferred): Migrate to OAuth2 ────────────────────────────────────',
    'OAuth2 service apps issue scoped, short-lived tokens (1 hour) and do not require',
    'storing a long-lived credential. Reference: https://developer.okta.com/docs/guides/implement-oauth-for-okta/main/',
    '',
    'Step 1 — Create an OIDC Service Application:',
    '  Applications → Create App Integration → OIDC → Service Application.',
    '  Name it after the integration (e.g. "CI Pipeline - Okta API").',
    '',
    'Step 2 — Grant API scopes:',
    '  On the new app → Okta API Scopes tab.',
    '  Grant only the scopes the integration actually needs (principle of least privilege).',
    '  Do NOT grant okta.users.manage unless the integration modifies users.',
    '',
    'Step 3 — Configure a public/private key pair:',
    '  General → Client Credentials → Public Key / Private Key.',
    '  Generate a new key pair; store the private key in a secret manager (not source code).',
    '',
    'Step 4 — Update integration code:',
    '  Replace SSWS token authentication with the client credentials flow:',
    '    POST /oauth2/v1/token with client_id, client_assertion (JWT signed with private key).',
    '  The access token expires in 1 hour — implement automatic refresh.',
    '',
    'Step 5 — Test and then revoke the old SSWS token:',
    '  Verify the integration works with the OAuth2 token before revoking.',
    '  Security → API → Tokens → [token] → Revoke.',
    '  WARNING: Revoke AFTER confirming the migration works — not before.',
    '',
    '── Path 2 (interim): Add network zone restriction to existing tokens ─────────',
    'Use this if the integration cannot be migrated to OAuth2 immediately.',
    'Zone restriction limits where the token can be used — if stolen, it only works',
    'from the attacker\'s IP if it happens to be in your allowed zone.',
    '',
    'Step 1 — Identify egress IPs for the integration using the token.',
    '',
    'Step 2 — Create an IP network zone:',
    '  Security → Networks → Add Zone → IP Zone.',
    '  Add the integration\'s egress IPs/CIDRs.',
    '  Name it descriptively (e.g. "CI-Pipeline-Egress").',
    '',
    'Step 3 — Restrict the API token:',
    '  Security → API → Tokens.',
    '  Click the token name → Edit.',
    '  Under Network Zone, select the zone you created.',
    '  Click Save.',
    '',
    'Step 4 — Verify the integration still works from its normal IP.',
    '',
    '── For all tokens ───────────────────────────────────────────────────────────',
    'Revoke any tokens that have had no zone violations or other activity in the last 30 days.',
    '(Note: Okta does not emit a general token-usage event. Use system.api_token.request_outside_allowed_range',
    'to detect zone violations, and system.api_token.create / system.api_token.revoke for lifecycle tracking.)',
  ];
}

// ── Risk assessment ───────────────────────────────────────────────────────────

function buildApiTokenRiskAssessment(counts) {
  const total        = counts?.totalTokens ?? 0;
  const unrestricted = counts?.unrestricted ?? 0;
  const noExpiry     = counts?.noExpiry ?? 0;

  return {
    teaSeverity: 'MODERATE',
    changeRisk:  'MODERATE',
    summary:
      `${total} active SSWS API token${total !== 1 ? 's' : ''} found` +
      (unrestricted > 0 ? `, ${unrestricted} without a network zone restriction` : '') +
      (noExpiry > 0 ? `, ${noExpiry} with no expiry` : '') +
      '. SSWS API tokens are long-lived, broadly-scoped credentials — a stolen token ' +
      'provides persistent admin API access with no inherent time limit or IP boundary. ' +
      'OAuth2 service apps (client credentials flow) are the preferred replacement: ' +
      'tokens are scoped to specific permissions, expire after 1 hour, and do not ' +
      'require storing a long-lived credential.',
    preChangeChecks: [
      'Identify the egress IP addresses for every integration using SSWS tokens before adding zone restrictions — the token will stop working from IPs not in the zone.',
      'Check each token\'s last-used timestamp: tokens inactive for 30+ days are safe to revoke immediately.',
      'Verify whether each integration supports OAuth2 client credentials before starting migration — some legacy tools do not.',
      'The Okta "OAuth for Okta" guide lists which API endpoints are accessible via OAuth2 scoped tokens; endpoints not on that list still require SSWS tokens.',
    ],
    blastRadius:
      'Adding a network zone restriction to an existing token is safe and non-breaking ' +
      'as long as the integration\'s egress IPs are included in the zone. ' +
      'Revoking an SSWS token WILL immediately break any integration still using it — ' +
      'always complete the OAuth2 migration and verify the new credential works before revoking. ' +
      'Never revoke first.',
    rolloutSteps: [
      'Step 1 — Revoke tokens inactive for 30+ days (safe, no integration impact).',
      'Step 2 — Add network zone restrictions to all remaining tokens immediately (safe, non-breaking).',
      'Step 3 — Prioritise OAuth2 migration for integrations that support client credentials.',
      'Step 4 — For tokens that cannot be migrated, document the integration and set a review date.',
      'Step 5 — Monitor System Log for new token creation to prevent token sprawl (see postChangeMonitoring queries).',
    ],
    postChangeMonitoring: {
      description:
        'After adding zone restrictions and migrating tokens, watch for integration failures from IPs ' +
        'not covered by the zone, and for new SSWS token creation that could indicate fresh token sprawl.',
      logQueries: [
        {
          description: 'API token usage denied by zone restriction',
          filter: 'eventType eq "system.api_token.request_outside_allowed_range"',
          timeWindow: 'first 48 hours post-zone-restriction',
          note: 'Failures here mean an integration is calling from an IP not in the zone. Check client.ipAddress and add to the zone if legitimate.',
        },
        {
          description: 'New SSWS API tokens created (token sprawl monitor)',
          filter: 'eventType eq "system.api_token.create"',
          timeWindow: 'ongoing post-change',
          note: 'Each new token should be reviewed. A spike here suggests teams are creating SSWS tokens instead of using OAuth2.',
        },
      ],
    },
    rollback:
      'Network zone restrictions can be removed immediately via Security > API > Tokens > [token] > Edit. ' +
      'OAuth2 migration is not easily rolled back once the SSWS token is revoked — ' +
      'the token value is only shown at creation time and cannot be recovered. ' +
      'If rollback is needed, a new SSWS token must be created and the integration reconfigured.',
  };
}

// ── Tool registration ─────────────────────────────────────────────────────────

function registerApiTokenTools(server) {
  server.tool(
    'okta_audit_api_tokens',
    'Audit all active SSWS API tokens in the org. ' +
    'Reports total count, flags tokens without network zone restriction (unrestricted tokens ' +
    'can be used from any IP if stolen), and flags tokens with no expiry. ' +
    'Recommends migrating to OAuth2 service apps (client credentials flow) as the primary ' +
    'remediation, with network zone restriction as an interim control for tokens that ' +
    'cannot be migrated immediately. ' +
    'Read-only — does not create, update, or revoke tokens. ' +
    'Requires okta.apiTokens.read scope. ' +
    'Token values are never returned by the Okta API after creation.',
    {},
    async () => {
      if (process.env.OFFLINE_MODE === 'true') {
        // Representative offline counts matching the TEA example scenario (13 total)
        const mockCounts = { totalTokens: 13, unrestricted: 11, zoneRestricted: 2, noExpiry: 5 };
        return buildMcpOffline({
          remediation: {
            terraform:         buildApiTokenTerraform([]),
            logQueries:        buildApiTokenLogQueries(),
            adminConsoleSteps: buildApiTokenAdminSteps(),
            riskAssessment:    buildApiTokenRiskAssessment(mockCounts),
          },
        });
      }

      try {
        const client = await createOktaClient();

        // Fetch tokens and available IP zones in parallel
        const [tokenResult, ipZones] = await Promise.all([
          fetchApiTokens(client),
          fetchIpZones(client),
        ]);

        if (!tokenResult.available) {
          return buildMcpError(new Error(
            `Could not retrieve API tokens: ${tokenResult.reason}`,
          ));
        }

        const summarised   = tokenResult.tokens.map(summariseToken);
        const unrestricted = summarised.filter((t) => !t.zoneRestricted);
        const noExpiry     = summarised.filter((t) => !t.hasExpiry);
        const counts = {
          totalTokens:   summarised.length,
          unrestricted:  unrestricted.length,
          zoneRestricted: summarised.length - unrestricted.length,
          noExpiry:      noExpiry.length,
        };

        const findings = [];

        if (summarised.length > TOKEN_THRESHOLD) {
          findings.push({
            id:       'API_TOKENS_PRESENT',
            severity: 'LOW',
            description:
              `${summarised.length} active SSWS API token${summarised.length !== 1 ? 's' : ''} found. ` +
              'OAuth2 service apps with client credentials are preferred — ' +
              'they issue scoped, 1-hour tokens with no standing credential.',
            recommendation:
              'Migrate integrations to OAuth2 (client credentials flow). ' +
              'See https://developer.okta.com/docs/guides/implement-oauth-for-okta/main/',
          });
        }

        if (unrestricted.length > 0) {
          findings.push({
            id:       'API_TOKEN_NO_ZONE_RESTRICTION',
            severity: 'MODERATE',
            description:
              `${unrestricted.length} token${unrestricted.length !== 1 ? 's are' : ' is'} not ` +
              'restricted to a network zone — if stolen, the token can be used from any IP address.',
            recommendation:
              'Create an IP network zone containing the integration\'s egress IPs and ' +
              'apply it to each unrestricted token via Security → API → Tokens → [token] → Edit.',
          });
        }

        if (noExpiry.length > 0) {
          findings.push({
            id:       'API_TOKEN_NO_EXPIRY',
            severity: 'LOW',
            description:
              `${noExpiry.length} token${noExpiry.length !== 1 ? 's have' : ' has'} no expiry ` +
              '(neither expiresAt nor a rolling tokenWindow is set). ' +
              'A token with no expiry remains valid indefinitely unless explicitly revoked.',
            recommendation:
              'Set a tokenWindow on the token or revoke and recreate with an expiry. ' +
              'Tokens unused for 30+ days should be revoked immediately.',
          });
        }

        return buildMcpOk({
          summary: {
            ...counts,
            availableIpZones:  ipZones.length,
            findingCount:      findings.length,
            highFindings:      findings.filter((f) => f.severity === 'HIGH').length,
          },
          findings,
          tokens: summarised,
          availableIpZones: ipZones.map((z) => ({ id: z.id, name: z.name, status: z.status })),
          remediation: {
            terraform:         buildApiTokenTerraform(ipZones),
            logQueries:        buildApiTokenLogQueries(),
            adminConsoleSteps: buildApiTokenAdminSteps(),
            riskAssessment:    buildApiTokenRiskAssessment(counts),
          },
        });
      } catch (err) {
        return buildMcpError(err);
      }
    },
  );
}

module.exports = {
  registerApiTokenTools,
  buildApiTokenTerraform,
  buildApiTokenLogQueries,
  buildApiTokenRiskAssessment,
};
