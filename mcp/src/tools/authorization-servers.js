'use strict';

const { buildMcpOk, buildMcpError, buildMcpOffline } = require('./resolver-utils');
const { createOktaClient } = require('../auth/okta-client');

// The default authorization server ID is always "default"
const DEFAULT_SERVER_ID = 'default';
const DEFAULT_AUDIENCE = 'api://default';

// ── Fetchers ───────────────────────────────────────────────────────────────────

async function fetchAuthorizationServers(client) {
  try {
    const { data } = await client.get('/api/v1/authorizationServers');
    return { available: true, servers: Array.isArray(data) ? data : [] };
  } catch (err) {
    const status = err.response?.status;
    if (status === 404 || status === 403) {
      return {
        available: false,
        reason: `API returned ${status} — Authorization Servers endpoint may require okta.authorizationServers.read scope or API Access Management.`,
        servers: [],
      };
    }
    return { available: false, reason: err.message, servers: [] };
  }
}

async function fetchServerPolicies(client, serverId) {
  try {
    const { data } = await client.get(`/api/v1/authorizationServers/${serverId}/policies`);
    return Array.isArray(data) ? data : [];
  } catch (err) {
    return [];
  }
}

// ── Audit ──────────────────────────────────────────────────────────────────────

async function auditAuthorizationServers(client, servers) {
  const findings = [];
  const serverAudits = [];

  for (const server of servers) {
    const serverFindings = [];
    const isDefault = server.id === DEFAULT_SERVER_ID || server.name === 'default';

    // Custom servers with the default scaffold audience are likely unconfigured
    if (!isDefault && server.audiences && server.audiences.includes(DEFAULT_AUDIENCE)) {
      serverFindings.push({
        id: 'AUTH_SERVER_DEFAULT_AUDIENCE',
        severity: 'LOW',
        description:
          `Authorization server "${server.name}" still uses the default audience "api://default". ` +
          'This suggests the server may not have been customised from its initial scaffold.',
        recommendation:
          `Update the audience to a meaningful URI for this server (e.g. "api://${server.name}") ` +
          'under Security > API > Authorization Servers.',
      });
    }

    // Inactive custom servers should be reviewed or removed
    if (!isDefault && server.status === 'INACTIVE') {
      serverFindings.push({
        id: 'AUTH_SERVER_INACTIVE',
        severity: 'LOW',
        description:
          `Authorization server "${server.name}" is INACTIVE. ` +
          'Unused authorization servers increase the attack surface and should be removed.',
        recommendation:
          `Delete or reactivate "${server.name}" under Security > API > Authorization Servers.`,
      });
    }

    // Check if the server has at least one custom access policy (beyond the default)
    const policies = await fetchServerPolicies(client, server.id);
    const activePolicies = policies.filter((p) => p.status === 'ACTIVE');

    if (activePolicies.length === 0 && server.status === 'ACTIVE') {
      serverFindings.push({
        id: 'AUTH_SERVER_NO_ACCESS_POLICY',
        severity: 'MODERATE',
        description:
          `Authorization server "${server.name}" is ACTIVE but has no active access policies. ` +
          'Without an access policy, all token requests may be permitted by a catch-all default.',
        recommendation:
          `Create a least-privilege access policy for "${server.name}" that restricts which ` +
          'OAuth clients and scopes can request tokens from this server.',
      });
    }

    serverAudits.push({
      id: server.id,
      name: server.name,
      description: server.description,
      audiences: server.audiences,
      status: server.status,
      isDefault,
      policyCount: activePolicies.length,
      findings: serverFindings,
    });

    findings.push(...serverFindings);
  }

  return { findings, serverAudits };
}

// ── Terraform ──────────────────────────────────────────────────────────────────

function buildAuthServerTerraform() {
  return `# Terraform — Okta Authorization Servers
#
# Provider setup:
#   https://developer.okta.com/docs/guides/terraform-enable-org-access/main/
# Resource reference:
#   https://registry.terraform.io/providers/okta/okta/latest/docs/resources/auth_server
#   https://registry.terraform.io/providers/okta/okta/latest/docs/resources/auth_server_policy

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
  scopes      = ["okta.authorizationServers.manage"]
  private_key = "<PATH_OR_CONTENT_OF_PRIVATE_KEY>"
}

# Update a custom authorization server audience
resource "okta_auth_server" "example" {
  name        = "<YOUR_SERVER_NAME>"
  description = "<YOUR_SERVER_DESCRIPTION>"
  audiences   = ["api://<YOUR_SERVER_NAME>"]   # Replace api://default with a meaningful URI
  issuer_mode = "ORG_URL"
  status      = "ACTIVE"
}

# Add a least-privilege access policy to the authorization server
resource "okta_auth_server_policy" "default_policy" {
  auth_server_id   = okta_auth_server.example.id
  name             = "Default Access Policy"
  description      = "Restrict token access to approved OAuth clients"
  priority         = 1
  status           = "ACTIVE"
  client_whitelist = ["<YOUR_CLIENT_ID>"]  # List specific client IDs
}

resource "okta_auth_server_policy_rule" "default_rule" {
  auth_server_id   = okta_auth_server.example.id
  policy_id        = okta_auth_server_policy.default_policy.id
  name             = "Allow approved clients"
  priority         = 1
  status           = "ACTIVE"
  grant_type_whitelist = ["authorization_code", "refresh_token"]
  scope_whitelist  = ["<REQUIRED_SCOPE>"]  # List only required scopes
  access_token_lifetime_minutes = 60
}
`;
}

// ── Log queries ────────────────────────────────────────────────────────────────

function buildAuthServerLogQueries() {
  return [
    {
      description: 'Authorization server configuration changes',
      filter: 'eventType sw "security.api."',
      timeWindow: 'last 90 days',
      note: 'Audit trail of changes to authorization server configuration, policies, and scopes.',
    },
    {
      description: 'Token grants from authorization servers',
      filter: 'eventType eq "app.oauth2.as.token.grant"',
      timeWindow: 'last 30 days',
      note: 'All token grants across authorization servers — review for unexpected client IDs or scopes.',
    },
    {
      description: 'Token grant failures',
      filter: 'eventType eq "app.oauth2.as.token.grant" AND outcome.result eq "FAILURE"',
      timeWindow: 'last 7 days',
      note: 'Failed token requests — may indicate misconfigured policies or probing by unauthorized clients.',
    },
  ];
}

// ── Admin console steps ────────────────────────────────────────────────────────

function buildAuthServerAdminSteps() {
  return [
    'Sign in to the Okta Admin Console.',
    'Go to Security > API > Authorization Servers.',
    'Review each authorization server:',
    '  • Ensure the audience is a meaningful URI (not "api://default" for custom servers).',
    '  • Remove or deactivate any servers that are no longer in use.',
    '  • Verify each active server has at least one access policy.',
    'For the default authorization server:',
    '  a. Click "default" > Access Policies.',
    '  b. Ensure the catch-all rule does not grant unrestricted scopes.',
    '  c. Consider restricting allowed clients to known OAuth applications.',
    'For each custom server:',
    '  a. Update the audience to a unique, meaningful URI.',
    '  b. Add an access policy that restricts which clients and scopes are permitted.',
    '  c. Click Save after each change.',
  ];
}

// ── Risk assessment ────────────────────────────────────────────────────────────

function buildAuthServerRiskAssessment() {
  return {
    teaSeverity: 'MODERATE',
    changeRisk:  'LOW',
    summary:
      'Authorization servers with default audiences and permissive access policies can ' +
      'issue tokens with excessive scopes to unintended clients. ' +
      'Unused authorization servers increase the attack surface without providing value.',
    preChangeChecks: [
      'Before changing a server audience, confirm with the application teams which audience value they are using — tokens scoped to the old audience will be immediately invalid.',
      'Before deactivating a server, search System Log for recent token issuance events to verify the server is truly unused.',
      'The "default" server audience "api://default" is expected and should not be changed.',
    ],
    blastRadius:
      'Changing an authorization server audience invalidates all existing tokens scoped to the old audience — ' +
      'any client holding an in-flight token will receive a 401 on the next API call. ' +
      'Deactivating a server has the same effect. ' +
      'Coordinate with application teams before making audience changes in production.',
    rolloutSteps: [
      'Step 1 — Inventory all authorization servers and identify unused ones.',
      'Step 2 — Verify unused servers have had no recent activity in System Log before deactivating.',
      'Step 3 — Update custom server audiences to meaningful URIs — coordinate with app owners first.',
      'Step 4 — Review and tighten access policies on each active server.',
    ],
    postChangeMonitoring: {
      description:
        'After changing authorization server configuration, watch for 401 errors in application logs ' +
        'and for token issuance failures in Okta System Log.',
      logQueries: [
        {
          description: 'Token issuance failures post-change',
          filter: 'eventType eq "app.oauth2.as.token.grant" AND outcome.result eq "FAILURE"',
          timeWindow: 'first 24 hours post-change',
          note: 'Failures here after changing an audience or policy indicate clients using the old configuration.',
        },
        {
          description: 'Authorization server configuration changes audit',
          filter: 'eventType sw "app.oauth2.as."',
          timeWindow: 'last 7 days',
          note: 'Audit trail of authorization server create, update, and delete events.',
        },
      ],
    },
    rollback:
      'Audience and policy changes are reversible. Deleted servers can be recreated but ' +
      'previously issued tokens will not be valid against a recreated server.',
  };
}

// ── Tool registration ─────────────────────────────────────────────────────────

function registerAuthorizationServerTools(server) {
  server.tool(
    'okta_list_authorization_servers',
    'Audit Okta Authorization Servers — checks for servers using default scaffold audiences, ' +
    'inactive servers that should be removed, and active servers with no access policies. ' +
    'Overly permissive authorization servers can issue tokens with excessive scopes to ' +
    'unintended clients. Returns per-server audit results and remediation guidance.',
    {},
    async () => {
      if (process.env.OFFLINE_MODE === 'true') {
        return buildMcpOffline({
          remediation: {
            terraform:         buildAuthServerTerraform(),
            logQueries:        buildAuthServerLogQueries(),
            adminConsoleSteps: buildAuthServerAdminSteps(),
            riskAssessment:    buildAuthServerRiskAssessment(),
          },
        });
      }
      try {
        const client = await createOktaClient();
        const result = await fetchAuthorizationServers(client);

        if (!result.available) {
          return buildMcpOk({
            available: false,
            reason: result.reason,
            findings: [{
              id: 'AUTH_SERVER_API_UNAVAILABLE',
              severity: 'INFO',
              description: `Authorization Servers API unavailable: ${result.reason}`,
              recommendation: 'Verify manually under Security > API > Authorization Servers.',
            }],
          });
        }

        const { findings, serverAudits } = await auditAuthorizationServers(client, result.servers);

        return buildMcpOk({
          summary: {
            totalServers: result.servers.length,
            findingCount: findings.length,
            serversWithFindings: serverAudits.filter((s) => s.findings.length > 0).length,
          },
          servers: serverAudits,
          findings,
          remediation: {
            terraform: buildAuthServerTerraform(),
            logQueries: buildAuthServerLogQueries(),
            adminConsoleSteps: buildAuthServerAdminSteps(),
            riskAssessment: buildAuthServerRiskAssessment(),
          },
        });
      } catch (err) {
        return buildMcpError(err);
      }
    },
  );
}

module.exports = { registerAuthorizationServerTools };
