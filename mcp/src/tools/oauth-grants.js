'use strict';

const { z } = require('zod');
const { buildMcpOk, buildMcpError, buildMcpOffline, buildMcpReadOnly } = require('./resolver-utils');
const { createOktaClient } = require('../auth/okta-client');

// HIGH-severity grants: deprecated per OAuth 2.0 Security BCP (RFC 9700).
// These expose credentials or tokens in ways Authorization Code + PKCE avoids.
const HIGH_SEVERITY_GRANTS = new Set([
  'password',
  'implicit',
]);

// LOW-severity advisory grants: not inherently insecure, but intended only for
// constrained devices (CLIs, TVs) and should be disabled if not actively used.
const LOW_SEVERITY_GRANTS = new Set([
  'urn:ietf:params:oauth:grant-type:device_code',
]);

// Combined set for backwards compatibility in filter operations
const INSECURE_GRANTS = new Set([...HIGH_SEVERITY_GRANTS, ...LOW_SEVERITY_GRANTS]);

// Apps of these types are Okta-internal and should not be modified.
const SKIP_APP_TYPES = new Set([
  'OKTA', 'OKTA_ORG2ORG', 'OKTA_ENDUSER',
]);

// ── Fetchers ───────────────────────────────────────────────────────────────────

async function fetchAllApps(client) {
  const apps = [];
  let url = '/api/v1/apps?limit=200&filter=status%20eq%20%22ACTIVE%22';

  // Paginate through all results
  while (url) {
    const response = await client.get(url);
    apps.push(...response.data);

    // Follow Link: <next> header if present
    const linkHeader = response.headers?.link || '';
    const nextMatch = linkHeader.match(/<([^>]+)>;\s*rel="next"/);
    if (nextMatch) {
      url = nextMatch[1].replace(/^https?:\/\/[^/]+/, '');
    } else {
      url = null;
    }
  }

  return apps;
}

// ── Audit ──────────────────────────────────────────────────────────────────────

function auditApp(app) {
  const grantTypes = app.settings?.oauthClient?.grant_types || [];
  return {
    highGrants: grantTypes.filter((g) => HIGH_SEVERITY_GRANTS.has(g)),
    lowGrants:  grantTypes.filter((g) => LOW_SEVERITY_GRANTS.has(g)),
  };
}

function buildAudit(apps) {
  const flaggedHigh = [];
  const flaggedLow  = [];
  let skipped = 0;

  for (const app of apps) {
    if (SKIP_APP_TYPES.has(app.name?.toUpperCase()) || SKIP_APP_TYPES.has(app.signOnMode)) {
      skipped++;
      continue;
    }

    const { highGrants, lowGrants } = auditApp(app);
    const appMeta = {
      appId:     app.id,
      appName:   app.label || app.name,
      appType:   app.signOnMode || app.name,
      allGrants: app.settings?.oauthClient?.grant_types || [],
      profileUrl: app.links?.appLinks?.[0]?.href || null,
    };

    if (highGrants.length > 0) {
      flaggedHigh.push({ ...appMeta, insecureGrants: highGrants, severity: 'HIGH' });
    }
    if (lowGrants.length > 0) {
      flaggedLow.push({ ...appMeta, insecureGrants: lowGrants, severity: 'LOW' });
    }
  }

  // Legacy: flagged = union of both for Terraform/admin step builders
  const flagged = [
    ...flaggedHigh,
    ...flaggedLow.filter((a) => !flaggedHigh.some((b) => b.appId === a.appId)),
  ];

  return { flagged, flaggedHigh, flaggedLow, skipped, totalScanned: apps.length };
}

// ── Terraform builder ──────────────────────────────────────────────────────────

function buildTerraform(flaggedApps) {
  if (flaggedApps.length === 0) {
    return `# No apps with Password or Implicit grant types were found — no Terraform changes needed.`;
  }

  const blocks = flaggedApps.map((a) => {
    const safeGrants = a.allGrants
      .filter((g) => !INSECURE_GRANTS.has(g))
      .map((g) => `"${g}"`)
      .join(', ');

    return `
# App: ${a.appName} (ID: ${a.appId})
# Removes: ${a.insecureGrants.join(', ')}
resource "okta_app_oauth" "${a.appId.replace(/-/g, '_')}" {
  app_id = "${a.appId}"

  # Retain all secure grant types; Password, Implicit, and Device Code are omitted.
  grant_types = [${safeGrants || '"authorization_code"'}]

  # Verify remaining settings with: terraform plan
}`;
  });

  return `# Terraform — Remove insecure OAuth grant types (Password, Implicit, Device Code)
#
# Provider setup:
#   https://developer.okta.com/docs/guides/terraform-enable-org-access/main/
#
# WARNING: Review each app before applying. Removing grant types from production
# apps without updating the app's own OAuth client code will break those flows.
# Coordinate with application owners before applying this change.
#
# Reference: RFC 9700 OAuth 2.0 Security BCP, NIST SP 800-63C

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
  scopes      = ["okta.apps.manage"]
  private_key = "<PATH_OR_CONTENT_OF_PRIVATE_KEY>"
}
${blocks.join('\n')}
`;
}

// ── Log queries ────────────────────────────────────────────────────────────────

function buildLogQueries() {
  return [
    {
      description: 'Token grants using Password grant type',
      filter: 'eventType eq "app.oauth2.as.token.grant" AND debugContext.debugData.grantType eq "password"',
      timeWindow: 'last 30 days',
      note: 'After removing the Password grant from an app, requests using it will fail. Run this before removal to assess blast radius.',
    },
    {
      description: 'Token grants using Implicit grant type',
      filter: 'eventType eq "app.oauth2.as.token.grant" AND debugContext.debugData.grantType eq "implicit"',
      timeWindow: 'last 30 days',
      note: 'Identifies apps still actively using the Implicit flow — coordinate with owners before removing.',
    },
    {
      description: 'Token grants using Device Code grant type',
      filter: 'eventType eq "app.oauth2.as.token.grant" AND debugContext.debugData.grantType eq "urn:ietf:params:oauth:grant-type:device_code"',
      timeWindow: 'last 30 days',
      note: 'Identifies apps actively using the Device Authorization Grant — used by CLI tools and smart devices. Confirm whether it is intentional before removing.',
    },
    {
      description: 'App OAuth configuration changes',
      filter: 'eventType eq "application.lifecycle.update"',
      timeWindow: 'last 90 days',
      note: 'Audit trail of app setting updates — verifies grant type changes were applied.',
    },
  ];
}

// ── Admin console steps ────────────────────────────────────────────────────────

function buildAdminConsoleSteps(flaggedApps) {
  if (flaggedApps.length === 0) {
    return ['No apps with insecure grant types were found — no action required.'];
  }

  const steps = [
    'Sign in to the Okta Admin Console.',
    'Go to Applications > Applications.',
    'For each app listed below, remove Password and/or Implicit grant types:',
    ...flaggedApps.map((a, i) =>
      `  ${i + 1}. "${a.appName}" (App ID: ${a.appId}) — currently has: ${a.insecureGrants.join(', ')}`
    ),
    '',
    'For each app:',
    '  a. Click the app name to open its settings.',
    '  b. Go to the "General" tab.',
    '  c. In the "General Settings" section, click Edit.',
    '  d. Under "Grant type", uncheck "Resource Owner Password", "Implicit (Hybrid)", and/or "Device Authorization".',
    '  e. Click Save.',
    '',
    'IMPORTANT: Before removing a grant type from a production app:',
    '  • Confirm with the app owner that the grant type is no longer in use.',
    '  • Check System Log for active usage (use the log queries provided).',
    '  • Update the app\'s OAuth client code to use Authorization Code + PKCE instead.',
  ];

  return steps;
}

// ── Risk assessment ────────────────────────────────────────────────────────────

function buildRiskAssessment(flaggedHigh, flaggedLow) {
  const hasHighSeverity = (flaggedHigh || []).length > 0;
  const hasLowSeverity  = (flaggedLow  || []).length > 0;

  return {
    teaSeverity: hasHighSeverity ? 'HIGH' : hasLowSeverity ? 'LOW' : 'INFO',
    changeRisk:  'MODERATE',
    summary:
      'The Resource Owner Password Credentials (ROPC) grant and Implicit grant are HIGH severity — ' +
      'both are deprecated per OAuth 2.0 Security BCP (RFC 9700) and expose credentials or tokens ' +
      'in ways that Authorization Code + PKCE avoids. ' +
      'The Device Authorization Grant is LOW severity — it is intended only for constrained devices ' +
      '(CLIs, smart TVs) and should be disabled if not actively used, but it is not inherently insecure.',
    preChangeChecks: [
      'Run the log queries to identify apps actively using Password/Implicit/Device Code grants before removing anything.',
      'Contact the app owner for each flagged application — confirm the grant type is in active use before removal.',
      'Check whether any CLI tools, test suites, or service accounts depend on the Password grant — these break immediately when the grant is removed.',
      'Device Code grant removal only affects constrained-device flows (TV apps, CLI tools without a browser).',
    ],
    blastRadius:
      'Any application currently using a removed grant type will break immediately — ' +
      'OAuth flows using the removed grant will return an "unsupported_grant_type" error. ' +
      'Password grant removal is highest risk for legacy or internally-built integrations. ' +
      'Implicit grant removal affects SPAs that have not yet migrated to Authorization Code + PKCE. ' +
      'Device Code grant removal is lowest risk and only affects constrained-device flows.',
    rolloutSteps: [
      'Step 1 — Run log queries to identify apps with active grant usage over the last 30 days.',
      'Step 2 — Prioritise removing unused grants (no recent log events) — zero blast radius.',
      'Step 3 — For active Password/Implicit apps: coordinate migration to Authorization Code + PKCE.',
      'Step 4 — Remove grant types from apps confirmed as migrated or confirmed as unused.',
      'Step 5 — Remove Device Code grants from apps where there is no constrained-device use case.',
      'Step 6 — Monitor System Log for grant errors after each removal (see postChangeMonitoring queries).',
    ],
    postChangeMonitoring: {
      description:
        'After removing insecure grant types, watch for grant-related errors in Okta System Log. ' +
        'Each error event here is an application that still has code using the removed grant.',
      logQueries: [
        {
          description: 'OAuth grant failures post-removal (Password/Implicit)',
          filter: 'eventType eq "app.oauth2.as.token.grant" AND outcome.result eq "FAILURE"',
          timeWindow: 'first 48 hours post-change',
          note: 'Each failure here is an app still using the removed grant. Check target.displayName to identify the app.',
        },
        {
          description: 'Device Code grant usage post-removal',
          filter: 'eventType eq "app.oauth2.as.token.grant" AND debugContext.debugData.grantType eq "urn:ietf:params:oauth:grant-type:device_code"',
          timeWindow: 'first 48 hours post-change',
          note: 'Should drop to zero after removing Device Code grants. Residual events mean a device is still using this flow.',
        },
      ],
    },
    rollback:
      'Grant types can be re-added at any time from Applications > Applications > [App] > General.',
  };
}

// ── Tool registration ─────────────────────────────────────────────────────────

function registerOAuthGrantTools(server) {
  server.tool(
    'okta_list_apps_insecure_grants',
    'Audit all active Okta applications for insecure OAuth 2.0 grant types: ' +
    'Resource Owner Password Credentials (password), Implicit (implicit), and ' +
    'Device Authorization Grant (device_code). All three are deprecated or restricted ' +
    'per RFC 9700 (OAuth 2.0 Security BCP). ' +
    'Returns a list of flagged apps with their current grant types, plus Terraform and ' +
    'Admin Console remediation steps.',
    {},
    async () => {
      if (process.env.OFFLINE_MODE === 'true') {
        return buildMcpOffline({
          remediation: {
            terraform:         buildTerraform([]),
            logQueries:        buildLogQueries(),
            adminConsoleSteps: buildAdminConsoleSteps([]),
            riskAssessment:    buildRiskAssessment([], []),
          },
        });
      }
      try {
        const client = await createOktaClient();
        const apps = await fetchAllApps(client);
        const { flagged, flaggedHigh, flaggedLow, skipped, totalScanned } = buildAudit(apps);

        return buildMcpOk({
          summary: {
            totalScanned,
            skippedSystemApps: skipped,
            flaggedCount:      flagged.length,
            highFindings:      flaggedHigh.length,
            lowAdvisory:       flaggedLow.length,
          },
          flaggedApps:     flagged,
          flaggedHighApps: flaggedHigh,
          flaggedLowApps:  flaggedLow,
          remediation: {
            terraform:         buildTerraform(flagged),
            logQueries:        buildLogQueries(),
            adminConsoleSteps: buildAdminConsoleSteps(flagged),
            riskAssessment:    buildRiskAssessment(flaggedHigh, flaggedLow),
          },
        });
      } catch (err) {
        return buildMcpError(err);
      }
    },
  );

  server.tool(
    'okta_remove_insecure_grants',
    'Remove Password and/or Implicit OAuth grant types from a specific Okta application. ' +
    'Provide the appId (from okta_list_apps_insecure_grants) and the grants to remove. ' +
    'Write operation — run okta_list_apps_insecure_grants first and confirm with the app owner ' +
    'before calling. Verify System Log for active usage before applying.',
    {
      appId: z.string().describe('Okta application ID (e.g. 0oa1abc...)'),
      grantsToRemove: z
        .array(z.enum(['password', 'implicit', 'urn:ietf:params:oauth:grant-type:device_code']))
        .min(1)
        .describe('Which insecure grant types to remove: "password", "implicit", "urn:ietf:params:oauth:grant-type:device_code", or any combination'),
    },
    async ({ appId, grantsToRemove }) => {
      if (process.env.OFFLINE_MODE === 'true') {
        return buildMcpOffline({ skipped: true, message: 'Write operations are not available in offline mode.' });
      }
      if (process.env.PROD_MODE === 'true') {
        return buildMcpReadOnly();
      }
      try {
        const client = await createOktaClient();

        // Fetch current app settings
        const { data: app } = await client.get(`/api/v1/apps/${appId}`);

        const currentGrants = app.settings?.oauthClient?.grant_types || [];
        const removeSet = new Set(grantsToRemove);
        const newGrants = currentGrants.filter((g) => !removeSet.has(g));

        if (newGrants.length === currentGrants.length) {
          return buildMcpOk({
            message: `No matching insecure grants found on "${app.label}". No changes made.`,
            appId,
            appName: app.label,
            currentGrants,
            grantsToRemove,
          });
        }

        // Build minimal update payload — preserve all other settings
        const payload = {
          ...app,
          settings: {
            ...app.settings,
            oauthClient: {
              ...app.settings?.oauthClient,
              grant_types: newGrants,
            },
          },
        };

        const { data: updated } = await client.put(`/api/v1/apps/${appId}`, payload);

        const appliedRemovals = currentGrants.filter((g) => removeSet.has(g));

        return buildMcpOk({
          message: `Removed [${appliedRemovals.join(', ')}] grant type(s) from "${app.label}".`,
          appId,
          appName: app.label,
          removedGrants: appliedRemovals,
          remainingGrants: updated.settings?.oauthClient?.grant_types || newGrants,
          remediation: {
            logQueries: buildLogQueries(),
            adminConsoleSteps: [
              `Verify: Go to Applications > "${app.label}" > General tab.`,
              `Confirm grant types no longer include: ${appliedRemovals.join(', ')}.`,
              'Check System Log for any errors from apps still attempting to use the removed grants.',
            ],
            riskAssessment: buildRiskAssessment([], []),
          },
        });
      } catch (err) {
        return buildMcpError(err);
      }
    },
  );
}

module.exports = { registerOAuthGrantTools };
