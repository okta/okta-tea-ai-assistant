'use strict';

const { buildMcpOk, buildMcpError, buildMcpOffline, buildMcpReadOnly } = require('./resolver-utils');
const { createOktaClient } = require('../auth/okta-client');

const THREATINSIGHT_PATH = '/api/v1/threats/configuration';
const THREAT_EVENT       = 'security.threat.detected';

// Zone name patterns that suggest corporate / trusted networks
const CORP_ZONE_PATTERNS = /\b(corp|corporate|office|vpn|internal|hq|headquarters|intranet|trusted|employee|staff|branch)\b/i;

// ── Syslog helper ─────────────────────────────────────────────────────────────

async function fetchThreatStats(client) {
  const since = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString();
  try {
    const { data: events } = await client.get('/api/v1/logs', {
      params: { filter: `eventType eq "${THREAT_EVENT}"`, since, limit: 1000 },
    });

    const bySeverity   = {};
    const byThreatType = {};

    for (const event of events) {
      const sev = event.severity || 'UNKNOWN';
      bySeverity[sev] = (bySeverity[sev] || 0) + 1;

      const threatType =
        event.debugContext?.debugData?.threatSuspected ||
        event.outcome?.reason                          ||
        event.displayMessage                           ||
        'Unknown';
      byThreatType[threatType] = (byThreatType[threatType] || 0) + 1;
    }

    return {
      total:          events.length,
      truncated:      events.length === 1000,
      period:         'last_7_days',
      bySeverity,
      topThreatTypes: Object.entries(byThreatType)
        .sort(([, a], [, b]) => b - a)
        .slice(0, 10)
        .map(([type, count]) => ({ type, count })),
    };
  } catch (err) {
    return { total: null, period: 'last_7_days', error: err.message };
  }
}

// ── Network zones helper ──────────────────────────────────────────────────────

async function fetchNetworkZones(client) {
  try {
    const { data: zones } = await client.get('/api/v1/zones');
    return zones.map((z) => ({ id: z.id, name: z.name, type: z.type, status: z.status, usage: z.usage }));
  } catch (_err) {
    return null;
  }
}

// ── Remediation builders ──────────────────────────────────────────────────────

function detectCorpZoneCandidates(zones) {
  if (!zones) return [];
  return zones.filter((z) => z.type === 'IP' && z.status === 'ACTIVE' && CORP_ZONE_PATTERNS.test(z.name));
}

/**
 * Generate ready-to-apply Terraform HCL for okta_threat_insight_settings.
 *
 * Schema verified against:
 *   https://registry.terraform.io/providers/okta/okta/latest/docs/resources/threat_insight_settings
 *   https://registry.terraform.io/providers/okta/okta/latest/docs/resources/network_zone
 *
 * Attribute names confirmed from provider source:
 *   action          — "none" | "audit" | "block"
 *   network_excludes — list of IP-type network zone IDs (NOT "excluded_zones")
 */
function buildTerraform(config, zones) {
  const existingExcludedIds = config.excludedZones || [];
  const corpCandidates      = detectCorpZoneCandidates(zones || []);
  const newCandidateIds     = corpCandidates
    .map((z) => z.id)
    .filter((id) => !existingExcludedIds.includes(id));
  const allExcludedIds = [...existingExcludedIds, ...newCandidateIds];

  const zoneMap = Object.fromEntries((zones || []).map((z) => [z.id, z.name]));

  let networkExcludesHcl;
  if (allExcludedIds.length === 0) {
    networkExcludesHcl = '[]';
  } else {
    const lines = allExcludedIds.map((id, i) => {
      const name  = zoneMap[id] ? ` # ${zoneMap[id]}` : '';
      const comma = i < allExcludedIds.length - 1 ? ',' : '';
      return `    "${id}"${comma}${name}`;
    });
    networkExcludesHcl = `[\n${lines.join('\n')}\n  ]`;
  }

  const candidateNote = newCandidateIds.length > 0
    ? `# Auto-detected corporate/trusted zones appended to network_excludes:\n#   ${corpCandidates.map((z) => z.name).join(', ')}\n`
    : '';

  return `# Terraform — Okta ThreatInsight blocking mode
#
# Provider setup:
#   https://developer.okta.com/docs/guides/terraform-enable-org-access/main/
# Resource reference:
#   https://registry.terraform.io/providers/okta/okta/latest/docs/resources/threat_insight_settings
# Network zone reference:
#   https://registry.terraform.io/providers/okta/okta/latest/docs/resources/network_zone
#
# Known provider note: network_excludes is a List (not Set), so element order is
# preserved. The Okta API may return zones in a different order — use lifecycle
# ignore_changes = [network_excludes] if you see spurious plan diffs.

terraform {
  required_providers {
    okta = {
      source  = "okta/okta"
      version = "~> 4.0"
    }
  }
}

provider "okta" {
  org_name    = "<YOUR_OKTA_ORG>"   # subdomain only, e.g. "dev-123456"
  base_url    = "okta.com"          # or "oktapreview.com" / "okta-emea.com"
  client_id   = "<YOUR_CLIENT_ID>"
  scopes      = ["okta.threatInsights.manage", "okta.networkZones.read"]
  private_key = "<PATH_OR_CONTENT_OF_PRIVATE_KEY>"
}

${candidateNote}resource "okta_threat_insight_settings" "main" {
  # action: "none" | "audit" | "block"
  # "block" prevents sign-ins from IPs Okta has flagged across its tenant network.
  action = "block"

  # network_excludes: IP-type zone IDs whose traffic bypasses ThreatInsight.
  # Add your corporate / office / VPN zones here before enabling blocking.
  # Only IP-type zones are accepted — DYNAMIC zones are not supported here.
  network_excludes = ${networkExcludesHcl}
}
`;
}

function buildAdminConsoleSteps() {
  return [
    'Sign in to the Okta Admin Console (https://<your-domain>-admin.okta.com).',
    'In the left navigation, go to Security > General.',
    'Scroll to the "ThreatInsight" section.',
    'Before changing the action: review "Network zones excluded from ThreatInsight" and add any corporate, office, or VPN IP zones so employee traffic is never blocked.',
    'Under "Action", select "Log and block requests from suspicious IPs" (blocking mode). Options: None — disabled; Log and enforce zone rules — audit only; Log and block requests from suspicious IPs — full blocking.',
    'Click Save.',
    'Verify by opening Reports > System Log, filtering for: eventType eq "security.threat.detected" — blocked events will show outcome.result = "DENY".',
  ];
}

function buildLogQueries() {
  return [
    {
      description: 'All ThreatInsight detections — last 30 days',
      filter: 'eventType eq "security.threat.detected"',
      timeWindow: 'last 30 days',
      note: 'Run before enabling blocking to establish a baseline detection volume.',
    },
    {
      description: 'Blocked sign-ins from ThreatInsight (blocking mode only)',
      filter: 'eventType eq "security.threat.detected" and outcome.result eq "DENY"',
      timeWindow: 'last 7 days',
      note: 'Only populated once blocking mode is active. Monitor for unexpected blocks on legitimate users.',
    },
    {
      description: 'Audited (logged-only) ThreatInsight detections',
      filter: 'eventType eq "security.threat.detected" and outcome.result eq "ALLOW"',
      timeWindow: 'last 7 days',
      note: 'In audit mode, threats are logged but not blocked — these are live risk indicators.',
    },
    {
      description: 'ThreatInsight configuration changes — audit trail',
      filter: 'eventType eq "security.threat.configuration.update"',
      timeWindow: 'last 90 days',
      note: 'Track who changed the ThreatInsight mode and when.',
    },
  ];
}

function buildRiskAssessment(config) {
  const alreadyBlocking = config.action === 'block';
  return {
    teaSeverity: 'HIGH',
    changeRisk:  'LOW',
    summary:
      'Enabling ThreatInsight blocking uses Okta\'s cross-tenant threat intelligence — ' +
      'IPs associated with credential stuffing, password spraying, and automated attacks ' +
      'across the Okta customer network are blocked before reaching your sign-in flow.',
    currentAction:   config.action,
    alreadyBlocking,
    preChangeChecks: [
      'Identify all IP-type network zones that represent corporate, office, and VPN egress IPs.',
      'Confirm those zones are added to ThreatInsight network_excludes before switching to blocking mode.',
      'Review the last 30 days of security.threat.detected events in audit mode to establish a baseline blocked-IP volume.',
      'Check that no scheduled automation uses IPs that are flagged across other Okta tenants.',
    ],
    blastRadius: alreadyBlocking
      ? 'ThreatInsight is already in blocking mode — no change in blast radius from this finding.'
      : 'Legitimate users whose requests come from a flagged IP (shared datacenter egress, VPN exit node ' +
        'flagged by other tenants, flagged ISP range) may be blocked. This is uncommon in practice because ' +
        'Okta\'s threat scoring is calibrated for low false-positive rates. ' +
        'Add your corporate network zone(s) to network_excludes before enabling blocking — ' +
        'traffic from excluded zones bypasses ThreatInsight entirely.',
    rolloutSteps: [
      'Step 1 — Identify your corporate, office, and VPN IP-type network zones in Okta.',
      'Step 2 — Add those zones to the ThreatInsight network_excludes list.',
      'Step 3 — Switch ThreatInsight to blocking mode.',
      'Step 4 — Monitor System Log for 48 hours (see postChangeMonitoring queries below).',
      'Step 5 — If a legitimate user is blocked, add their source zone to network_excludes.',
    ],
    postChangeMonitoring: {
      description:
        'After switching to blocking mode, monitor for 48 hours to confirm legitimate users are not impacted. ' +
        'The key signal is unexpected DENY outcomes on security.threat.detected for users you recognise.',
      logQueries: [
        {
          description: 'Blocked sign-ins from ThreatInsight — post-change monitor',
          filter: 'eventType eq "security.threat.detected" AND outcome.result eq "DENY"',
          timeWindow: 'first 48 hours post-change',
          note: 'Review actor.displayName and client.ipAddress for each DENY. Legitimate user? Add their zone to network_excludes.',
        },
        {
          description: 'Successful sign-ins despite threat detection (audit mode residual)',
          filter: 'eventType eq "security.threat.detected" AND outcome.result eq "ALLOW"',
          timeWindow: 'first 48 hours post-change',
          note: 'Should drop to near-zero after switching to block mode. If still high, verify action was saved.',
        },
      ],
    },
    rollback:
      'You can switch from blocking back to audit mode at any time with immediate effect — no restarts needed.',
  };
}

function buildExclusionZoneAdvice(config, zones) {
  const existingExcludedIds = config.excludedZones || [];
  const candidates          = detectCorpZoneCandidates(zones || []);
  const notYetExcluded      = candidates.filter((z) => !existingExcludedIds.includes(z.id));
  return {
    recommendation:
      'Before enabling blocking mode, add your corporate IP-type network zone(s) to the ThreatInsight ' +
      'exclusions list. Only IP-type zones are supported — DYNAMIC zones cannot be excluded.',
    currentExclusionCount: existingExcludedIds.length,
    detectedCandidatesNotYetExcluded: notYetExcluded.map((z) => ({
      id: z.id, name: z.name, status: z.status,
      action: 'Recommend adding to ThreatInsight network_excludes before enabling blocking.',
    })),
    noCandidatesNote:
      notYetExcluded.length === 0 && existingExcludedIds.length === 0
        ? 'No active IP zones with corporate-style names (corp, office, vpn, internal, hq, etc.) were found. ' +
          'Create an IP-type network zone under Security > Networks, then add it to the ThreatInsight exclusions.'
        : null,
  };
}

// ── Tool registration ─────────────────────────────────────────────────────────

function registerThreatInsightTools(server) {
  server.tool(
    'okta_get_threatinsight_config',
    'Retrieve the current Okta ThreatInsight configuration (action mode: none/audit/block, and excluded network zones) ' +
    'together with a 7-day summary of security.threat.detected syslog events. ' +
    'Also returns structured remediation guidance: Terraform HCL, manual admin console steps, ' +
    'System Log queries, a risk assessment, and exclusion zone recommendations.',
    {},
    async () => {
      if (process.env.OFFLINE_MODE === 'true') {
        const cfg = { action: 'none', excludedZones: [] };
        return buildMcpOffline({
          remediation: {
            terraform:           buildTerraform(cfg, []),
            logQueries:          buildLogQueries(),
            adminConsoleSteps:   buildAdminConsoleSteps(),
            riskAssessment:      buildRiskAssessment(cfg),
            exclusionZoneAdvice: buildExclusionZoneAdvice(cfg, []),
          },
        });
      }
      try {
        const client = await createOktaClient();

        const [{ data: config }, threats7d, networkZones] = await Promise.all([
          client.get(THREATINSIGHT_PATH),
          fetchThreatStats(client),
          fetchNetworkZones(client),
        ]);

        return buildMcpOk({
          config,
          threats7d,
          networkZones,
          remediation: {
            terraform:           buildTerraform(config, networkZones),
            logQueries:          buildLogQueries(),
            adminConsoleSteps:   buildAdminConsoleSteps(),
            riskAssessment:      buildRiskAssessment(config),
            exclusionZoneAdvice: buildExclusionZoneAdvice(config, networkZones),
          },
        });
      } catch (err) {
        return buildMcpError(err);
      }
    },
  );

  server.tool(
    'okta_set_threatinsight_blocking',
    'Set Okta ThreatInsight to blocking mode. Blocks sign-in attempts from IPs Okta identifies as malicious. Write operation — confirm with the admin before calling.',
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
        const { data } = await client.post(THREATINSIGHT_PATH, { action: 'block' });
        return buildMcpOk({ message: 'ThreatInsight set to blocking mode.', config: data });
      } catch (err) {
        return buildMcpError(err);
      }
    },
  );
}

module.exports = { registerThreatInsightTools };
