'use strict';

const { z } = require('zod');
const { buildMcpOk, buildMcpError, buildMcpOffline, buildMcpReadOnly } = require('./resolver-utils');
const { createOktaClient } = require('../auth/okta-client');

const COUNTRY_CODE_REGEX = /^[A-Z]{2}$/;

function validateCountryCodes(codes) {
  const invalid = codes.filter((c) => !COUNTRY_CODE_REGEX.test(c));
  if (invalid.length > 0) {
    throw new Error(
      `Invalid country codes: ${invalid.join(', ')}. Use ISO 3166-1 alpha-2 format (e.g. "US", "CN", "RU").`,
    );
  }
}

// ── IP zone size audit — mirrors TEA NetworkZonesSufficientlyRestrictive ──────
// Default threshold: 2 * 256 = 512 addresses across all active IP zones.
// Source: threat_exposure_analyzer/models/config.py NETWORK_ZONES_MAXIMUM_ADDRESSES
const IP_ZONE_MAX_ADDRESSES = 2 * 256;

function ipv4ToInt(ip) {
  return ip.trim().split('.').reduce((acc, octet) => (acc << 8) + parseInt(octet, 10), 0) >>> 0;
}

function countGatewayIps(gateway) {
  const { type, value } = gateway;
  if (!value) return 0;
  if (type === 'CIDR') {
    const slash = value.indexOf('/');
    if (slash === -1) return 1;
    const ip = value.slice(0, slash).trim();
    if (ip.includes(':')) return 1; // IPv6 — count as 1 per TEA
    const prefix = parseInt(value.slice(slash + 1), 10);
    return Math.pow(2, 32 - prefix);
  }
  if (type === 'RANGE') {
    const [start, end] = value.split('-');
    if (!start || !end) return 1;
    if (start.trim().includes(':') || end.trim().includes(':')) return 1; // IPv6
    const diff = ipv4ToInt(end) - ipv4ToInt(start);
    return diff >= 0 ? diff + 1 : 1;
  }
  return 0;
}

function auditIpZoneSizes(zones) {
  const activeIpZones = zones.filter((z) => z.type === 'IP' && z.status === 'ACTIVE');
  const zoneIpCounts = activeIpZones.map((z) => ({
    id:      z.id,
    name:    z.name,
    ipCount: (z.gateways || []).reduce((sum, gw) => sum + countGatewayIps(gw), 0),
  }));
  const totalIps = zoneIpCounts.reduce((sum, z) => sum + z.ipCount, 0);
  const passed   = totalIps < IP_ZONE_MAX_ADDRESSES;
  return {
    totalIps,
    threshold:      IP_ZONE_MAX_ADDRESSES,
    passed,
    teaSeverity:    'MODERATE',
    violatingZones: passed ? [] : zoneIpCounts.filter((z) => z.ipCount > 0).sort((a, b) => b.ipCount - a.ipCount),
    finding: passed ? null : {
      id:             'IP_ZONE_TOO_BROAD',
      severity:       'MODERATE',
      description:    `Total addressable IPs across active IP zones is ${totalIps}, exceeding the TEA threshold of ${IP_ZONE_MAX_ADDRESSES}. Overly broad IP ranges mean that if any IP in the range is compromised, the zone exemption or block applies to far more addresses than intended.`,
      recommendation: `Tighten gateway CIDR/range entries so total IPs across all active IP zones is below ${IP_ZONE_MAX_ADDRESSES}. Use /32 entries or narrow CIDRs for known corporate IPs rather than broad /8 or /16 ranges.`,
    },
  };
}

// ── Syslog helper ─────────────────────────────────────────────────────────────

async function fetchBlockedRequestStats(client) {
  const since = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString();
  try {
    const { data: events } = await client.get('/api/v1/logs', {
      params: { filter: 'eventType eq "security.request.blocked"', since, limit: 1000 },
    });

    const blocksByZone = {};
    for (const event of events) {
      const zoneName =
        event.debugContext?.debugData?.networkZoneName  ||
        event.debugContext?.debugData?.zoneName         ||
        event.target?.find((t) => t.type === 'NetworkZone')?.displayName ||
        event.outcome?.reason                           ||
        null;
      if (zoneName) blocksByZone[zoneName] = (blocksByZone[zoneName] || 0) + 1;
    }

    const stats = {
      total:     events.length,
      truncated: events.length === 1000,
      period:    'last_7_days',
      byZone:    Object.entries(blocksByZone)
        .sort(([, a], [, b]) => b - a)
        .map(([zoneName, count]) => ({ zoneName, count })),
    };
    return { blocksByZone, stats };
  } catch (err) {
    return { blocksByZone: {}, stats: { total: null, period: 'last_7_days', error: err.message } };
  }
}

// ── Network zone remediation builders ─────────────────────────────────────────

/**
 * Terraform templates for common network zone use cases.
 *
 * Schema verified against provider source:
 *   https://registry.terraform.io/providers/okta/okta/latest/docs/resources/network_zone
 *
 * Key attributes confirmed from provider docs:
 *   IP zone:      type = "IP",      gateways = set of CIDR/range strings
 *   DYNAMIC zone: type = "DYNAMIC", dynamic_locations = set of ISO-3166-1 alpha-2 country codes
 *                                   (NOT "locations" — that attribute does not exist)
 *   usage:        "POLICY" (default) | "BLOCKLIST"
 */
function buildListTerraform() {
  return `# Terraform — Okta Network Zone examples
#
# Provider setup:
#   https://developer.okta.com/docs/guides/terraform-enable-org-access/main/
# Resource reference:
#   https://registry.terraform.io/providers/okta/okta/latest/docs/resources/network_zone

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
  base_url    = "okta.com"
  client_id   = "<YOUR_CLIENT_ID>"
  scopes      = ["okta.networkZones.manage"]
  private_key = "<PATH_OR_CONTENT_OF_PRIVATE_KEY>"
}

# ── Example 1: IP zone for corporate / trusted network ────────────────────────
# Use this to identify known-good IP ranges (office, VPN, CI/CD) in sign-on policies
# and in ThreatInsight's network_excludes list.
# gateways accepts CIDR notation ("203.0.113.0/24") or IP ranges ("10.0.0.1-10.0.0.50").

resource "okta_network_zone" "corporate_network" {
  name   = "Corporate-Network"
  type   = "IP"
  status = "ACTIVE"
  usage  = "POLICY"

  gateways = [
    "203.0.113.0/24",    # Replace with your office CIDR
    "198.51.100.0/24",   # Replace with your VPN CIDR
  ]

  # proxies = ["..."]    # Optional: add known proxy IPs here
}

# ── Example 2: DYNAMIC BLOCKLIST zone for country blocking ────────────────────
# Blocks all sign-in attempts from the listed countries.
# Requires Okta ThreatInsight Advanced or Adaptive MFA feature.
# dynamic_locations accepts ISO 3166-1 alpha-2 codes ("CN") or
# country-region codes ("CN-BJ" = Beijing).

resource "okta_network_zone" "country_blocklist" {
  name              = "Country-Blocklist"
  type              = "DYNAMIC"
  status            = "ACTIVE"
  usage             = "BLOCKLIST"
  dynamic_locations = ["CN", "RU", "KP", "IR"]   # Replace with your blocked countries
}

# ── Example 3: DYNAMIC BLOCKLIST for Tor exit nodes ──────────────────────────
# Blocks all Tor anonymiser traffic automatically — no country codes needed.

resource "okta_network_zone" "tor_blocklist" {
  name               = "Tor-Anonymizer-Blocklist"
  type               = "DYNAMIC"
  status             = "ACTIVE"
  usage              = "BLOCKLIST"
  dynamic_proxy_type = "TorAnonymizer"
}
`;
}

/**
 * Generate Terraform for the specific DYNAMIC BLOCKLIST zone that was just
 * created or updated by okta_block_countries.
 */
function buildBlockCountriesTerraform(zoneName, countryCodes) {
  const locationsHcl = countryCodes
    .map((c, i) => `    "${c}"${i < countryCodes.length - 1 ? ',' : ''}`)
    .join('\n');

  const resourceLabel = zoneName
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '') || 'country_blocklist';

  return `# Terraform — Okta Network Zone (country BLOCKLIST)
#
# Provider setup:
#   https://developer.okta.com/docs/guides/terraform-enable-org-access/main/
# Resource reference:
#   https://registry.terraform.io/providers/okta/okta/latest/docs/resources/network_zone
#
# dynamic_locations: ISO 3166-1 alpha-2 country codes. Format: "CN" (whole country)
# or "CN-BJ" (country + region). DYNAMIC zones require ThreatInsight Advanced.

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

resource "okta_network_zone" "${resourceLabel}" {
  name              = "${zoneName}"
  type              = "DYNAMIC"
  status            = "ACTIVE"
  usage             = "BLOCKLIST"
  dynamic_locations = [
${locationsHcl}
  ]
}
`;
}

function buildNetworkZoneLogQueries(zoneName) {
  const zoneFilter = zoneName
    ? ` and debugContext.debugData.networkZoneName eq "${zoneName}"`
    : '';

  return [
    {
      description: 'Requests blocked by any network zone',
      filter: 'eventType eq "security.request.blocked"',
      timeWindow: 'last 30 days',
      note: 'Baseline view of all zone-based blocking. Run after activating a new BLOCKLIST zone to confirm it is taking effect.',
    },
    {
      description: `Requests blocked by this zone${zoneName ? ` (${zoneName})` : ''}`,
      filter: `eventType eq "security.request.blocked"${zoneFilter}`,
      timeWindow: 'last 7 days',
      note: zoneName
        ? `Isolates blocking activity for the "${zoneName}" zone specifically.`
        : 'Replace the networkZoneName value with your zone\'s exact name to isolate its activity.',
    },
    {
      description: 'Network zone configuration changes (admin audit trail)',
      filter: 'eventType sw "zone."',
      timeWindow: 'last 90 days',
      note: 'The sw (starts-with) operator matches zone.create, zone.update, zone.delete, and related events. Use to audit who changed zone configuration and when.',
    },
    {
      description: 'Successful sign-ins from blocked countries (potential bypass indicator)',
      filter: 'eventType eq "user.session.start" and outcome.result eq "SUCCESS"',
      timeWindow: 'last 7 days',
      note: 'Cross-reference with your blocked country list. Successes from blocked countries may indicate VPN bypass, misconfigured zone, or an inactive zone status.',
    },
  ];
}

function buildNetworkZoneRiskAssessment(context) {
  // teaSeverity for proxy blocking (TOR / anonymizers) = HIGH per TEA validators
  // NetworkBlockingTorProxies and NetworkBlockingAnonymizingProxies.
  // teaSeverity for country blocking = MODERATE per NetworkZonesHighRiskCountriesBlocked.
  const base = {
    teaSeverity: context === 'country-block' ? 'MODERATE' : 'HIGH',
    rollback: 'Deactivate or delete the zone immediately to stop blocking. Changes take effect within seconds.',
  };

  if (context === 'country-block') {
    return {
      ...base,
      changeRisk: 'MODERATE',
      summary:
        'Country-level blocking via DYNAMIC zones is broad — it blocks ALL traffic from a country, ' +
        'including legitimate remote workers, business partners, and contractors. ' +
        'The risk of blocking legitimate users is higher than ThreatInsight (which is IP-reputation based).',
      preChangeChecks: [
        'Review the last 30 days of user.session.start events and check actor.geographicalContext.country for the target countries.',
        'Confirm no active employees, contractors, or partners are located in the countries you plan to block.',
        'Check whether any automated integrations or cloud services egress from the target countries.',
        'Enable ThreatInsight blocking first as a lower-risk alternative before using country blocking.',
      ],
      blastRadius:
        'Remote employees or contractors in blocked countries will be denied access immediately. ' +
        'Automated systems with cloud egress in blocked regions will also be blocked. ' +
        'Partner integrations originating from affected countries will stop working. ' +
        'Country blocking has a larger blast radius than ThreatInsight — use only for countries ' +
        'with zero legitimate business activity.',
      rolloutSteps: [
        'Step 1 — Enable ThreatInsight blocking first (lower false-positive risk).',
        'Step 2 — Review user locations to confirm no legitimate users are in the target countries.',
        'Step 3 — Create the DYNAMIC BLOCKLIST zone with target country codes.',
        'Step 4 — Activate in POLICY mode first (step-up MFA) before switching to BLOCKLIST.',
        'Step 5 — Monitor security.request.blocked events for 48 hours (see postChangeMonitoring queries).',
      ],
      postChangeMonitoring: {
        description:
          'After activating a country BLOCKLIST zone, monitor for blocked requests from unexpected countries or users.',
        logQueries: [
          {
            description: 'Requests blocked by network zone (country)',
            filter: 'eventType eq "security.request.blocked"',
            timeWindow: 'first 48 hours post-change',
            note: 'Check actor.geographicalContext.country on each blocked event. Unexpected countries in the block list need investigation.',
          },
          {
            description: 'Sign-in attempts from blocked countries (successful — possible bypass)',
            filter: 'eventType eq "user.session.start" AND outcome.result eq "SUCCESS"',
            timeWindow: 'first 48 hours post-change',
            note: 'Cross-reference with your blocked country list. Successes from blocked countries may indicate VPN bypass or a misconfigured zone.',
          },
        ],
      },
    };
  }

  return {
    ...base,
    changeRisk: 'MODERATE',
    summary: 'Network Zones let you deny or step-up authentication from unusual locations. ' +
      'IP-type zones in POLICY mode apply different authentication requirements based on network location; ' +
      'in BLOCKLIST mode they hard-deny all traffic from listed IPs. ' +
      'DYNAMIC zones extend this to country-level and proxy/TOR blocking.',
    preChangeChecks: [
      'Verify CIDR ranges are accurate — misconfigured ranges can block legitimate corporate traffic.',
      'Confirm no critical service accounts or integrations originate from the IPs being blocked.',
      'Test with a single non-critical application before applying the zone broadly.',
    ],
    blastRadius: 'Misconfigured CIDR ranges could block legitimate corporate traffic. ' +
      'In POLICY mode the blast radius is limited to extra MFA prompts; in BLOCKLIST mode it is a hard deny for all traffic from those IPs.',
    rolloutSteps: [
      'Step 1 — Verify CIDR ranges are accurate.',
      'Step 2 — Activate zone in POLICY mode first to test sign-on rule behavior.',
      'Step 3 — Switch to BLOCKLIST usage only if all traffic from those IPs should be denied.',
      'Step 4 — Monitor for unexpected blocks (see postChangeMonitoring queries).',
    ],
    postChangeMonitoring: {
      description: 'After creating or modifying a network zone, confirm the intended traffic is affected and no legitimate traffic is blocked.',
      logQueries: [
        {
          description: 'Requests blocked by this network zone',
          filter: 'eventType eq "security.request.blocked"',
          timeWindow: 'first 48 hours post-change',
          note: 'Review each blocked event to confirm the blocked IP is expected.',
        },
        {
          description: 'Network zone configuration audit trail',
          filter: 'eventType sw "zone."',
          timeWindow: 'last 7 days',
          note: 'Confirms zone was created/updated as expected.',
        },
      ],
    },
  };
}

// ── Tools ─────────────────────────────────────────────────────────────────────

function registerNetworkZoneTools(server) {

  server.tool(
    'okta_list_network_zones',
    'List all Okta network zones with their id, name, type (IP / DYNAMIC / DYNAMIC_V2), status, usage (POLICY or BLOCKLIST), ' +
    'blocked_requests_7d — requests blocked by each zone over the last 7 days (from security.request.blocked syslog events), ' +
    'and ip_count — total addressable IPs in each active IP-type zone. ' +
    'Runs a TEA-aligned IP zone size audit: flags if total IPs across all active IP zones exceeds 512 (TEA NetworkZonesSufficientlyRestrictive threshold). ' +
    'Also returns Terraform templates and System Log queries for managing network zones.',
    {},
    async () => {
      if (process.env.OFFLINE_MODE === 'true') {
        return buildMcpOffline({
          ip_zone_audit: { totalIps: 0, threshold: IP_ZONE_MAX_ADDRESSES, passed: true, teaSeverity: 'MODERATE', violatingZones: [], finding: null },
          remediation: {
            terraform:         buildListTerraform(),
            logQueries:        buildNetworkZoneLogQueries(null),
            adminConsoleSteps: null,
            riskAssessment:    buildNetworkZoneRiskAssessment('general'),
          },
        });
      }
      try {
        const client = await createOktaClient();

        const [{ data: zones }, { blocksByZone, stats: blockedStats }] = await Promise.all([
          client.get('/api/v1/zones'),
          fetchBlockedRequestStats(client),
        ]);

        const ipZoneAudit = auditIpZoneSizes(zones);

        const summary = zones.map((z) => ({
          id:                  z.id,
          name:                z.name,
          type:                z.type,
          status:              z.status,
          usage:               z.usage,
          blocked_requests_7d: blocksByZone[z.name] ?? 0,
          ...(z.type === 'IP' && z.status === 'ACTIVE' ? {
            ip_count: (z.gateways || []).reduce((sum, gw) => sum + countGatewayIps(gw), 0),
          } : {}),
          ...(z.type === 'DYNAMIC' ? { locations: z.locations || [] } : {}),
        }));

        return buildMcpOk({
          zones:               summary,
          blocked_requests_7d: blockedStats,
          ip_zone_audit:       ipZoneAudit,
          remediation: {
            terraform:         buildListTerraform(),
            logQueries:        buildNetworkZoneLogQueries(null),
            adminConsoleSteps: [
              'Sign in to the Okta Admin Console.',
              'Go to Security > Networks to view and manage network zones.',
              'Click "Add Zone" to create a new zone (IP or DYNAMIC type).',
              'For an IP zone: enter CIDRs or IP ranges under "Gateway IPs".',
              'For a DYNAMIC blocklist: choose "Block" for usage, then select countries or proxy type.',
              'Set status to "Active" and click Save.',
              'To use a zone in ThreatInsight exclusions, go to Security > General > ThreatInsight.',
              `TEA finding — IP zone size: if ip_zone_audit.passed is false, tighten CIDR entries in the listed violatingZones to bring total IPs below ${IP_ZONE_MAX_ADDRESSES}.`,
              'Use Network Zones to deny or step-up authentication from unusual locations: create a DYNAMIC zone for high-risk countries and set it to BLOCKLIST to deny, or to POLICY mode to require step-up MFA for sign-ins originating outside known corporate networks.',
            ],
            riskAssessment: buildNetworkZoneRiskAssessment('general'),
          },
        });
      } catch (err) {
        return buildMcpError(err);
      }
    },
  );

  server.tool(
    'okta_get_network_zone',
    'Get the full details of a specific Okta network zone by ID.',
    { zoneId: z.string().describe('The Okta network zone ID') },
    async ({ zoneId }) => {
      if (process.env.OFFLINE_MODE === 'true') {
        return buildMcpOffline({
          remediation: {
            terraform:         buildBlockCountriesTerraform('my-blocklist', []),
            logQueries:        buildNetworkZoneLogQueries('my-blocklist'),
            adminConsoleSteps: null,
            riskAssessment:    buildNetworkZoneRiskAssessment({}),
          },
        });
      }
      try {
        const client = await createOktaClient();
        const { data } = await client.get(`/api/v1/zones/${zoneId}`);
        return buildMcpOk({ zone: data });
      } catch (err) {
        const status = err.response?.status;
        const msg = status === 404 ? `Zone "${zoneId}" not found.` : err.message;
        return buildMcpError(new Error(msg));
      }
    },
  );

  server.tool(
    'okta_block_countries',
    'Add one or more countries to an Okta DYNAMIC BLOCKLIST network zone. If zoneId is provided, countries are added to that existing zone. If omitted, a new DYNAMIC BLOCKLIST zone named "Claude-Blocked-Countries" is created. Requires Adaptive MFA / ThreatInsight Advanced. Country codes must be ISO 3166-1 alpha-2 (e.g. ["CN", "RU", "KP"]). Write operation — confirm with the admin before calling.',
    {
      countryCodes: z.array(z.string()).describe('ISO 3166-1 alpha-2 country codes to block, e.g. ["CN", "RU"]'),
      zoneId: z.string().optional().describe('Existing DYNAMIC BLOCKLIST zone ID to update. Omit to create a new zone.'),
    },
    async ({ countryCodes, zoneId }) => {
      if (process.env.OFFLINE_MODE === 'true') {
        return buildMcpOffline({ skipped: true, message: 'Write operations are not available in offline mode.' });
      }
      if (process.env.PROD_MODE === 'true') {
        return buildMcpReadOnly();
      }
      try {
        validateCountryCodes(countryCodes);
      } catch (err) {
        return buildMcpError(err);
      }

      const newLocations = countryCodes.map((code) => ({ country: code, include: [] }));

      try {
        const client = await createOktaClient();

        if (zoneId) {
          const { data: existing } = await client.get(`/api/v1/zones/${zoneId}`);

          if (existing.type !== 'DYNAMIC') {
            return buildMcpError(new Error(
              `Zone "${zoneId}" is type "${existing.type}", not DYNAMIC. Country blocking requires a DYNAMIC zone. ` +
              'Omit zoneId to create a new DYNAMIC BLOCKLIST zone.',
            ));
          }

          const existingCodes = new Set((existing.locations || []).map((l) => l.country));
          const toAdd         = newLocations.filter((l) => !existingCodes.has(l.country));
          const merged        = [...(existing.locations || []), ...toAdd];

          const { data: updated } = await client.put(`/api/v1/zones/${zoneId}`, {
            ...existing,
            locations: merged,
          });

          const allCodes = merged.map((l) => l.country);
          return buildMcpOk({
            message:    `Added ${toAdd.length} country code(s) to zone "${existing.name}". ${merged.length} total blocked countries.`,
            addedCodes: toAdd.map((l) => l.country),
            zone:       { id: updated.id, name: updated.name, locations: updated.locations },
            remediation: {
              terraform:         buildBlockCountriesTerraform(updated.name, allCodes),
              logQueries:        buildNetworkZoneLogQueries(updated.name),
              adminConsoleSteps: [
                `Sign in to the Okta Admin Console.`,
                `Go to Security > Networks and open the "${updated.name}" zone.`,
                `Verify the updated country list includes the newly added codes.`,
                `Check zone status is "Active".`,
                `Open Reports > System Log and filter: eventType eq "security.request.blocked" and debugContext.debugData.networkZoneName eq "${updated.name}" — new blocks should appear within minutes.`,
              ],
              riskAssessment: buildNetworkZoneRiskAssessment('country-block'),
            },
          });
        } else {
          const body = {
            type:      'DYNAMIC',
            name:      'Claude-Blocked-Countries',
            status:    'ACTIVE',
            usage:     'BLOCKLIST',
            locations: newLocations,
          };

          let created;
          try {
            const res = await client.post('/api/v1/zones', body);
            created = res.data;
          } catch (apiErr) {
            const detail = apiErr.response?.data?.errorSummary || apiErr.message;
            if (apiErr.response?.status === 403 || detail.toLowerCase().includes('feature') || detail.toLowerCase().includes('not enabled')) {
              return buildMcpError(new Error(
                'DYNAMIC network zones are not available on this Okta tenant. ' +
                'This feature requires Okta ThreatInsight Advanced or Adaptive MFA. ' +
                'Contact your Okta account team to enable it.',
              ));
            }
            throw apiErr;
          }

          return buildMcpOk({
            message:  `Created DYNAMIC BLOCKLIST zone "${created.name}" with ${countryCodes.length} blocked country code(s).`,
            zone:     { id: created.id, name: created.name, locations: created.locations },
            remediation: {
              terraform:         buildBlockCountriesTerraform(created.name, countryCodes),
              logQueries:        buildNetworkZoneLogQueries(created.name),
              adminConsoleSteps: [
                `Sign in to the Okta Admin Console.`,
                `Go to Security > Networks — confirm "${created.name}" appears and status is "Active".`,
                `Open Reports > System Log and filter: eventType eq "security.request.blocked" and debugContext.debugData.networkZoneName eq "${created.name}" — blocks should appear within minutes.`,
                `To add more countries later, call okta_block_countries with the zone ID: ${created.id}`,
              ],
              riskAssessment: buildNetworkZoneRiskAssessment('country-block'),
            },
          });
        }
      } catch (err) {
        return buildMcpError(err);
      }
    },
  );
}

module.exports = { registerNetworkZoneTools };
