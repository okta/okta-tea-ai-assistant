'use strict';

const { z } = require('zod');
const { buildMcpOffline, buildMcpReadOnly } = require('./resolver-utils');
const { createOktaClient } = require('../auth/okta-client');

// ── proxyType values — Okta OAS3 DynamicNetworkZone enum ─────────────────────
// Spec: https://developer.okta.com/docs/api/openapi/okta-management/management/tag/NetworkZone
// Values verified against TEA dataset NetworkZoneSettingProxyType enum:
//   TorAnonymizer = TOR exit nodes only
//   Any           = TOR + all other anonymizing proxies
const PROXY_TYPES = {
  tor:             'TorAnonymizer', // TOR exit nodes only
  all_anonymizers: 'Any',           // TOR + all other anonymizing proxies
};

// ── OFAC comprehensive sanctions programs ────────────────────────────────────
const SANCTIONED_COUNTRIES = [
  { country: 'CU', label: 'Cuba' },
  { country: 'IR', label: 'Iran' },
  { country: 'KP', label: 'North Korea' },
];

// ── Russian-administered Ukrainian regions (ISO 3166-2) ──────────────────────
// DYNAMIC zone NetworkZoneLocation format: { country, region? }
// A missing `region` field means the entire country; a region value means that
// ISO 3166-2 subdivision only.
const DISPUTED_REGIONS = [
  {
    country: 'UA',
    region: 'UA-43',
    label: 'Crimea (UA-43 — Avtonomna Respublika Krym)',
  },
  {
    country: 'UA',
    region: 'UA-14',
    label: 'Donetsk Oblast / DNR (UA-14)',
  },
];

const PROXY_ZONE_NAME   = 'Claude-Security-Proxy-Blocklist';
const COUNTRY_ZONE_NAME = 'Claude-Security-Country-Blocklist';

// ── Location helpers ─────────────────────────────────────────────────────────

/**
 * Build the NetworkZoneLocation array for a DYNAMIC zone.
 *   Full-country block : { country: "CU" }
 *   Sub-region block   : { country: "UA", region: "UA-43" }
 */
function buildLocations({ sanctioned, regions }) {
  const blockedCountries = new Set();
  const entries = [];

  if (sanctioned) {
    for (const c of SANCTIONED_COUNTRIES) {
      entries.push({ country: c.country });
      blockedCountries.add(c.country);
    }
  }

  if (regions) {
    for (const r of DISPUTED_REGIONS) {
      // Skip region entry if the whole country is already blocked
      if (!blockedCountries.has(r.country)) {
        entries.push({ country: r.country, region: r.region });
      }
    }
  }

  return entries;
}

/**
 * Merge new location entries into an existing array.
 * - Incoming full-country entries replace any sub-region entries for that country.
 * - Incoming entries with the same (country, region) key replace the old entry.
 */
function mergeLocations(existing, incoming) {
  const keyOf = (l) => l.region ? `${l.country}/${l.region}` : l.country;
  const incomingKeys        = new Set(incoming.map(keyOf));
  const incomingFullCountries = new Set(
    incoming.filter((l) => !l.region).map((l) => l.country)
  );

  const kept = (existing || []).filter((l) => {
    if (incomingKeys.has(keyOf(l))) return false;             // exact match — replace
    if (l.region && incomingFullCountries.has(l.country)) return false; // region superseded by full-country
    return true;
  });

  return [...kept, ...incoming];
}

// ── Zone look-up ─────────────────────────────────────────────────────────────

async function findZoneByName(client, name) {
  const { data } = await client.get('/api/v1/zones');
  return (data || []).find((z) => z.name === name) ?? null;
}

// ── Feature-availability detection ───────────────────────────────────────────

function isDynamicUnavailable(err) {
  const status = err.response?.status;
  const detail = (err.response?.data?.errorSummary || err.message || '').toLowerCase();
  return (
    (status === 403 || status === 400) &&
    (detail.includes('feature') || detail.includes('not enabled') || detail.includes('dynamic'))
  );
}

function dynamicUnavailableError(apiDetail) {
  return new Error(
    'Enhanced Dynamic (DYNAMIC_V2) network zones are not available on this Okta tenant. ' +
    'This feature requires Okta ThreatInsight Advanced or Adaptive MFA. ' +
    'Contact your Okta account team to enable it. ' +
    `(API detail: ${apiDetail})`
  );
}

// ── Zone upsert helpers ───────────────────────────────────────────────────────

async function upsertProxyZone(client, proxyType, hintId) {
  // Resolve target zone: caller-supplied ID → find by name → create
  let targetId = hintId;
  if (!targetId) {
    const found = await findZoneByName(client, PROXY_ZONE_NAME);
    if (found) targetId = found.id;
  }

  if (targetId) {
    const { data: current } = await client.get(`/api/v1/zones/${targetId}`);
    const { data: updated } = await client.put(`/api/v1/zones/${targetId}`, {
      ...current,
      type: 'DYNAMIC_V2',
      proxyType,
    });
    return { action: 'updated', zone: updated };
  }

  try {
    const { data: created } = await client.post('/api/v1/zones', {
      type:      'DYNAMIC_V2',
      name:      PROXY_ZONE_NAME,
      status:    'ACTIVE',
      usage:     'BLOCKLIST',
      proxyType,
    });
    return { action: 'created', zone: created };
  } catch (err) {
    if (isDynamicUnavailable(err)) {
      throw dynamicUnavailableError(err.response?.data?.errorSummary || err.message);
    }
    throw err;
  }
}

async function upsertCountryZone(client, locations, hintId) {
  let targetId = hintId;
  if (!targetId) {
    const found = await findZoneByName(client, COUNTRY_ZONE_NAME);
    if (found) targetId = found.id;
  }

  if (targetId) {
    const { data: current } = await client.get(`/api/v1/zones/${targetId}`);
    const merged = mergeLocations(current.locations, locations);
    const { data: updated } = await client.put(`/api/v1/zones/${targetId}`, {
      ...current,
      locations: merged,
    });
    return { action: 'updated', zone: updated, locationCount: merged.length };
  }

  try {
    const { data: created } = await client.post('/api/v1/zones', {
      type:      'DYNAMIC',
      name:      COUNTRY_ZONE_NAME,
      status:    'ACTIVE',
      usage:     'BLOCKLIST',
      locations,
    });
    return { action: 'created', zone: created, locationCount: locations.length };
  } catch (err) {
    if (isDynamicUnavailable(err)) {
      throw dynamicUnavailableError(err.response?.data?.errorSummary || err.message);
    }
    throw err;
  }
}

// ── Tool registration ─────────────────────────────────────────────────────────

/**
 * @param {import('@modelcontextprotocol/sdk/server/mcp.js').McpServer} server
 */
function registerSecurityZoneTools(server) {
  server.tool(
    'okta_configure_security_blocklist',
    'Create or update Okta network zones for common security threats. ' +
    'Manages two separate zones: ' +
    '(1) an Enhanced Dynamic (DYNAMIC_V2) BLOCKLIST zone that blocks anonymizing proxies (TOR and/or all anonymizers); ' +
    '(2) a DYNAMIC BLOCKLIST zone that blocks OFAC-sanctioned countries (Cuba, Iran, North Korea) ' +
    'and Russian-administered Ukrainian regions (Crimea UA-43, Donetsk Oblast / DNR UA-14). ' +
    'Each zone is automatically found by its managed name and updated, or created fresh if absent — ' +
    'making the operation idempotent. ' +
    'This is a write operation — confirm intent with the admin before calling.',
    {
      proxyBlock: z
        .enum(['none', 'tor', 'all_anonymizers'])
        .optional()
        .describe(
          'Proxy/anonymizer blocking level. ' +
          '"none" — skip the proxy zone. ' +
          '"tor" — block TOR exit nodes only (proxyType=TorAnonymizer). ' +
          '"all_anonymizers" — block TOR plus all other anonymizing proxies (proxyType=Any). ' +
          'Defaults to "tor" when omitted.'
        ),

      blockSanctionedCountries: z
        .boolean()
        .optional()
        .describe(
          'Block OFAC-sanctioned countries: Cuba (CU), Iran (IR), North Korea (KP). ' +
          'Defaults to true when omitted.'
        ),

      blockDisputedRegions: z
        .boolean()
        .optional()
        .describe(
          'Block Russian-administered Ukrainian regions via ISO 3166-2 sub-region codes: ' +
          'Crimea (UA-43) and Donetsk Oblast / DNR (UA-14). ' +
          'Note: some geolocation providers assign IPs in these territories to Russia (RU) ' +
          'rather than Ukraine, so coverage may be incomplete. ' +
          'Defaults to true when omitted.'
        ),

      existingProxyZoneId: z
        .string()
        .optional()
        .describe(
          'ID of an existing DYNAMIC_V2 (Enhanced Dynamic) BLOCKLIST zone to update with the proxy rule. ' +
          'Omit to auto-find or create "' + PROXY_ZONE_NAME + '".'
        ),

      existingCountryZoneId: z
        .string()
        .optional()
        .describe(
          'ID of an existing DYNAMIC BLOCKLIST zone to update with country/region rules ' +
          '(new entries are merged with existing ones). ' +
          'Omit to auto-find or create "' + COUNTRY_ZONE_NAME + '".'
        ),
    },

    async ({
      proxyBlock               = 'tor',
      blockSanctionedCountries = true,
      blockDisputedRegions     = true,
      existingProxyZoneId,
      existingCountryZoneId,
    }) => {
      if (proxyBlock === 'none' && !blockSanctionedCountries && !blockDisputedRegions) {
        return {
          content: [{
            type: 'text',
            text: JSON.stringify({
              ok: false,
              error: 'Nothing to configure — proxyBlock is "none" and both country/region options are false.',
            }),
          }],
          isError: true,
        };
      }

      if (process.env.OFFLINE_MODE === 'true') {
        return buildMcpOffline({ skipped: true, message: 'Write operations are not available in offline mode.' });
      }
      if (process.env.PROD_MODE === 'true') {
        return buildMcpReadOnly();
      }

      const results  = [];
      const warnings = [];

      try {
        const client = await createOktaClient();

        // ── Proxy zone ───────────────────────────────────────────────────────
        if (proxyBlock !== 'none') {
          const proxyType = PROXY_TYPES[proxyBlock];
          try {
            const r = await upsertProxyZone(client, proxyType, existingProxyZoneId ?? null);
            results.push({
              zone:        'proxy',
              action:      r.action,
              id:          r.zone.id,
              name:        r.zone.name,
              proxyType,
              description: proxyBlock === 'tor'
                ? 'Blocks TOR exit node traffic.'
                : 'Blocks all anonymizing proxy traffic (TOR and non-TOR anonymizers).',
            });
          } catch (err) {
            warnings.push({ zone: 'proxy', error: err.message });
          }
        }

        // ── Country / region zone ────────────────────────────────────────────
        if (blockSanctionedCountries || blockDisputedRegions) {
          const locations = buildLocations({
            sanctioned: blockSanctionedCountries,
            regions:    blockDisputedRegions,
          });

          const blockedLabels = [
            ...(blockSanctionedCountries
              ? SANCTIONED_COUNTRIES.map((c) => `${c.label} (${c.country})`)
              : []),
            ...(blockDisputedRegions
              ? DISPUTED_REGIONS.map((r) => r.label)
              : []),
          ];

          try {
            const r = await upsertCountryZone(client, locations, existingCountryZoneId ?? null);
            results.push({
              zone:                 'countries',
              action:               r.action,
              id:                   r.zone.id,
              name:                 r.zone.name,
              blocked:              blockedLabels,
              totalLocationEntries: r.locationCount,
            });

            if (blockDisputedRegions) {
              warnings.push({
                zone:    'countries',
                message:
                  'Crimea (UA-43) and Donetsk Oblast (UA-14) are blocked via Ukrainian ISO 3166-2 ' +
                  'region codes. Some geolocation providers assign IPs in these territories to Russia ' +
                  '(RU) — coverage for those IPs will be incomplete. For comprehensive blocking, ' +
                  'consider also adding Russia (RU) as a full-country entry.',
              });
            }
          } catch (err) {
            warnings.push({ zone: 'countries', error: err.message });
          }
        }

        const ok = results.length > 0;
        return {
          content: [{
            type: 'text',
            text: JSON.stringify({ ok, results, warnings }),
          }],
          isError: !ok,
        };
      } catch (err) {
        return {
          content: [{
            type: 'text',
            text: JSON.stringify({ ok: false, error: err.message }),
          }],
          isError: true,
        };
      }
    }
  );
}

module.exports = { registerSecurityZoneTools };
