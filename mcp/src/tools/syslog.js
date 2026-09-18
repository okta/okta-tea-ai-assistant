'use strict';

const { z } = require('zod');
const { buildMcpOk, buildMcpError, buildMcpOffline } = require('./resolver-utils');
const { createOktaClient } = require('../auth/okta-client');

// ── Factor classification ─────────────────────────────────────────────────────
//
// Okta OIE System Log events carry factor info in authenticationContext.
// Classic tenants use debugContext.debugData.factor instead.
// We check both to be robust across tenant types.

function classifyEvent(event) {
  const credType   = (event.authenticationContext?.credentialType || '').toUpperCase().trim();
  const authKey    = (event.authenticationContext?.authenticatorKey || '').toLowerCase().trim();
  const debugFactor = (event.debugContext?.debugData?.factor || '').toUpperCase().trim();

  // WebAuthn: credentialType "FIDO2", OR authenticatorKey "webauthn", OR legacy "FIDO_WEBAUTHN"
  if (
    credType   === 'FIDO2' ||
    authKey    === 'webauthn' ||
    debugFactor === 'FIDO_WEBAUTHN'
  ) {
    return { phishingResistant: true, factor: 'webauthn', label: 'WebAuthn / FIDO2' };
  }

  // FastPass: credentialType "SIGNED_NONCE" (OIE) or legacy "SIGNED_NONCE"
  if (credType === 'SIGNED_NONCE' || debugFactor === 'SIGNED_NONCE') {
    return { phishingResistant: true, factor: 'fastpass', label: 'Okta FastPass' };
  }

  // Non-phishing-resistant — keep a human-readable label for the breakdown table
  const label = credType || debugFactor || authKey || 'UNKNOWN';
  return { phishingResistant: false, factor: label, label };
}

// ── Log fetcher ────────────────────────────────────────────────────────────────
//
// Okta System Log API constraints:
//   - Max page size:    1,000 events per request
//   - Rate limit:       5–20 requests/minute on developer tenants; higher on production.
//                       The SAME budget is shared with every other tool that queries
//                       /api/v1/logs (ThreatInsight, Network Zones, etc.).
//   - Sort order:       newest-first always
//   - Pagination:       Link: <url>; rel="next" header
//   - On 429:           X-Rate-Limit-Reset header gives the Unix timestamp to retry after
//
// Strategy: one page (1,000 events max), with one retry on 429 after the reset window.
// One page = one API call, well within any tenant's log rate limit. For most tenants
// (<1,000 MFA successes in 24 h) this is complete. For larger tenants it's an honest
// sample of the most recent events, reported with the actual window covered.

const MAX_RETRIES = 1;
const FALLBACK_RETRY_MS = 62_000; // wait 62s if X-Rate-Limit-Reset header is missing

async function getLogsWithRetry(client, url, config, attempt = 0) {
  try {
    return await client.get(url, config);
  } catch (err) {
    const status = err.response?.status;
    if (status === 429 && attempt < MAX_RETRIES) {
      // Okta returns X-Rate-Limit-Reset as a Unix timestamp (seconds)
      const resetHeader = err.response?.headers?.['x-rate-limit-reset'];
      const resetMs = resetHeader
        ? Math.max(0, parseInt(resetHeader, 10) * 1000 - Date.now()) + 1000
        : FALLBACK_RETRY_MS;

      await new Promise((resolve) => setTimeout(resolve, resetMs));
      return getLogsWithRetry(client, url, config, attempt + 1);
    }
    throw err;
  }
}

async function fetchMfaSuccessEvents(client, since) {
  const filter = 'eventType eq "user.authentication.auth_via_mfa" AND outcome.result eq "SUCCESS"';

  const response = await getLogsWithRetry(client, '/api/v1/logs', {
    params: { filter, since, limit: 1000 },
  });

  const events = Array.isArray(response.data) ? response.data : [];

  // Check whether more pages exist (we deliberately don't fetch them to preserve rate limit)
  const linkHeader = response.headers?.link || '';
  const hasMore    = linkHeader.includes('rel="next"');

  // Remaining rate limit budget after this one call
  const rateLimitRemaining = parseInt(response.headers?.['x-rate-limit-remaining'] ?? '-1', 10);

  const oldestEvent = events.length > 0 ? events[events.length - 1].published : null;

  return { events, oldestEvent, truncated: hasMore, rateLimitRemaining };
}

// ── Tool registration ─────────────────────────────────────────────────────────

function registerSyslogTools(server) {
  server.tool(
    'okta_get_phishing_resistant_usage',
    'Calculate recent phishing-resistant MFA usage by querying Okta System Log ' +
    '(eventType eq "user.authentication.auth_via_mfa" AND outcome.result eq "SUCCESS"). ' +
    'Counts successful MFA authentications by factor type and reports the number and percentage ' +
    'of phishing-resistant sign-ins — WebAuthn/FIDO2 (hardware-bound, AiTM-immune) and ' +
    'Okta FastPass (signed_nonce, device-bound, passwordless) — versus total successful MFA. ' +
    'Requires okta.logs.read scope.',
    {},
    async () => {
      if (process.env.OFFLINE_MODE === 'true') {
        // Representative demo data — shows a tenant with low phishing-resistant adoption
        return buildMcpOffline({
          period: 'last_24_hours',
          note: 'Offline mode — sample data only. Connect to a live tenant for real usage statistics.',
          totalMfaSuccesses: 247,
          phishingResistantTotal: 31,
          phishingResistantPercent: 13,
          breakdown: {
            webauthn:  12,
            fastpass:  19,
            other:     216,
            byFactor: {
              'WebAuthn / FIDO2':     12,
              'Okta FastPass':        19,
              'PUSH':                 148,
              'TOTP':                 52,
              'EMAIL':                16,
            },
          },
          eventsTruncated: false,
          interpretation:
            '13% of MFA successes used a phishing-resistant factor. ' +
            'The majority (87%) used factors that are susceptible to real-time phishing and AiTM attacks. ' +
            'Consider enabling FastPass on managed devices and requiring WebAuthn/FastPass in Authentication Policies.',
        });
      }

      try {
        const client = await createOktaClient();
        const since  = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();

        const { events, oldestEvent, truncated, rateLimitRemaining } = await fetchMfaSuccessEvents(client, since);

        // Tally by factor
        let webauthnCount  = 0;
        let fastpassCount  = 0;
        const byFactor = {};

        for (const event of events) {
          const { factor, label } = classifyEvent(event);
          byFactor[label] = (byFactor[label] || 0) + 1;
          if (factor === 'webauthn')  webauthnCount++;
          if (factor === 'fastpass')  fastpassCount++;
        }

        const total = events.length;
        const phishingResistantTotal = webauthnCount + fastpassCount;
        const phishingResistantPercent = total > 0
          ? Math.round((phishingResistantTotal / total) * 100)
          : 0;

        // Describe the actual sample window covered
        const sampleWindow = oldestEvent
          ? `${oldestEvent} → now (${total} events, 1 API call)`
          : 'no events found';

        const sampleNote = truncated
          ? `Result is a sample of the most recent ${total} events — more events exist in the 24-hour window. ` +
            `For this tenant, ${total} events covers only the period from ${oldestEvent} to now, not the full 24 hours. ` +
            'The percentage shown is representative of recent traffic, not a full-day count.'
          : null;

        const interpretation = total === 0
          ? 'No successful MFA authentications were recorded in the queried window.'
          : phishingResistantPercent >= 80
            ? `${phishingResistantPercent}% of sampled MFA successes used a phishing-resistant factor — strong adoption.`
            : phishingResistantPercent >= 40
              ? `${phishingResistantPercent}% of sampled MFA successes used a phishing-resistant factor — moderate adoption. ` +
                'Consider expanding FastPass deployment or requiring phishing-resistant factors in Authentication Policies.'
              : `${phishingResistantPercent}% of sampled MFA successes used a phishing-resistant factor — low adoption. ` +
                'Most sign-ins use factors susceptible to real-time phishing and AiTM attacks (push, TOTP, SMS). ' +
                'Enable FastPass on managed devices and add WebAuthn to Authentication Policies.';

        return buildMcpOk({
          queriedWindow: 'last_24_hours',
          since,
          sampleWindow,
          sampleNote,
          eventsAnalysed:          total,
          isSample:                truncated,
          phishingResistantTotal,
          phishingResistantPercent,
          breakdown: {
            webauthn:  webauthnCount,
            fastpass:  fastpassCount,
            other:     total - phishingResistantTotal,
            byFactor:  Object.fromEntries(
              Object.entries(byFactor).sort(([, a], [, b]) => b - a),
            ),
          },
          interpretation,
          rateLimitRemaining,
        });
      } catch (err) {
        return buildMcpError(err);
      }
    },
  );

  server.tool(
    'okta_query_syslogs',
    'Run an ad-hoc query against the Okta System Log (/api/v1/logs). ' +
    'Accepts any valid Okta SCIM filter expression and returns matching events with key fields ' +
    '(timestamp, eventType, actor, target, outcome, client IP, factor type). ' +
    'Use this for: investigating specific users or IPs, auditing admin actions, ' +
    'counting failed sign-ins, checking policy changes, or any other one-off log analysis. ' +
    'Handles 429 rate limits with automatic retry. Requires okta.logs.read scope. ' +
    'Filter syntax reference: https://developer.okta.com/docs/reference/api/system-log/#filter-expression',
    {
      filter: z.string()
        .describe(
          'Okta System Log SCIM filter. Examples: ' +
          '"eventType eq \\"user.session.start\\" AND outcome.result eq \\"FAILURE\\"" — failed sign-ins; ' +
          '"eventType eq \\"user.account.update_password\\"" — password changes; ' +
          '"actor.id eq \\"00u...\\"" — events by a specific user; ' +
          '"eventType sw \\"policy.\\"" — all policy changes.',
        ),
      since: z.string().optional()
        .describe('ISO 8601 start time. Default: 24 hours ago. Example: "2024-01-15T00:00:00Z".'),
      limit: z.number().int().min(1).max(1000).optional()
        .describe('Max events to return (1–1000). Default: 100. Use 1000 for counting/statistics queries.'),
    },
    async ({ filter, since, limit = 100 }) => {
      if (process.env.OFFLINE_MODE === 'true') {
        return buildMcpOffline({
          note: 'Offline mode — cannot query live System Log. Connect to a tenant to run log queries.',
          filter,
          events: [],
          totalReturned: 0,
          hasMore: false,
        });
      }
      try {
        const client     = await createOktaClient();
        const sinceParam = since || new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();

        const response = await getLogsWithRetry(client, '/api/v1/logs', {
          params: { filter, since: sinceParam, limit },
        });

        const raw    = Array.isArray(response.data) ? response.data : [];
        const hasMore = (response.headers?.link || '').includes('rel="next"');
        const rateLimitRemaining = parseInt(response.headers?.['x-rate-limit-remaining'] ?? '-1', 10);

        // Return a trimmed-down view of each event so Claude can reason about it
        // without the full 5 KB+ raw object overwhelming the context window.
        const events = raw.map((e) => ({
          published:       e.published,
          eventType:       e.eventType,
          displayMessage:  e.displayMessage,
          severity:        e.severity,
          outcome: {
            result: e.outcome?.result,
            reason: e.outcome?.reason ?? null,
          },
          actor: {
            id:          e.actor?.id,
            displayName: e.actor?.displayName,
            type:        e.actor?.type,
          },
          target: (e.target || []).map((t) => ({
            id:          t.id,
            displayName: t.displayName,
            type:        t.type,
          })),
          client: {
            ipAddress: e.client?.ipAddress ?? null,
            country:   e.client?.geographicalContext?.country ?? null,
            city:      e.client?.geographicalContext?.city ?? null,
          },
          authenticationContext: {
            credentialType:  e.authenticationContext?.credentialType  ?? null,
            authenticatorKey: e.authenticationContext?.authenticatorKey ?? null,
          },
          debugData: e.debugContext?.debugData ?? null,
        }));

        return buildMcpOk({
          filter,
          since:           sinceParam,
          totalReturned:   events.length,
          hasMore,
          rateLimitRemaining,
          note: hasMore
            ? `Only the first ${events.length} matching events are shown. More exist — narrow your filter or reduce the time window to see all results within one page.`
            : null,
          events,
        });
      } catch (err) {
        return buildMcpError(err);
      }
    },
  );
}

module.exports = { registerSyslogTools };
