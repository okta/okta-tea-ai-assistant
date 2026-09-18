'use strict';

/**
 * Shared utilities for all MCP resolver tools.
 *
 * ── REMEDIATION CONTRACT ──────────────────────────────────────────────────────
 *
 * Every resolver tool that diagnoses a security finding should include a
 * `remediation` key in its response payload with this shape:
 *
 *   {
 *     // Extracted by the client and emitted as dedicated SSE artifact events.
 *     // The browser renders these verbatim — Claude never reformats them.
 *     // This eliminates generation AND reproduction hallucination for exact
 *     // technical content (HCL syntax, filter strings, attribute names).
 *
 *     terraform:  string | null,   // ready-to-apply HCL
 *     logQueries: Array<{          // System Log queries for verification
 *       description: string,
 *       filter:      string,       // exact Okta System Log filter expression
 *       timeWindow:  string,       // e.g. "last 30 days"
 *       note:        string,       // when/why to use this query
 *     }> | null,
 *
 *     // Passed through to Claude for prose synthesis.
 *     // Claude reads these and narrates them — paraphrase risk is acceptable
 *     // because the content is descriptive, not syntactically exact.
 *
 *     adminConsoleSteps: string[] | null,
 *     riskAssessment: {              // "Change Risk & Blast Radius" section
 *       teaSeverity: 'INFO'|'LOW'|'MODERATE'|'HIGH',  // severity of NOT fixing this (TEA security_impact)
 *       changeRisk:  'INFO'|'LOW'|'MODERATE'|'HIGH',  // risk of applying the fix
 *       summary:              string,
 *       preChangeChecks:      string[],   // verify these before making the change
 *       blastRadius:          string,     // what could break and who is affected
 *       rolloutSteps:         string[],   // safe rollout sequence
 *       postChangeMonitoring: {           // what to watch after making the change
 *         description: string,
 *         logQueries:  Array<{description, filter, timeWindow, note}>,
 *       },
 *       rollback: string,
 *     } | null,
 *     exclusionZoneAdvice: object   | null,  // tool-specific
 *     // ... any other tool-specific prose fields
 *   }
 *
 * ── HOW ARTIFACTS FLOW ────────────────────────────────────────────────────────
 *
 *   MCP tool → full JSON result
 *     │
 *     ├─► client/server.js extractAndEmitArtifacts()
 *     │     ├─► send('terraform_artifact', { toolName, hcl })
 *     │     ├─► send('log_queries_artifact', { toolName, queries })
 *     │     └─► returns result with terraform + logQueries STRIPPED
 *     │
 *     ├─► tool_result SSE event (full JSON, for the UI collapsible)
 *     └─► Claude receives STRIPPED result (no HCL, no filter strings)
 *           └─► Claude narrates risk, steps, zone advice in prose
 *
 * ── ADDING A NEW RESOLVER ─────────────────────────────────────────────────────
 *
 *  1. In your tool handler, build a `remediation` object following the shape above.
 *  2. Pass it into buildMcpOk({ ...liveData, remediation }).
 *  3. The client picks it up automatically — no client changes needed.
 */

/**
 * Wrap a successful tool payload in the MCP content envelope.
 * @param {object} payload   Keys merged into { ok: true, ...payload }
 */
function buildMcpOk(payload) {
  return {
    content: [{
      type: 'text',
      text: JSON.stringify({ ok: true, ...payload }),
    }],
  };
}

/**
 * Wrap an offline-mode tool payload.  Identical envelope to buildMcpOk but
 * always includes offlineMode: true and liveData: null so the client/Claude
 * can branch on those fields without checking the calling context.
 * @param {object} payload   remediation + any static fields for this domain
 */
function buildMcpOffline(payload) {
  return {
    content: [{
      type: 'text',
      text: JSON.stringify({ ok: true, offlineMode: true, liveData: null, ...payload }),
    }],
  };
}

/**
 * Reject a write operation in production mode.
 * The access token itself only carries read scopes in prod, so the Okta API
 * would reject the call anyway — this guard provides a clear error message.
 */
function buildMcpReadOnly() {
  return {
    content: [{
      type: 'text',
      text: JSON.stringify({ ok: false, prodMode: true, error: 'Write operations are disabled in production mode.' }),
    }],
    isError: true,
  };
}

/**
 * Wrap an error in the MCP content envelope.
 * For Axios errors, includes the Okta API response body so callers see the
 * actual rejection reason rather than just "Request failed with status code N".
 * @param {Error} err
 */
function buildMcpError(err) {
  const detail = err.response?.data;
  const error = detail
    ? `${err.message} — ${JSON.stringify(detail)}`
    : err.message;
  return {
    content: [{ type: 'text', text: JSON.stringify({ ok: false, error }) }],
    isError: true,
  };
}

module.exports = { buildMcpOk, buildMcpError, buildMcpOffline, buildMcpReadOnly };
