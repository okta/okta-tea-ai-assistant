'use strict';

const REDACTED = '[REDACTED]';
const MAX_DEPTH = 8;
const MAX_ARRAY_ITEMS = 50;
const MAX_STRING_LENGTH = 6_000;
const MAX_SERIALIZED_LENGTH = 60_000;

// Normalized key names (lowercase, hyphens/spaces → underscores) whose values
// should never be forwarded to an AI provider.
const SENSITIVE_KEYS = new Set([
  'apikey',
  'api_key',
  'apitoken',
  'api_token',
  'authorization',
  'bearertoken',
  'bearer_token',
  'clientsecret',
  'client_secret',
  'cookie',
  'credential',
  'idtoken',
  'id_token',
  'password',
  'privatekey',
  'private_key',
  'refreshtoken',
  'refresh_token',
  'secret',
  'signingkey',
  'signing_key',
  'ssws',
  'accesstoken',
  'access_token',
]);

function maskPersonalData(value) {
  return value
    .replace(/\b[A-Z0-9._%+-]+@([A-Z0-9.-]+\.[A-Z]{2,})\b/gi, '[EMAIL]@$1')
    .replace(/\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b/g, '$1.$2.$3.x');
}

function sanitizeValue(value, options, depth, seen) {
  if (depth > MAX_DEPTH) return '[TRUNCATED]';
  if (typeof value === 'string') {
    const masked = options.maskPersonalData ? maskPersonalData(value) : value;
    return masked.length > MAX_STRING_LENGTH
      ? `${masked.slice(0, MAX_STRING_LENGTH)}…[TRUNCATED]`
      : masked;
  }
  if (value === null || typeof value === 'number' || typeof value === 'boolean') {
    return value;
  }
  if (Array.isArray(value)) {
    return value
      .slice(0, MAX_ARRAY_ITEMS)
      .map((item) => sanitizeValue(item, options, depth + 1, seen));
  }
  if (typeof value === 'bigint') return value.toString();
  if (typeof value === 'undefined') return '[UNDEFINED]';
  if (typeof value === 'symbol') return value.description ?? '[SYMBOL]';
  if (typeof value === 'function') return '[FUNCTION]';
  if (seen.has(value)) return '[CIRCULAR]';
  seen.add(value);
  const output = {};
  for (const [key, item] of Object.entries(value)) {
    const normalizedKey = key.toLowerCase().replace(/[-\s]/g, '_');
    output[key] = SENSITIVE_KEYS.has(normalizedKey)
      ? REDACTED
      : sanitizeValue(item, options, depth + 1, seen);
  }
  return output;
}

/**
 * Sanitize a tool result before forwarding it to an AI provider.
 * Redacts credential-named fields, caps total size, and optionally masks PII.
 * Returns the sanitized value (parse + re-stringify before sending).
 */
function sanitizeToolResult(value, options = {}) {
  const sanitized = sanitizeValue(
    value,
    { maskPersonalData: options.maskPersonalData ?? false },
    0,
    new WeakSet(),
  );
  const serialized = JSON.stringify(sanitized);
  if (serialized.length <= MAX_SERIALIZED_LENGTH) return sanitized;
  return {
    truncated: true,
    content: `${serialized.slice(0, MAX_SERIALIZED_LENGTH)}…[TRUNCATED]`,
  };
}

/**
 * Convert any caught error to a safe ≤500-char string.
 * Strips email addresses and IP addresses that may appear in error messages.
 */
function safeError(error) {
  const message = error instanceof Error ? error.message : 'Unknown error.';
  return maskPersonalData(message).slice(0, 500);
}

module.exports = { sanitizeToolResult, safeError };
