'use strict';

require('dotenv').config();

// ---------------------------------------------------------------------------
// Run mode
//   npm run dev     → NODE_ENV=development
//   npm run prod    → NODE_ENV=production
//   npm run offline / npm start → NODE_ENV=offline  (no Okta connection)
// ---------------------------------------------------------------------------

const APP_MODE  = process.env.NODE_ENV === 'production' ? 'prod'
                : process.env.NODE_ENV === 'offline'    ? 'offline'
                : 'dev';
const IS_PROD    = APP_MODE === 'prod';
const IS_OFFLINE = APP_MODE === 'offline';

if (IS_OFFLINE) {
  // Signal the MCP subprocess that no Okta calls should be made.
  process.env.OFFLINE_MODE = 'true';
} else {
  if (IS_PROD) {
    // Signal the MCP subprocess to reject all write operations.
    // The login flow will also only request read scopes, so the access token
    // itself cannot authorize writes regardless of application logic.
    process.env.PROD_MODE = 'true';
  }
  // Map mode-specific Okta credentials into the vars the MCP server subprocess expects.
  // .env keys:  OKTA_TEA_DEV_DOMAIN / OKTA_TEA_DEV_CLIENT_ID
  //             OKTA_TEA_PROD_DOMAIN / OKTA_TEA_PROD_CLIENT_ID
  const _modePrefix = `OKTA_TEA_${APP_MODE.toUpperCase()}_`;
  if (process.env[`${_modePrefix}DOMAIN`])    process.env.OKTA_DOMAIN    = process.env[`${_modePrefix}DOMAIN`];
  if (process.env[`${_modePrefix}CLIENT_ID`]) process.env.OKTA_CLIENT_ID = process.env[`${_modePrefix}CLIENT_ID`];
}

const fs   = require('fs');
const os   = require('os');
const path = require('path');
const express = require('express');
const multer    = require('multer');
const pdfParse  = require('pdf-parse');
const { Client } = require('@modelcontextprotocol/sdk/client/index.js');
const { StdioClientTransport } = require('@modelcontextprotocol/sdk/client/stdio.js');

// Handle both ESM-default and direct CommonJS exports from the Anthropic SDK
const _anthropicPkg = require('@anthropic-ai/sdk');
const Anthropic = _anthropicPkg.default ?? _anthropicPkg;

const { sanitizeToolResult, safeError } = require('./sanitize');

// OpenAI SDK — optional; only fails at call time if not installed
let OpenAI = null;
try {
  const _openaiPkg = require('openai');
  OpenAI = _openaiPkg.default ?? _openaiPkg;
} catch (_) { /* openai package not installed */ }

// ---------------------------------------------------------------------------
// Provider configuration
// ---------------------------------------------------------------------------

function getAvailableProviders() {
  const providers = [];

  if (process.env.ANTHROPIC_API_KEY) {
    providers.push({
      id:    'anthropic',
      label: 'Claude (Anthropic)',
      model: process.env.ANTHROPIC_MODEL || 'claude-sonnet-4-6',
    });
  }

  if (process.env.OPENAI_API_KEY) {
    providers.push({
      id:      'openai',
      label:   'GPT-4o (OpenAI)',
      model:   process.env.OPENAI_MODEL || 'gpt-4o',
      apiKey:  process.env.OPENAI_API_KEY,
    });
  }

  if (process.env.OLLAMA_BASE_URL) {
    providers.push({
      id:      'ollama',
      label:   'Ollama (local)',
      model:   process.env.OLLAMA_MODEL || 'llama3.1',
      baseURL: process.env.OLLAMA_BASE_URL,
      apiKey:  'ollama', // OpenAI SDK requires a non-empty string
    });
  }

  return providers;
}

function getProviderConfig(id) {
  return getAvailableProviders().find((p) => p.id === id) ?? null;
}

function getDefaultProviderId() {
  const providers = getAvailableProviders();
  return providers.length > 0 ? providers[0].id : null;
}

// ---------------------------------------------------------------------------
// Token scope inspection
// ---------------------------------------------------------------------------

const TOKEN_STORE_PATH = path.join(os.homedir(), '.okta-tea-ai-assistant', 'tokens.json');

const REQUIRED_READ_SCOPES = [
  'okta.apps.read',
  'okta.logs.read',
  'okta.policies.read',
  'okta.authenticators.read',
  'okta.deviceAssurance.read',
  'okta.idps.read',
  'okta.features.read',
  'okta.securityEventsProviders.read',
  'okta.behaviors.read',
  'okta.logStreams.read',
  'okta.captchas.read',
  'okta.authorizationServers.read',
  'okta.roles.read',
  'okta.apiTokens.read',
];

const REQUIRED_WRITE_SCOPES = [
  'okta.apps.manage',
  'okta.policies.manage',
  'okta.authenticators.manage',
  'okta.threatInsights.manage',
  'okta.networkZones.manage',
  'okta.orgs.manage',
  'okta.deviceAssurance.manage',
  'okta.features.manage',
];

function decodeJwtPayload(token) {
  try {
    const b64 = token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/');
    return JSON.parse(Buffer.from(b64, 'base64').toString('utf8'));
  } catch {
    return null;
  }
}

function logGrantedScopes() {
  let tokens;
  try {
    tokens = JSON.parse(fs.readFileSync(TOKEN_STORE_PATH, 'utf8'));
  } catch {
    console.warn('[okta_login] Could not read token store — scope check skipped.');
    return;
  }

  const payload = decodeJwtPayload(tokens.accessToken);
  if (!payload) {
    console.warn('[okta_login] Could not decode access token — scope check skipped.');
    return;
  }

  const granted = Array.isArray(payload.scp) ? payload.scp : [];
  console.log('\n[okta_login] Access token scopes granted:');
  granted.forEach((s) => console.log(`  ✓  ${s}`));

  const requiredForMode = IS_PROD
    ? REQUIRED_READ_SCOPES
    : [...REQUIRED_READ_SCOPES, ...REQUIRED_WRITE_SCOPES];

  const missing = requiredForMode.filter((s) => !granted.includes(s));
  if (missing.length > 0) {
    console.warn('\n[okta_login] ⚠  Missing required scopes — some tools will return 403:');
    missing.forEach((s) => console.warn(`  ✗  ${s}`));
    console.warn('\n  Fix: Admin Console → Applications → [Your App] → Okta API Scopes tab');
    console.warn('  Grant each missing scope, then run okta_login again to refresh the token.\n');
  } else if (IS_PROD) {
    console.log('\n[okta_login] All read scopes present. Write scopes intentionally omitted in production mode.\n');
  } else {
    console.log('\n[okta_login] All required scopes present.\n');
  }
}

// Per-tool scope requirements — used by /api/tools to show availability in the UI.
const TOOL_SCOPE_MAP = {
  okta_login:                                [],
  okta_get_auth_status:                      [],
  okta_get_threatinsight_config:             ['okta.threatInsights.manage'],
  okta_set_threatinsight_blocking:           ['okta.threatInsights.manage', 'okta.networkZones.manage'],
  okta_list_authenticators:                  ['okta.authenticators.read'],
  okta_update_okta_verify_settings:          ['okta.authenticators.manage'],
  okta_deactivate_weak_authenticator:        ['okta.authenticators.manage'],
  okta_list_authentication_policies:         ['okta.policies.read'],
  okta_update_authentication_policy_rule:    ['okta.policies.manage'],
  okta_get_phishing_resistant_usage:         ['okta.policies.read', 'okta.apps.read'],
  okta_list_admin_console_policy:            ['okta.policies.read'],
  okta_update_admin_console_policy_rule:     ['okta.policies.manage'],
  okta_audit_super_admins:                   ['okta.roles.read'],
  okta_audit_api_tokens:                     ['okta.apiTokens.read'],
  okta_get_attack_protection:                ['okta.policies.read', 'okta.orgs.manage'],
  okta_get_behavior_detection:               ['okta.behaviors.read'],
  okta_get_captcha_config:                   ['okta.captchas.read'],
  okta_list_account_management_policy:       ['okta.policies.read'],
  okta_update_account_management_policy_rule:['okta.policies.manage'],
  okta_audit_default_policies:               ['okta.policies.read'],
  okta_list_device_assurance_policies:       ['okta.deviceAssurance.read'],
  okta_create_device_assurance_policy:       ['okta.deviceAssurance.manage'],
  okta_get_device_integration_config:        ['okta.apps.read'],
  okta_get_identity_proofing_config:         ['okta.apps.read'],
  okta_get_idp_config:                       ['okta.idps.read'],
  okta_get_itp_config:                       ['okta.policies.read'],
  okta_enable_itp_session_protection:        ['okta.policies.manage', 'okta.orgs.manage'],
  okta_enable_itp_universal_logout:          ['okta.policies.manage', 'okta.orgs.manage'],
  okta_get_log_streaming_config:             ['okta.logStreams.read'],
  okta_get_network_zone:                     ['okta.networkZones.manage'],
  okta_list_network_zones:                   ['okta.networkZones.manage'],
  okta_block_countries:                      ['okta.networkZones.manage'],
  okta_list_apps_insecure_grants:            ['okta.apps.read'],
  okta_remove_insecure_grants:               ['okta.apps.manage'],
  okta_list_authorization_servers:           ['okta.authorizationServers.read'],
  okta_list_password_policies:               ['okta.policies.read'],
  okta_update_password_policy:               ['okta.policies.manage'],
  okta_list_session_policies:                ['okta.policies.read'],
  okta_update_session_policy_rule:           ['okta.policies.manage'],
  okta_get_security_general_settings:        ['okta.orgs.manage'],
  okta_enable_suspicious_activity_reporting: ['okta.orgs.manage'],
  okta_enable_suspicious_device_blocking:    ['okta.orgs.manage'],
  okta_configure_security_blocklist:         ['okta.orgs.manage'],
  okta_get_security_notification_emails:     ['okta.orgs.manage'],
  okta_query_syslogs:                        ['okta.logs.read'],
};

// Returns the scopes from the current access token, or null if no valid token.
function getGrantedScopes() {
  try {
    const tokens = JSON.parse(fs.readFileSync(TOKEN_STORE_PATH, 'utf8'));
    if (!tokens?.accessToken) return null;
    const payload = decodeJwtPayload(tokens.accessToken);
    if (!payload) return null;
    if (payload.exp && payload.exp * 1000 < Date.now()) return null;
    return Array.isArray(payload.scp) ? payload.scp : [];
  } catch {
    return null;
  }
}

function logToolError(toolName, resultText) {
  let parsed;
  try { parsed = JSON.parse(resultText); } catch { return; }
  if (!parsed || parsed.ok !== false) return;

  const errMsg = parsed.error || 'unknown error';
  console.error(`\n[MCP tool: ${toolName}] FAILED: ${errMsg}`);

  const code = (errMsg.match(/\b(4\d{2})\b/) || [])[1];
  if (code === '403') {
    console.error('  → 403 Forbidden: The Okta app is missing API scope grants for this operation.');
    console.error('  → Fix: Admin Console → Applications → [Your App] → Okta API Scopes tab');
    console.error('  → Grant the missing scope, save, then run okta_login again.\n');
  } else if (code === '401') {
    console.error('  → 401 Unauthorized: Access token is missing, expired, or invalid.');
    console.error('  → Fix: run okta_login to re-authenticate.\n');
  } else if (code) {
    console.error(`  → HTTP ${code}: check the Okta API response details above.\n`);
  }
}

// ---------------------------------------------------------------------------
// MCP client setup
// ---------------------------------------------------------------------------

let mcpClient = null;
let mcpTools = [];

async function initMCP() {
  const serverPath =
    process.env.MCP_SERVER_PATH ||
    path.resolve(__dirname, './mcp/src/index.js');

  const transport = new StdioClientTransport({
    command: 'node',
    args: [serverPath],
    env: { ...process.env },
  });

  mcpClient = new Client(
    { name: 'okta-mcp-chat', version: '1.0.0' },
    { capabilities: {} }
  );

  await mcpClient.connect(transport);

  const { tools } = await mcpClient.listTools();
  mcpTools = tools;

  console.log(`MCP connected. Tools available: ${tools.map((t) => t.name).join(', ')}`);
}

// ---------------------------------------------------------------------------
// Tool format converters
// ---------------------------------------------------------------------------

function toAnthropicTools(tools) {
  return tools.map((t) => ({
    name: t.name,
    description: t.description || '',
    input_schema: t.inputSchema || { type: 'object', properties: {} },
  }));
}

function toOpenAITools(tools) {
  return tools.map((t) => ({
    type: 'function',
    function: {
      name: t.name,
      description: t.description || '',
      parameters: t.inputSchema || { type: 'object', properties: {} },
    },
  }));
}

// ---------------------------------------------------------------------------
// File parsing helpers
// ---------------------------------------------------------------------------

function htmlToText(html) {
  return html
    .replace(/<style[^>]*>[\s\S]*?<\/style>/gi, '')
    .replace(/<script[^>]*>[\s\S]*?<\/script>/gi, '')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&nbsp;/g, ' ')
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/\s+/g, ' ')
    .trim();
}

function extractSummarySection(html) {
  const clean = html
    .replace(/<script[\s\S]*?<\/script>/gi, '')
    .replace(/<style[\s\S]*?<\/style>/gi, '');

  let m = clean.match(
    /<(?:div|section|article|main|table)\b[^>]+(?:id|class)=["'][^"']*\bsummar[^"']*["'][^>]*>([\s\S]*?)<\/(?:div|section|article|main|table)>/i
  );
  if (m) {
    const content = htmlToText(m[1]).trim();
    if (content) return content.slice(0, 8000);
  }

  const headingRe = /<h[1-4]\b[^>]*>[^<]*\bsummar[^<]*<\/h[1-4]>([\s\S]*?)(?=<h[1-4]\b|$)/gi;
  let match;
  while ((match = headingRe.exec(clean)) !== null) {
    const content = htmlToText(match[1]).trim();
    if (content) return content.slice(0, 8000);
  }

  return htmlToText(clean).slice(0, 8000);
}

async function pdfToText(buffer) {
  const data = await pdfParse(buffer);
  return data.text || '';
}

function extractSummaryFromPlainText(text) {
  const match = /\bsummar(?:y|ies)\b/i.exec(text);
  if (match) {
    const afterHeading = text.indexOf('\n', match.index);
    const content = afterHeading !== -1 ? text.slice(afterHeading + 1).trim() : text.slice(match.index).trim();
    if (content) return content.slice(0, 8000);
  }
  return text.slice(0, 8000);
}

// ---------------------------------------------------------------------------
// Tool labels
// ---------------------------------------------------------------------------

const TOOL_LABELS = {
  okta_get_threatinsight_config:              'Check ThreatInsight Config',
  okta_set_threatinsight_blocking:            'Enable ThreatInsight Blocking',
  okta_list_network_zones:                    'List Network Zones',
  okta_get_network_zone:                      'Get Zone Details',
  okta_block_countries:                       'Block Countries',
  okta_configure_security_blocklist:          'Configure Security Blocklist',
  okta_list_password_policies:                'Audit Password Policies',
  okta_update_password_policy:                'Harden Password Policy',
  okta_list_session_policies:                 'Audit Session Policies',
  okta_update_session_policy_rule:            'Harden Session Policy Rule',
  okta_list_authenticators:                   'Audit Authenticators',
  okta_update_okta_verify_settings:           'Enable Number Challenge',
  okta_get_security_general_settings:         'Audit Security General',
  okta_enable_suspicious_device_blocking:     'Enable Device Blocking',
  okta_enable_suspicious_activity_reporting:  'Enable Activity Reporting',
  okta_list_authentication_policies:          'Audit Authentication Policies',
  okta_update_authentication_policy_rule:     'Update Auth Policy Rule',
  okta_list_admin_console_policy:             'Audit Admin Console Policy',
  okta_update_admin_console_policy_rule:      'Harden Admin Console Policy Rule',
  okta_get_security_notification_emails:      'Audit Notification Emails',
  okta_list_apps_insecure_grants:             'Audit OAuth Grant Types',
  okta_remove_insecure_grants:                'Remove Insecure Grants',
  okta_list_account_management_policy:        'Audit Account Mgmt Policy',
  okta_update_account_management_policy_rule: 'Harden Account Mgmt Policy',
  okta_query_syslogs:                         'Query System Logs',
};

function humanLabel(toolName) {
  return TOOL_LABELS[toolName] ||
    toolName.replace(/^okta_/, '').replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase());
}

// ---------------------------------------------------------------------------
// Express app
// ---------------------------------------------------------------------------

const PORT = parseInt(process.env.PORT || '3000', 10);

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Reject cross-origin POST/PUT/DELETE requests. Browsers always send Origin
// on cross-origin requests and cannot spoof it, so this blocks CSRF from any
// page that isn't the app itself.
app.use((req, res, next) => {
  if (req.method === 'GET' || req.method === 'HEAD') return next();
  const origin = req.headers.origin;
  if (origin !== `http://localhost:${PORT}` && origin !== `http://127.0.0.1:${PORT}`) {
    res.status(403).json({ error: 'Forbidden' });
    return;
  }
  next();
});

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 25 * 1024 * 1024 },
  fileFilter: (_req, file, cb) => {
    const extOk  = /\.(html?|pdf)$/i.test(file.originalname);
    const mimeOk = /^text\/html$|^application\/pdf$|^application\/xhtml\+xml$/.test(file.mimetype);
    const ok = extOk && mimeOk;
    cb(ok ? null : new Error('Only HTML and PDF files are accepted for TEA reports'), ok);
  },
});

// ---------------------------------------------------------------------------
// Conversation state — one history per provider
// ---------------------------------------------------------------------------

const histories = {
  anthropic: [],
  openai:    [],
  ollama:    [],
};

// ---------------------------------------------------------------------------
// Artifact extraction
// ---------------------------------------------------------------------------

// Returns true when a tool result has at least one security finding that warrants
// showing a Terraform remediation snippet. Tools without a summary (e.g.
// ThreatInsight, network zones) are conservatively treated as having findings.
function resultHasFindings(parsed) {
  const s = parsed?.summary;
  if (!s) return true;
  const FINDING_FIELDS = ['totalFindings', 'findingCount', 'flaggedCount', 'oktaVerifyFindings'];
  return FINDING_FIELDS.some((f) => (s[f] ?? 0) > 0);
}

// Replace placeholder values in HCL with live tenant credentials when available.
function populateTerraformPlaceholders(hcl) {
  const domain   = process.env.OKTA_DOMAIN   || '';
  const clientId = process.env.OKTA_CLIENT_ID || '';
  let result = hcl;
  if (domain) {
    const dotIdx = domain.indexOf('.');
    const orgName = dotIdx !== -1 ? domain.slice(0, dotIdx) : domain;
    const baseUrl = dotIdx !== -1 ? domain.slice(dotIdx + 1) : 'okta.com';
    result = result.replace(/<YOUR_OKTA_ORG>/g, orgName);
    // Update base_url line only when the org is not on the standard okta.com domain.
    if (baseUrl !== 'okta.com') {
      result = result.replace(/^(\s*base_url\s*=\s*)"okta\.com"/m, `$1"${baseUrl}"`);
    }
  }
  if (clientId) {
    result = result.replace(/<YOUR_CLIENT_ID>/g, clientId);
  }
  return result;
}

function extractAndEmitArtifacts(send, toolName, resultText, { showTerraform = true, emitLogQueries = true } = {}) {
  let parsed;
  try { parsed = JSON.parse(resultText); } catch { return resultText; }
  if (!parsed?.ok || !parsed?.remediation) return resultText;

  const { terraform, logQueries, adminConsoleSteps, ...restRemediation } = parsed.remediation;
  const hasFindings = resultHasFindings(parsed);

  if (emitLogQueries && Array.isArray(logQueries) && logQueries.length > 0) {
    send('log_queries_available', { toolName, queries: logQueries });
  }

  // Pass terraform and admin console steps to Claude only when the caller wants
  // them shown AND there are actual findings to remediate. When the config is
  // already compliant, strip both so Claude omits the remediation sections.
  const includeRemediation = showTerraform && hasFindings;
  const populatedTerraform = typeof terraform === 'string'
    ? populateTerraformPlaceholders(terraform)
    : terraform;
  const finalRemediation = {
    ...restRemediation,
    ...(includeRemediation && typeof populatedTerraform === 'string' && populatedTerraform.trim() ? { terraform: populatedTerraform } : {}),
    ...(includeRemediation && adminConsoleSteps ? { adminConsoleSteps } : {}),
  };

  return JSON.stringify({ ...parsed, remediation: finalRemediation });
}

// ---------------------------------------------------------------------------
// Shared MCP tool-call helper
// ---------------------------------------------------------------------------

async function callMCPTool(send, toolId, toolName, toolInput, artifactOpts) {
  send('tool_call', { id: toolId, name: toolName, input: toolInput });

  let fullResultText;
  try {
    if (!mcpClient) throw new Error('MCP server is not connected');
    const result = await mcpClient.callTool({ name: toolName, arguments: toolInput });
    fullResultText = result.content?.[0]?.text ?? JSON.stringify(result, null, 2);
  } catch (err) {
    console.error(`[MCP tool: ${toolName}] callTool threw: ${err.message}`);
    fullResultText = JSON.stringify({ ok: false, error: safeError(err) });
  }

  logToolError(toolName, fullResultText);

  if (toolName === 'okta_login') {
    try { const r = JSON.parse(fullResultText); if (r.ok !== false) logGrantedScopes(); } catch { /* ignore */ }
  }

  // Sanitize before forwarding to the AI provider: redacts credential-named fields
  // and caps payload size. fullResultText stays raw for logging and the browser UI.
  let sanitizedText;
  try {
    sanitizedText = JSON.stringify(sanitizeToolResult(JSON.parse(fullResultText)));
  } catch {
    sanitizedText = JSON.stringify(sanitizeToolResult(fullResultText));
  }

  const resultForModel = extractAndEmitArtifacts(send, toolName, sanitizedText, artifactOpts);
  send('tool_result', { id: toolId, name: toolName, result: fullResultText });

  return { fullResultText, resultForModel };
}

// ---------------------------------------------------------------------------
// Anthropic agentic loop
// ---------------------------------------------------------------------------

async function runAnthropicLoop({ apiKey, model, systemPrompt, messages, send, artifactOpts, toolList = mcpTools }) {
  const client = new Anthropic({ apiKey });
  const tools = toAnthropicTools(toolList);

  while (true) {
    const stream = client.messages.stream({
      model,
      max_tokens: 16000,
      thinking: { type: 'adaptive' },
      system: systemPrompt,
      messages,
      ...(tools.length > 0 && { tools }),
    });

    stream.on('text', (text) => send('text_delta', { text }));

    const response = await stream.finalMessage();

    if (response.stop_reason === 'tool_use') {
      messages.push({ role: 'assistant', content: response.content });
      const toolResults = [];

      for (const block of response.content) {
        if (block.type !== 'tool_use') continue;
        const { resultForModel } = await callMCPTool(send, block.id, block.name, block.input, artifactOpts);
        toolResults.push({ type: 'tool_result', tool_use_id: block.id, content: resultForModel });
      }

      messages.push({ role: 'user', content: toolResults });
    } else {
      messages.push({ role: 'assistant', content: response.content });
      return messages;
    }
  }
}

// ---------------------------------------------------------------------------
// OpenAI-compatible agentic loop  (OpenAI and Ollama)
// ---------------------------------------------------------------------------

async function runOpenAICompatibleLoop({ apiKey, baseURL, model, systemPrompt, messages, send, artifactOpts, toolList = mcpTools }) {
  if (!OpenAI) {
    throw new Error(
      'The "openai" npm package is not installed. Run: npm install openai',
    );
  }

  const client = new OpenAI({ apiKey, ...(baseURL && { baseURL }) });
  const tools = toOpenAITools(toolList);

  while (true) {
    const stream = await client.chat.completions.create({
      model,
      messages: [{ role: 'system', content: systemPrompt }, ...messages],
      max_tokens: 16000,
      ...(tools.length > 0 && { tools, tool_choice: 'auto' }),
      stream: true,
    });

    let textContent = '';
    const toolCallsAccum = [];
    let finishReason = null;

    for await (const chunk of stream) {
      const choice = chunk.choices[0];
      if (!choice) continue;
      if (choice.finish_reason) finishReason = choice.finish_reason;

      const delta = choice.delta;

      if (delta.content) {
        textContent += delta.content;
        send('text_delta', { text: delta.content });
      }

      if (delta.tool_calls) {
        for (const tc of delta.tool_calls) {
          if (!toolCallsAccum[tc.index]) {
            toolCallsAccum[tc.index] = { id: '', name: '', argParts: [] };
          }
          const acc = toolCallsAccum[tc.index];
          if (tc.id) acc.id += tc.id;
          if (tc.function?.name) acc.name += tc.function.name;
          if (tc.function?.arguments) acc.argParts.push(tc.function.arguments);
        }
      }
    }

    if (finishReason === 'tool_calls' && toolCallsAccum.length > 0) {
      const toolCalls = toolCallsAccum.map((acc) => ({
        id:       acc.id,
        type:     'function',
        function: { name: acc.name, arguments: acc.argParts.join('') },
      }));

      messages.push({ role: 'assistant', content: textContent || null, tool_calls: toolCalls });

      for (const tc of toolCalls) {
        let toolInput;
        try { toolInput = JSON.parse(tc.function.arguments); } catch { toolInput = {}; }

        const { resultForModel } = await callMCPTool(send, tc.id, tc.function.name, toolInput, artifactOpts);
        messages.push({ role: 'tool', tool_call_id: tc.id, content: resultForModel });
      }
    } else {
      messages.push({ role: 'assistant', content: textContent });
      return messages;
    }
  }
}

// ---------------------------------------------------------------------------
// Dispatch helper — picks loop by provider id
// ---------------------------------------------------------------------------

async function runAILoop(providerId, { systemPrompt, messages, send, artifactOpts, toolList = mcpTools }) {
  const cfg = getProviderConfig(providerId);
  if (!cfg) throw new Error(`Provider "${providerId}" is not configured.`);

  if (providerId === 'anthropic') {
    return runAnthropicLoop({
      apiKey: process.env.ANTHROPIC_API_KEY,
      model:  cfg.model,
      systemPrompt,
      messages,
      send,
      artifactOpts,
      toolList,
    });
  }

  return runOpenAICompatibleLoop({
    apiKey:  cfg.apiKey,
    baseURL: cfg.baseURL,
    model:   cfg.model,
    systemPrompt,
    messages,
    send,
    artifactOpts,
    toolList,
  });
}

// ---------------------------------------------------------------------------
// System prompts
// ---------------------------------------------------------------------------

const SYSTEM_PROMPT = `You are an Okta security assistant with direct access to tools that can inspect and configure an Okta tenant. Help administrators understand and improve their security posture.

Guidelines:
- When asked about a security threat (credential stuffing, brute force, MFA bypass, phishing, etc.), immediately use your tools to inspect the current configuration before making recommendations
- Explain findings in plain English — avoid jargon, define acronyms on first use
- For write operations (enabling ThreatInsight blocking, adding network zone blocklists), always describe what the change will do and its impact, then ask the user to confirm before applying
- If a tool returns an authentication error, advise the user to call the okta_login tool first
- When showing data, summarise the key insight — don't just dump raw JSON at the user
- Be concise but thorough; use bullet points for lists of findings

Available capabilities: ThreatInsight configuration, network zone management (IP/country blocklists), password policy hardening, global session policy management, Okta authenticator audit (Okta Verify Number Challenge, SMS/Phone MFA active, Security Questions as MFA), Security General settings (unknown device blocking, suspicious activity reporting), Security Notification Email audit (suspicious activity email, new device, password change, factor enrollment notifications), Admin Console sign-on policy audit and hardening (MFA enforcement, re-authentication caps, phishing-resistant possession constraints via API), authentication policy audit and hardening (MFA enforcement, phishing-resistant possession constraints via API — use okta_update_authentication_policy_rule), OAuth grant type audit and remediation (remove deprecated Password/Implicit grants from apps), Account Management Policy audit and hardening (phishing-resistant possession factors for self-service password reset), phishing-resistant MFA usage analysis (WebAuthn/FastPass usage via okta_get_phishing_resistant_usage), ad-hoc System Log queries with any SCIM filter (okta_query_syslogs — use this for investigating specific users, failed sign-ins, admin changes, policy updates, or any other log question), and Okta authentication.

Artifact rendering note:
Tool results include a "remediation" object with these fields:
  - remediation.terraform          → present only when findings exist; output it verbatim in a \`\`\`hcl code block under ## Terraform Fix
  - remediation.logQueries         → NOT shown by default; tell the user to click "Show log queries" to view filter strings; do NOT paste filter strings in your text
  - adminConsoleSteps, riskAssessment (Change Risk & Blast Radius), exclusionZoneAdvice → narrate these in your response

Conditional sections rule: Only include ## Terraform Fix, ## How to Fix It — Okta Admin Console, and ## Apply Fix Automatically when the tool result contains at least one finding. When the audit is fully compliant (no findings), omit all three sections and end the response with "✅ No action required — configuration is compliant."

ThreatInsight response format:
Whenever you present ThreatInsight findings, structure your response with these sections (## headings) IN THIS EXACT ORDER:

## Current Status
Current action mode (none / audit / block), number of excluded zones, 7-day detection volume.

## Exclusion Zone Recommendations
From remediation.exclusionZoneAdvice: why it matters, any detectedCandidatesNotYetExcluded, noCandidatesNote if present.

## Relevant Logs — Tell the user to click "Show log queries" below the result; do not paste filter strings.

## Change Risk & Blast Radius
From remediation.riskAssessment: teaSeverity (how bad it is not to fix this) and changeRisk (how risky the fix itself is), preChangeChecks (what to verify before applying), blastRadius (what could break and who is affected), rolloutSteps (safe rollout sequence), postChangeMonitoring (what to watch after making the change), and rollback procedure.

## How to Fix It — Okta Admin Console
Numbered list from remediation.adminConsoleSteps. Reproduce each step in full.

## Terraform Fix — Output remediation.terraform verbatim in a \`\`\`hcl code block; provider setup at https://developer.okta.com/docs/guides/terraform-enable-org-access/main/.

## Apply Fix Automatically
Offer to apply the recommended change directly using your tools. State exactly what the tool call will do (e.g., enable blocking mode, add exclusion zones), then ask the user to confirm before proceeding.

Network zone response format:
When presenting network zone findings or post-action summaries, structure your response with these sections (## headings) IN THIS EXACT ORDER:

## Current Status
Summary of the current network zone configuration and any detected issues.

## Relevant Logs — Tell the user to click "Show log queries" below the result; do not paste filter strings.

## Change Risk & Blast Radius
From remediation.riskAssessment: teaSeverity (how bad it is not to fix this) and changeRisk (how risky the fix itself is), preChangeChecks (what to verify before applying), blastRadius (what could break and who is affected), rolloutSteps (safe rollout sequence), postChangeMonitoring (what to watch after making the change), and rollback procedure.

## How to Fix It — Okta Admin Console
Numbered list from remediation.adminConsoleSteps. Reproduce each step in full.

## Terraform Fix — Output remediation.terraform verbatim in a \`\`\`hcl code block; provider setup at https://developer.okta.com/docs/guides/terraform-enable-org-access/main/.

## Apply Fix Automatically
Offer to apply the recommended change directly using your tools. State exactly what the tool call will do, then ask the user to confirm before proceeding.

Password policy, session policy, authenticator, and Security General response format:
When presenting findings from okta_list_password_policies, okta_list_session_policies, okta_list_authenticators, okta_get_security_general_settings, okta_list_admin_console_policy, okta_list_account_management_policy, or any of their write counterparts, structure your response IN THIS EXACT ORDER:

## Current Status
Password policies: total policies, total findings, high-severity count, and summary of current settings (minLength, lockout, brute force, etc.).
Session policies: total rules audited, how many lack MFA, how many exceed the recommended session lifetime or idle timeout.
Authenticators: total findings, highFindings count, and the status of all five checks: (1) oktaVerifyNumberChallenge — ENABLED or DISABLED, (2) webAuthnActive — whether phishing-resistant hardware factor is available (HIGH if absent), (3) fastPassActive — whether FastPass passwordless is enabled (MODERATE if absent), (4) phoneActive — whether SMS/voice call MFA is active and should be removed (HIGH), (5) securityQuestionActive — whether Security Questions MFA is active and should be removed (MODERATE).
Security General: whether "Block suspicious password attempts from unknown devices" and "Report suspicious activity via email" are enabled. If the API did not return status, say so and direct to manual verification.
Account Management Policy: whether phishing-resistant possession factors are required for self-service password reset and recovery flows.

## Key Findings
List each finding from the audit — one line each. Include: severity (HIGH/MODERATE/LOW/INFO), affected policy or rule name, and what is wrong.
For write tool results: summarise what was changed and what the before/after finding counts were. List any remaining open findings.

## Relevant Logs — Tell the user to click "Show log queries"; call out the most relevant query type for the change (e.g. lockout events for brute-force changes). Do not paste filter strings.

## Change Risk & Blast Radius
From remediation.riskAssessment: teaSeverity (finding severity) and changeRisk (risk of applying the fix), preChangeChecks (verify before applying), blastRadius (who is affected and what could break), rolloutSteps, postChangeMonitoring, and rollback. Keep this concise — 3–5 bullet points.

## How to Fix It — Okta Admin Console
Numbered list from remediation.adminConsoleSteps. Reproduce each step in full.
For Security General: adminConsoleSteps is an object with two sub-arrays (unknownDeviceBlocking and suspiciousActivityReporting) — present both labelled sections.
For Authenticators: adminConsoleSteps and riskAssessment are objects with sub-sections (oktaVerify, webAuthn, fastPass, phone, securityQuestion). Present webAuthn and fastPass sections when those factors are ABSENT (they should be enabled). Present phone and securityQuestion sections when those factors are ACTIVE (they should be removed). Null sections mean no action needed for that check.

## Terraform Fix (where applicable) — Output remediation.terraform verbatim in a \`\`\`hcl code block; provider setup at https://developer.okta.com/docs/guides/terraform-enable-org-access/main/. If Terraform support is limited (e.g. Security General), say so and recommend the Admin Console.

## Apply Fix Automatically
Offer to apply the fix using the appropriate write tool. State exactly what the call will do, then ask for confirmation:
- Password policy gaps → okta_update_password_policy (provide the policyId and only the fields that need changing)
- Session policy rule gaps → okta_update_session_policy_rule (provide policyId and ruleId)
- Okta Verify Number Challenge → okta_update_okta_verify_settings with numberChallenge: "ENABLED"
- Unknown device blocking → okta_enable_suspicious_device_blocking
- Suspicious activity reporting → okta_enable_suspicious_activity_reporting
- Admin Console policy gaps (MFA, reauth, phishing-resistant) → okta_update_admin_console_policy_rule (provide policyId and ruleId from the audit; supports factorMode, reauthenticateInMinutes, and requirePhishingResistantPossession in one call)
- Authentication policy gaps (MFA, phishing-resistant) → okta_update_authentication_policy_rule (provide policyId and ruleId from okta_list_authentication_policies)
- Account Management Policy gaps → okta_update_account_management_policy_rule (provide policyId and ruleId from the audit)
When multiple policies have findings, offer to fix them one at a time and confirm each before proceeding.

Admin Console policy response format:
When presenting findings from okta_list_admin_console_policy or okta_update_admin_console_policy_rule, structure your response IN THIS EXACT ORDER:

## Current Status
App label and policy name. Total rules audited, number with findings, high-severity count.
State clearly whether admins can access the console without MFA (ADMIN_CONSOLE_NO_MFA) and whether sessions never expire (ADMIN_CONSOLE_REAUTH_NEVER).

## Key Findings
One line per finding — include severity (HIGH/MODERATE), rule name, and what is wrong.
For write tool results: summarise what changed, before/after finding counts, and any remaining open findings.

## Relevant Logs — Tell the user to click "Show log queries"; call out that "user.session.access_admin_app" is the key verification signal after enforcing 2FA. Do not paste filter strings.

## Change Risk & Blast Radius
From remediation.riskAssessment: teaSeverity (finding severity) and changeRisk (risk of applying the fix), preChangeChecks (verify enrollment before applying), blastRadius (who is affected), rolloutSteps, postChangeMonitoring, and rollback. Keep to 3–4 bullet points.

## How to Fix It — Okta Admin Console
Numbered list from remediation.adminConsoleSteps. Reproduce each step in full.

## Terraform Fix — Output remediation.terraform verbatim in a \`\`\`hcl code block; provider setup at https://developer.okta.com/docs/guides/terraform-enable-org-access/main/.

## Apply Fix Automatically
Offer to call okta_update_admin_console_policy_rule with the policyId and ruleId from the audit.
State exactly what will change: factorMode: "2FA", reauthenticateInMinutes: 240, and/or requirePhishingResistantPossession: true.
Warn: confirm all admin users have MFA enrolled before setting factorMode to "2FA" — admins without a factor will be locked out.
Warn: confirm all admins have Okta Verify or WebAuthn enrolled before setting requirePhishingResistantPossession: true.
Ask for confirmation before proceeding.

Phishing-resistant usage response format:
When presenting results from okta_get_phishing_resistant_usage, structure your response as:

## Phishing-Resistant MFA Usage 
Lead with the headline numbers: total MFA successes, phishing-resistant count, and percentage.

## Breakdown by Factor
Present the byFactor breakdown as a table or bullet list, ordered from most to least used.
Call out WebAuthn and FastPass counts specifically.

## Interpretation
Use the interpretation field from the result. Add context about what the numbers mean:
- ≥80%: strong adoption, note which policies are enforcing it
- 40–79%: moderate adoption, identify coverage gaps
- <40%: low adoption, recommend enabling FastPass on managed devices and adding phishingResistant: REQUIRED to Authentication Policies

## Next Steps (if adoption is low)
- Run okta_list_authenticators to check whether WebAuthn and FastPass are active
- Run okta_list_authentication_policies to see which policies currently require phishing-resistant factors
- Suggest enabling FastPass (Security > Authenticators > Okta Verify > Enable FastPass)
- Suggest adding WebAuthn to Authentication Policy rules`;

const TEA_SYSTEM_PROMPT = `You are an Okta tenant admin reviewing a Threat Exposure Assessment (TEA) report summary.

The summary section of a TEA report has been provided. Your task:

1. List every distinct security finding or recommendation as a numbered list — one line each
2. For each finding include: severity (Critical/High/Medium/Low if shown) and the Okta feature it affects (e.g. ThreatInsight, Network Zones, MFA, Session Policies)
3. For any finding you can verify with your available tools, check the current state NOW and mark it:
   - ✅ ALREADY FIXED
   - ⚠️ STILL AT RISK
   - ❓ CANNOT VERIFY

Output format:

**TEA Findings**
1. [Finding] — Severity: [level] — Feature: [area]
2. ...

Then for each finding you checked with tools:
**[Finding title]** — ✅/⚠️/❓ [status]
[1–2 sentence current-state explanation from tool result]

Keep findings concise. Do NOT reproduce the full report text.

Run the following checks automatically without waiting to be asked:
- ThreatInsight: okta_get_threatinsight_config
- Network zones: okta_list_network_zones
- Password policies: okta_list_password_policies
- Session policies (MFA, session lifetime, idle timeout, persistent cookies): okta_list_session_policies
- Authenticators (Number Challenge, phishing-resistant factors): okta_list_authenticators
- Security General (unknown device blocking, suspicious activity reporting): okta_get_security_general_settings
- Security Notification Emails: okta_get_security_notification_emails
- Admin Console policy: okta_list_admin_console_policy
- OAuth grant types (Password/Implicit): okta_list_apps_insecure_grants
- Account Management Policy (phishing-resistant factors for self-service recovery): okta_list_account_management_policy
- Identity Threat Protection (ITP Session Protection, Universal Logout, Workflow detections): okta_get_itp_config
- Device Assurance policies (jailbreak, disk encryption, OS version, screen lock): okta_list_device_assurance_policies
- Device Integration and EDR (endpoint security provider, auth policies using device signals): okta_get_device_integration_config
- Identity Proofing (IDV provider configured, enrollment/recovery policies require verification): okta_get_identity_proofing_config
- Behavior Detection (New Device, New IP, Velocity rules active): okta_get_behavior_detection
- Log Streaming to SIEM (at least one active log stream): okta_get_log_streaming_config
- CAPTCHA (configured and assigned to self-service flows): okta_get_captcha_config
- Authorization Servers (default audiences, unused servers, access policies): okta_list_authorization_servers
- Attack Protection (breached password detection, username enumeration protection): okta_get_attack_protection
- Authentication Policies (catch-all DENY rule, MFA on all rules, unused policies): okta_list_authentication_policies
- Identity Provider auto-link restrictions (accountLink.action on each IdP): okta_get_idp_config
- Default policy names (Appendix A — policies still using Okta default names): okta_audit_default_policies

Cross-reference each tool result against the TEA findings list to mark them ✅ ALREADY FIXED, ⚠️ STILL AT RISK, or ❓ CANNOT VERIFY.

Artifact rendering note:
Tool results include a "remediation" object. Use the following fields in your analysis:
- adminConsoleSteps, riskAssessment (Change Risk & Blast Radius), and exclusionZoneAdvice: include these in your analysis as-is.
- For Security General adminConsoleSteps: it is an object with unknownDeviceBlocking and suspiciousActivityReporting sub-arrays — present both.
- Do NOT mention log queries, log filter strings, or "Show log queries" — those are not available in the TEA review view.`;

// ---------------------------------------------------------------------------
// Offline mode system prompts  (no live Okta connection)
// ---------------------------------------------------------------------------

const OFFLINE_SYSTEM_PROMPT = `You are an Okta security assistant running in offline mode. You have access to tools that return pre-built remediation guidance — Terraform HCL, Admin Console steps, log queries, and risk assessments — but there is no live Okta tenant connection available. Live tenant data cannot be retrieved or verified.

Guidelines:
- When asked about an Okta security topic, call the appropriate tool to retrieve static remediation guidance for that domain
- All tool results will include offlineMode: true and liveData: null — this is expected
- Present the Terraform, Admin Console steps, log queries, and risk assessment from the tool result exactly as you would in online mode
- Do NOT offer to "Apply Fix Automatically" — write operations are disabled in offline mode
- Do NOT suggest running okta_login — authentication is not available offline
- Explain findings in plain English; define acronyms on first use
- Be concise but thorough; use bullet points for lists of findings

Artifact rendering note (same as online mode):
Tool results include a "remediation" object with these fields:
  - remediation.terraform          → output it verbatim in a \`\`\`hcl code block under ## Terraform Fix
  - remediation.logQueries         → NOT shown by default; tell the user to click "Show log queries" to view filter strings
  - adminConsoleSteps, riskAssessment (Change Risk & Blast Radius) → narrate these in your response

Conditional sections rule: In offline mode there is no live compliance check. Always present ## Terraform Fix, ## How to Fix It — Okta Admin Console, ## Change Risk & Blast Radius, and ## Relevant Logs sections — even without confirmed findings — since the user is reviewing the guidance, not their live tenant.

Offline mode note: Remind the user once (at the start of your first response) that you are running in offline mode and live tenant data is not available. After that first reminder, do not repeat it.`;

const OFFLINE_TEA_SYSTEM_PROMPT = `You are an Okta tenant admin reviewing a Threat Exposure Assessment (TEA) report summary in offline mode. There is no live Okta tenant connection available, so findings cannot be verified against the current configuration.

Your task:

1. List every distinct security finding or recommendation as a numbered list — one line each
2. For each finding include: severity (Critical/High/Medium/Low if shown) and the Okta feature it affects
3. Mark every finding ❓ CANNOT VERIFY (Offline Mode) — live tenant checks are not available

For each finding you CAN match to a tool, call the tool anyway to retrieve remediation guidance:
- ThreatInsight: okta_get_threatinsight_config
- Network zones: okta_list_network_zones
- Password policies: okta_list_password_policies
- Session policies: okta_list_session_policies
- Authenticators: okta_list_authenticators
- Security General: okta_get_security_general_settings
- Security Notification Emails: okta_get_security_notification_emails
- Admin Console policy: okta_list_admin_console_policy
- OAuth grant types: okta_list_apps_insecure_grants
- Account Management Policy: okta_list_account_management_policy
- Identity Threat Protection: okta_get_itp_config
- Device Assurance policies: okta_list_device_assurance_policies
- Device Integration and EDR: okta_get_device_integration_config
- Identity Proofing: okta_get_identity_proofing_config
- Behavior Detection: okta_get_behavior_detection
- Log Streaming: okta_get_log_streaming_config
- CAPTCHA: okta_get_captcha_config
- Authorization Servers: okta_list_authorization_servers
- Attack Protection: okta_get_attack_protection
- Authentication Policies: okta_list_authentication_policies
- Identity Provider config: okta_get_idp_config
- Default policy names: okta_audit_default_policies

Tool results will contain offlineMode: true. Use adminConsoleSteps and riskAssessment (Change Risk & Blast Radius) from each result to present remediation guidance per finding. Do NOT mention log queries or filter strings.

Output format:

**TEA Findings (Offline Review)**
1. [Finding] — Severity: [level] — Feature: [area] — ❓ CANNOT VERIFY (Offline Mode)
2. ...

Then for each domain where a tool was called:
**[Domain] — Remediation Guidance**
[Admin Console steps and risk assessment from the tool result]`;

// ---------------------------------------------------------------------------
// Chat endpoint  (POST /api/chat)
// ---------------------------------------------------------------------------

app.post('/api/chat', async (req, res) => {
  const { message, provider: reqProvider } = req.body;
  if (!message || !message.trim()) {
    return res.status(400).json({ error: 'message is required' });
  }

  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.flushHeaders();

  function send(event, data) {
    res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
  }

  const providerId = reqProvider || getDefaultProviderId();

  if (!providerId) {
    send('error', { message: 'No AI provider is configured. Set ANTHROPIC_API_KEY, OPENAI_API_KEY, or OLLAMA_BASE_URL in your .env file.' });
    res.end();
    return;
  }

  if (!getProviderConfig(providerId)) {
    send('error', { message: `Provider "${providerId}" is not configured. Check your .env file.` });
    res.end();
    return;
  }

  const history = histories[providerId] ?? [];
  const messages = [...history, { role: 'user', content: message.trim() }];

  try {
    // In prod mode, exclude write tools so the AI never offers to mutate the tenant.
    // Defense-in-depth: the MCP handlers also reject writes, and the access token
    // only carries read scopes, but filtering here prevents the AI from even trying.
    const chatTools = IS_PROD
      ? mcpTools.filter(t => !/^okta_(update|activate|deactivate|create|enable|disable|block|remove|configure|set)_/.test(t.name))
      : mcpTools;
    const finalMessages = await runAILoop(providerId, {
      systemPrompt: IS_OFFLINE ? OFFLINE_SYSTEM_PROMPT : SYSTEM_PROMPT,
      messages,
      send,
      artifactOpts: { showTerraform: true, emitLogQueries: !IS_OFFLINE },
      toolList: chatTools,
    });

    histories[providerId] = finalMessages;
    send('done', {});
  } catch (err) {
    console.error('Chat error:', err);
    send('error', { message: err.message || 'Unexpected error.' });
  } finally {
    res.end();
  }
});

// ---------------------------------------------------------------------------
// TEA report review endpoint  (POST /api/tea-review)
// ---------------------------------------------------------------------------

app.post('/api/tea-review', upload.single('file'), async (req, res) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.flushHeaders();

  function send(event, data) {
    res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
  }

  const providerId = (req.body && req.body.provider) || getDefaultProviderId();

  if (!providerId || !getProviderConfig(providerId)) {
    send('error', { message: 'No AI provider is configured. Check your .env file.' });
    res.end();
    return;
  }

  let summaryText;
  try {
    if (req.file) {
      const ext = path.extname(req.file.originalname).toLowerCase();
      if (ext === '.pdf') {
        const rawText = await pdfToText(req.file.buffer);
        if (!rawText.trim()) {
          send('error', { message: 'No text could be extracted from the PDF. The file may contain scanned images. Please use the HTML version of the TEA report if available.' });
          res.end();
          return;
        }
        summaryText = extractSummaryFromPlainText(rawText);
      } else {
        summaryText = extractSummarySection(req.file.buffer.toString('utf8'));
      }
    } else if (req.body && req.body.filePath) {
      const filePath = path.resolve(req.body.filePath.trim());
      const allowedDir = path.resolve(process.env.TEA_REPORT_DIR || os.homedir());
      if (!filePath.startsWith(allowedDir + path.sep) && filePath !== allowedDir) {
        send('error', { message: 'File path is outside the allowed directory.' });
        res.end();
        return;
      }
      const ext = path.extname(filePath).toLowerCase();
      if (ext !== '.html' && ext !== '.htm' && ext !== '.pdf') {
        send('error', { message: 'Only HTML and PDF files are supported.' });
        res.end();
        return;
      }
      if (!fs.existsSync(filePath)) {
        send('error', { message: `File not found: ${filePath}` });
        res.end();
        return;
      }
      if (ext === '.pdf') {
        const rawText = await pdfToText(fs.readFileSync(filePath));
        if (!rawText.trim()) {
          send('error', { message: 'No text could be extracted from the PDF. The file may contain scanned images. Please use the HTML version of the TEA report if available.' });
          res.end();
          return;
        }
        summaryText = extractSummaryFromPlainText(rawText);
      } else {
        summaryText = extractSummarySection(fs.readFileSync(filePath, 'utf8'));
      }
    } else {
      send('error', { message: 'Provide a file upload or a filePath in the request body.' });
      res.end();
      return;
    }
  } catch (err) {
    send('error', { message: `Failed to parse report: ${err.message}` });
    res.end();
    return;
  }

  if (!summaryText || !summaryText.trim()) {
    send('error', { message: 'No content could be extracted from the report.' });
    res.end();
    return;
  }

  const userMessage = `I have uploaded an Okta Threat Exposure Assessment (TEA) report. Below is the summary section extracted from the HTML file.

--- TEA SUMMARY ---
${summaryText}
--- END SUMMARY ---

Please list each finding concisely and check the current Okta configuration for findings you can verify with your tools.`;

  // TEA review uses its own isolated message list; does not draw from history
  const messages = [{ role: 'user', content: userMessage }];

  // Restrict the TEA review loop to read-only tools.  Injected content in a
  // crafted report must not be able to trigger write operations against the
  // Okta Management API without explicit user intent.
  const teaReadOnlyTools = mcpTools.filter(t => /^okta_(get|list)_/.test(t.name));

  try {
    const finalMessages = await runAILoop(providerId, {
      systemPrompt: IS_OFFLINE ? OFFLINE_TEA_SYSTEM_PROMPT : TEA_SYSTEM_PROMPT,
      messages,
      send,
      artifactOpts: { showTerraform: IS_OFFLINE, emitLogQueries: false },
      toolList: teaReadOnlyTools,
    });

    // Append TEA turn to main chat history so the user can continue chatting
    const history = histories[providerId] ?? [];
    histories[providerId] = [
      ...history,
      { role: 'user', content: userMessage },
      finalMessages[finalMessages.length - 1], // last assistant turn
    ];

    const resolverTools = mcpTools
      .filter((t) => !['okta_login', 'okta_get_auth_status'].includes(t.name))
      .map((t) => ({
        name:        t.name,
        label:       humanLabel(t.name),
        description: (t.description || '').slice(0, 120),
      }));

    if (resolverTools.length > 0) {
      send('resolver_options', { tools: resolverTools });
    }

    send('done', {});
  } catch (err) {
    console.error('TEA review error:', err);
    send('error', { message: err.message || 'Unexpected error.' });
  } finally {
    res.end();
  }
});

// ---------------------------------------------------------------------------
// Utility endpoints
// ---------------------------------------------------------------------------

app.post('/api/clear', (_req, res) => {
  Object.keys(histories).forEach((k) => { histories[k] = []; });
  res.json({ ok: true });
});

app.get('/api/status', (_req, res) => {
  res.json({
    connected: IS_OFFLINE ? true : mcpClient !== null,
    tools: mcpTools.map((t) => t.name),
    mode: APP_MODE,
    offline: IS_OFFLINE,
    debug: process.env.DEBUG === 'true',
  });
});

app.get('/api/providers', (_req, res) => {
  res.json(getAvailableProviders().map(({ id, label, model }) => ({ id, label, model })));
});

app.get('/api/auth-status', (_req, res) => {
  if (IS_OFFLINE) {
    return res.json({ loggedIn: false, expired: false, domain: '', offlineMode: true });
  }

  const domain = process.env.OKTA_DOMAIN || '';
  let loggedIn = false;
  let expired  = false;

  try {
    const tokens = JSON.parse(fs.readFileSync(TOKEN_STORE_PATH, 'utf8'));
    if (tokens && tokens.accessToken) {
      const payload = decodeJwtPayload(tokens.accessToken);
      if (payload) {
        if (payload.exp && payload.exp * 1000 < Date.now() + 5 * 60 * 1000) {
          expired = true;
        } else {
          loggedIn = true;
        }
      }
    }
  } catch { /* no token store yet */ }

  res.json({ loggedIn, expired, domain });
});

app.get('/api/tools', (_req, res) => {
  const grantedScopes = IS_OFFLINE ? null : getGrantedScopes();
  const loggedIn = grantedScopes !== null;

  // First sentence of a tool description — enough for a drawer entry.
  function shortDesc(desc) {
    const s = (desc || '').split(/\.\s+|—/)[0].trim();
    return s.length > 120 ? s.slice(0, 117) + '…' : s;
  }

  const tools = mcpTools.map((t) => {
    const required = TOOL_SCOPE_MAP[t.name] || [];
    const isAuthTool = t.name === 'okta_login' || t.name === 'okta_get_auth_status';
    const missing = (!isAuthTool && loggedIn)
      ? required.filter((s) => !grantedScopes.includes(s))
      : [];

    let status;
    if (isAuthTool)           status = 'auth';
    else if (IS_OFFLINE)      status = 'offline';
    else if (!loggedIn)       status = 'auth_required';
    else if (missing.length)  status = 'missing_scopes';
    else                      status = 'available';

    return {
      name:        t.name,
      label:       humanLabel(t.name),
      description: shortDesc(t.description),
      required,
      missing,
      status,
    };
  });

  // okta_login always first, then sort: available → auth → offline/auth_required → missing_scopes
  const ORDER = { auth: 0, available: 1, offline: 2, auth_required: 2, missing_scopes: 3 };
  tools.sort((a, b) => {
    if (a.name === 'okta_login') return -1;
    if (b.name === 'okta_login') return 1;
    return (ORDER[a.status] ?? 4) - (ORDER[b.status] ?? 4) || a.label.localeCompare(b.label);
  });

  res.json({ tools, loggedIn, grantedScopes: grantedScopes || [], offline: IS_OFFLINE });
});

app.post('/api/login', async (req, res) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.flushHeaders();

  function send(event, data) {
    res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
  }

  try {
    if (!mcpClient) throw new Error('MCP server is not connected');
    const mcpResult = await mcpClient.callTool({ name: 'okta_login', arguments: {} });
    const resultText = mcpResult.content?.[0]?.text ?? JSON.stringify(mcpResult);

    let loginOk = true;
    try {
      const parsed = JSON.parse(resultText);
      if (parsed.ok === false) loginOk = false;
    } catch { /* not JSON */ }

    if (loginOk) logGrantedScopes();

    send('login_result', { ok: loginOk, domain: process.env.OKTA_DOMAIN || '' });
    send('done', {});
  } catch (err) {
    console.error('[login] error:', err.message);
    send('error', { message: err.message });
  } finally {
    res.end();
  }
});

// ---------------------------------------------------------------------------
// Start
// ---------------------------------------------------------------------------

async function start() {
  try {
    await initMCP();
  } catch (err) {
    console.warn(`Warning: MCP server failed to start — ${err.message}`);
    console.warn('The web UI will load but tool calls will fail until MCP is available.');
  }

  app.listen(PORT, '127.0.0.1', () => {
    console.log(`\nOkta Security Chat → http://localhost:${PORT}`);
    console.log(`Mode: ${APP_MODE.toUpperCase()} | Okta domain: ${process.env.OKTA_DOMAIN || '(not set)'}\n`);
  });
}

start();
