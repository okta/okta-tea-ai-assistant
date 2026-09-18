'use strict';

const http = require('http');
const { execSync } = require('child_process');
const axios = require('axios');
const { generateVerifier, buildAuthUrl, REDIRECT_PORT, REDIRECT_URI } = require('../auth/pkce');
const { readTokens, writeTokens, isAccessTokenExpired } = require('../auth/token-store');

const LOGIN_TIMEOUT_MS = 90_000;

/**
 * Registers auth tools onto an McpServer instance.
 * @param {import('@modelcontextprotocol/sdk/server/mcp.js').McpServer} server
 */
function registerAuthTools(server) {
  server.tool(
    'okta_get_auth_status',
    'Check whether the user is currently authenticated with Okta and whether the token is valid.',
    {},
    async () => {
      if (process.env.OFFLINE_MODE === 'true') {
        return {
          content: [{ type: 'text', text: JSON.stringify({ authenticated: false, offlineMode: true, reason: 'Running in offline mode — no Okta connection available.' }) }],
        };
      }
      const tokens = readTokens();

      if (!tokens) {
        return {
          content: [{ type: 'text', text: JSON.stringify({ authenticated: false, reason: 'No tokens stored. Call okta_login.' }) }],
        };
      }

      const expired = isAccessTokenExpired(tokens);
      const canRefresh = Boolean(tokens.refreshToken);

      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify({
              authenticated: !expired || canRefresh,
              domain: tokens.domain,
              expiresAt: tokens.expiresAt,
              expired,
              canRefresh,
            }),
          },
        ],
      };
    }
  );

  server.tool(
    'okta_login',
    'Start the PKCE OAuth 2.0 flow. Opens the user\'s browser to the Okta login page and waits up to 90 seconds for the user to complete authentication. Stores tokens securely on disk. Requires OKTA_DOMAIN and OKTA_CLIENT_ID environment variables.',
    {},
    async () => {
      if (process.env.OFFLINE_MODE === 'true') {
        return {
          content: [{ type: 'text', text: JSON.stringify({ ok: false, offlineMode: true, error: 'Login is not available in offline mode. Start with npm run dev or npm run prod to connect to an Okta tenant.' }) }],
          isError: false,
        };
      }
      const domain = process.env.OKTA_DOMAIN;
      const clientId = process.env.OKTA_CLIENT_ID;

      const missing = [];
      if (!domain) missing.push('OKTA_DOMAIN');
      if (!clientId) missing.push('OKTA_CLIENT_ID');
      if (missing.length > 0) {
        return {
          content: [{ type: 'text', text: JSON.stringify({ ok: false, error: `Missing environment variables: ${missing.join(', ')}. Configure them in the MCP server settings.` }) }],
          isError: true,
        };
      }

      const verifier = generateVerifier();
      const writeEnabled = process.env.PROD_MODE !== 'true';
      const { url: authUrl, state: expectedState } = buildAuthUrl(domain, clientId, verifier, writeEnabled);

      let server;
      let _timedOut = false;

      const codePromise = new Promise((resolve, reject) => {
        server = http.createServer((req, res) => {
          const url = new URL(req.url, `http://localhost:${REDIRECT_PORT}`);

          if (url.pathname !== '/callback') {
            res.writeHead(404);
            res.end();
            return;
          }

          const code = url.searchParams.get('code');
          const error = url.searchParams.get('error');
          const returnedState = url.searchParams.get('state');

          if (returnedState !== expectedState) {
            res.writeHead(400);
            res.end('State mismatch');
            reject(new Error('OAuth state mismatch — possible CSRF attack. Please try logging in again.'));
            return;
          }

          if (error) {
            res.writeHead(200, { 'Content-Type': 'text/html' });
            res.end('<html><body><h2>Authentication failed.</h2><p>You may close this window.</p></body></html>');
            reject(new Error(`Okta error: ${error} — ${url.searchParams.get('error_description') || ''}`));
            return;
          }

          if (!code) {
            res.writeHead(400);
            res.end('Missing code');
            return;
          }

          res.writeHead(200, { 'Content-Type': 'text/html' });
          res.end('<html><body><h2>Authentication successful.</h2><p>You may close this window and return to Claude.</p></body></html>');
          resolve(code);
        });

        server.listen(REDIRECT_PORT, '127.0.0.1', () => {
          // open browser — macOS
          try {
            execSync(`open "${authUrl}"`, { stdio: 'ignore' });
          } catch {
            // non-macOS fallback: user will need to open the URL manually
          }
        });

        setTimeout(() => {
          _timedOut = true;
          reject(new Error('Login timed out after 90 seconds. Please try again.'));
        }, LOGIN_TIMEOUT_MS);
      });

      try {
        const code = await codePromise;

        // Exchange authorization code for tokens
        const tokenResponse = await axios.post(
          `https://${domain}/oauth2/v1/token`,
          new URLSearchParams({
            grant_type: 'authorization_code',
            code,
            redirect_uri: REDIRECT_URI,
            client_id: clientId,
            code_verifier: verifier,
          }),
          { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
        );

        const { access_token, refresh_token, expires_in } = tokenResponse.data;

        const tokens = {
          domain,
          clientId,
          accessToken: access_token,
          refreshToken: refresh_token || null,
          expiresAt: Date.now() + expires_in * 1000,
        };

        writeTokens(tokens);

        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify({
                ok: true,
                domain,
                expiresAt: tokens.expiresAt,
                message: 'Authentication successful. Tokens stored securely.',
              }),
            },
          ],
        };
      } catch (err) {
        return {
          content: [{ type: 'text', text: JSON.stringify({ ok: false, error: err.message }) }],
          isError: true,
        };
      } finally {
        if (server) server.close();
      }
    }
  );
}

module.exports = { registerAuthTools };
