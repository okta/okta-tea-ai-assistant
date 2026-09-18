'use strict';

const axios = require('axios');
const { readTokens, writeTokens, isAccessTokenExpired } = require('./token-store');

async function refreshAccessToken(tokens) {
  const { domain, clientId, refreshToken } = tokens;

  const response = await axios.post(
    `https://${domain}/oauth2/v1/token`,
    new URLSearchParams({
      grant_type: 'refresh_token',
      refresh_token: refreshToken,
      client_id: clientId,
    }),
    { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
  );

  const { access_token, refresh_token, expires_in } = response.data;

  const updated = {
    ...tokens,
    accessToken: access_token,
    refreshToken: refresh_token || tokens.refreshToken,
    expiresAt: Date.now() + expires_in * 1000,
  };

  writeTokens(updated);
  return updated;
}

/**
 * Returns an axios instance authenticated with a valid Okta access token.
 * Transparently refreshes the token if it is within 5 minutes of expiry.
 * Throws if no tokens are stored or refresh fails.
 */
async function createOktaClient() {
  let tokens = readTokens();

  if (!tokens) {
    throw new Error('Not authenticated. Call okta_login first.');
  }

  if (isAccessTokenExpired(tokens)) {
    if (!tokens.refreshToken) {
      throw new Error('Access token expired and no refresh token available. Call okta_login again.');
    }
    tokens = await refreshAccessToken(tokens);
  }

  return axios.create({
    baseURL: `https://${tokens.domain}`,
    headers: {
      Authorization: `Bearer ${tokens.accessToken}`,
      Accept: 'application/json',
      'Content-Type': 'application/json',
    },
  });
}

module.exports = { createOktaClient };
