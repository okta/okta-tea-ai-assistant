'use strict';

const nodeCrypto = require('crypto');

const READ_SCOPES  = 'openid offline_access okta.logs.read okta.policies.read okta.authenticators.read okta.apps.read okta.deviceAssurance.read okta.idps.read okta.features.read okta.securityEventsProviders.read okta.behaviors.read okta.logStreams.read okta.captchas.read okta.authorizationServers.read okta.roles.read okta.apiTokens.read okta.users.read';
const WRITE_SCOPES = 'okta.threatInsights.manage okta.networkZones.manage okta.policies.manage okta.authenticators.manage okta.apps.manage okta.orgs.manage okta.deviceAssurance.manage okta.features.manage';
const SCOPES = `${READ_SCOPES} ${WRITE_SCOPES}`;
const REDIRECT_PORT = 9876;
const REDIRECT_URI = `http://localhost:${REDIRECT_PORT}/callback`;

function generateVerifier() {
  return nodeCrypto.randomBytes(64).toString('base64url');
}

function generateChallenge(verifier) {
  return nodeCrypto.createHash('sha256').update(verifier).digest('base64url');
}

function buildAuthUrl(domain, clientId, verifier, writeEnabled = true) {
  const challenge = generateChallenge(verifier);
  const state = nodeCrypto.randomBytes(16).toString('hex');
  const params = new URLSearchParams({
    client_id: clientId,
    response_type: 'code',
    scope: writeEnabled ? SCOPES : READ_SCOPES,
    redirect_uri: REDIRECT_URI,
    code_challenge: challenge,
    code_challenge_method: 'S256',
    state,
  });
  return { url: `https://${domain}/oauth2/v1/authorize?${params.toString()}`, state };
}

module.exports = { generateVerifier, generateChallenge, buildAuthUrl, REDIRECT_PORT, REDIRECT_URI, SCOPES, READ_SCOPES, WRITE_SCOPES };
