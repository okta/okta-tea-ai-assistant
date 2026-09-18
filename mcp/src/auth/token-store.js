'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');

const STORE_DIR = path.join(os.homedir(), '.okta-tea-ai-assistant');
const STORE_PATH = path.join(STORE_DIR, 'tokens.json');

function ensureStoreDir() {
  if (!fs.existsSync(STORE_DIR)) {
    fs.mkdirSync(STORE_DIR, { mode: 0o700, recursive: true });
  }
}

function readTokens() {
  try {
    const raw = fs.readFileSync(STORE_PATH, 'utf8');
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

function writeTokens(tokens) {
  ensureStoreDir();
  fs.writeFileSync(STORE_PATH, JSON.stringify(tokens, null, 2), { mode: 0o600 });
}

function clearTokens() {
  try {
    fs.unlinkSync(STORE_PATH);
  } catch {
    // already gone
  }
}

function isAccessTokenExpired(tokens) {
  if (!tokens || !tokens.expiresAt) return true;
  return Date.now() >= tokens.expiresAt - 5 * 60 * 1000; // 5 min buffer
}

module.exports = { readTokens, writeTokens, clearTokens, isAccessTokenExpired, STORE_PATH };
