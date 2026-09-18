'use strict';

const {
  registerAuthenticatorTools,
  findOktaVerifyAuthenticator,
  auditOktaVerify,
  buildAuthenticatorTerraform,
  buildAuthenticatorLogQueries,
  buildAuthenticatorRiskAssessment,
} = require('../src/tools/authenticators');

jest.mock('../src/auth/okta-client', () => ({
  createOktaClient: jest.fn(),
}));

const { createOktaClient } = require('../src/auth/okta-client');

// ── Test helpers ───────────────────────────────────────────────────────────────

function captureTools(registerFn) {
  const tools = {};
  const mockServer = {
    tool(name, _desc, _schema, handler) {
      tools[name] = handler;
    },
  };
  registerFn(mockServer);
  return tools;
}

function makeOktaVerify(overrides = {}) {
  return {
    id: 'aut_verify_1',
    key: 'okta_verify',
    name: 'Okta Verify',
    type: 'app',
    status: 'ACTIVE',
    settings: {
      userVerification: 'PREFERRED',
      // Okta stores number challenge as channelBinding.required, not as numberChallenge
      channelBinding: { style: 'NUMBER_CHALLENGE', required: 'NEVER' },
      compliance: { fips: 'OPTIONAL' },
      appInstanceId: '',
    },
    ...overrides,
  };
}

function makeOktaVerifyEnabled(overrides = {}) {
  return makeOktaVerify({
    settings: {
      userVerification: 'PREFERRED',
      channelBinding: { style: 'NUMBER_CHALLENGE', required: 'ALWAYS' },
      compliance: { fips: 'OPTIONAL' },
      enrollmentSecurityLevel: 'HIGH',
    },
    ...overrides,
  });
}

function makeAuthenticatorList(oktaVerify = makeOktaVerify()) {
  return [
    { id: 'aut_pwd', key: 'okta_password', name: 'Password', type: 'password', status: 'ACTIVE', settings: {} },
    { id: 'aut_email', key: 'okta_email', name: 'Email', type: 'email', status: 'ACTIVE', settings: {} },
    oktaVerify,
  ];
}

// ── findOktaVerifyAuthenticator ────────────────────────────────────────────────

describe('findOktaVerifyAuthenticator', () => {
  test('finds Okta Verify by key', () => {
    const authenticators = makeAuthenticatorList();
    const found = findOktaVerifyAuthenticator(authenticators);
    expect(found).toBeTruthy();
    expect(found.key).toBe('okta_verify');
  });

  test('returns null when Okta Verify is absent', () => {
    const authenticators = [
      { id: 'aut_pwd', key: 'okta_password', name: 'Password' },
    ];
    expect(findOktaVerifyAuthenticator(authenticators)).toBeNull();
  });

  test('returns null for empty array', () => {
    expect(findOktaVerifyAuthenticator([])).toBeNull();
  });
});

// ── auditOktaVerify ────────────────────────────────────────────────────────────

describe('auditOktaVerify', () => {
  test('flags NUMBER_CHALLENGE_DISABLED when channelBinding.required is NEVER', () => {
    const result = auditOktaVerify(makeOktaVerify());
    const finding = result.findings.find((f) => f.id === 'NUMBER_CHALLENGE_DISABLED');
    expect(finding).toBeTruthy();
    expect(finding.severity).toBe('MODERATE');
  });

  test('no findings when channelBinding.required is ALWAYS', () => {
    const result = auditOktaVerify(makeOktaVerifyEnabled());
    expect(result.findingCount).toBe(0);
  });

  test('returns authenticator details with channelBinding state', () => {
    const result = auditOktaVerify(makeOktaVerify());
    expect(result.authenticatorId).toBe('aut_verify_1');
    expect(result.key).toBe('okta_verify');
    expect(result.current.channelBindingRequired).toBe('NEVER');
    expect(result.current.numberChallengeEnabled).toBe(false);
  });

  test('defaults to NEVER when settings are missing', () => {
    const result = auditOktaVerify(makeOktaVerify({ settings: undefined }));
    expect(result.findings.find((f) => f.id === 'NUMBER_CHALLENGE_DISABLED')).toBeTruthy();
  });
});

// ── buildAuthenticatorTerraform ────────────────────────────────────────────────

describe('buildAuthenticatorTerraform', () => {
  test('includes authenticator ID in a comment', () => {
    const tf = buildAuthenticatorTerraform(makeOktaVerify());
    expect(tf).toContain('aut_verify_1');
  });

  test('sets channelBinding.required to ALWAYS in Terraform', () => {
    const tf = buildAuthenticatorTerraform(makeOktaVerify());
    expect(tf).toContain('"required": "ALWAYS"');
    expect(tf).toContain('"style": "NUMBER_CHALLENGE"');
  });

  test('includes okta_authenticator resource block', () => {
    const tf = buildAuthenticatorTerraform(makeOktaVerify());
    expect(tf).toContain('resource "okta_authenticator" "okta_verify"');
  });
});

// ── buildAuthenticatorLogQueries ──────────────────────────────────────────────

describe('buildAuthenticatorLogQueries', () => {
  test('returns non-empty array', () => {
    const queries = buildAuthenticatorLogQueries();
    expect(queries.length).toBeGreaterThan(0);
  });

  test('includes push bombing denial query', () => {
    const queries = buildAuthenticatorLogQueries();
    const denyPush = queries.find((q) => q.filter.includes('OV_RESPONSE_DENY'));
    expect(denyPush).toBeTruthy();
  });
});

// ── buildAuthenticatorRiskAssessment ──────────────────────────────────────────

describe('buildAuthenticatorRiskAssessment', () => {
  test('changeRisk is LOW', () => {
    expect(buildAuthenticatorRiskAssessment().changeRisk).toBe('LOW');
  });

  test('mentions push bombing in summary', () => {
    const ra = buildAuthenticatorRiskAssessment();
    expect(ra.summary.toLowerCase()).toContain('push bombing');
  });
});

// ── okta_list_authenticators tool ─────────────────────────────────────────────

describe('okta_list_authenticators', () => {
  let tools;
  let mockClient;

  beforeEach(() => {
    mockClient = { get: jest.fn() };
    createOktaClient.mockResolvedValue(mockClient);
    tools = captureTools(registerAuthenticatorTools);
  });

  test('returns ok:true with authenticator list', async () => {
    mockClient.get.mockResolvedValue({ data: makeAuthenticatorList() });
    const result = await tools.okta_list_authenticators({});
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.ok).toBe(true);
    expect(parsed.summary.totalAuthenticators).toBe(3);
    expect(parsed.summary.oktaVerifyPresent).toBe(true);
  });

  test('flags finding when number challenge is disabled', async () => {
    mockClient.get.mockResolvedValue({ data: makeAuthenticatorList() });
    const result = await tools.okta_list_authenticators({});
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.summary.oktaVerifyFindings).toBeGreaterThan(0);
    expect(parsed.oktaVerifyAudit.findings.length).toBeGreaterThan(0);
  });

  test('handles missing Okta Verify gracefully', async () => {
    mockClient.get.mockResolvedValue({
      data: [{ id: 'aut_pwd', key: 'okta_password', name: 'Password', settings: {} }],
    });
    const result = await tools.okta_list_authenticators({});
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.ok).toBe(true);
    expect(parsed.summary.oktaVerifyPresent).toBe(false);
    expect(parsed.oktaVerifyAudit).toBeNull();
    expect(parsed.remediation).toBeTruthy();
  });

  test('returns error on API failure', async () => {
    createOktaClient.mockRejectedValue(new Error('Unauthorized'));
    const result = await tools.okta_list_authenticators({});
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.ok).toBe(false);
    expect(result.isError).toBe(true);
  });
});

// ── okta_update_okta_verify_settings tool ─────────────────────────────────────

describe('okta_update_okta_verify_settings', () => {
  let tools;
  let mockClient;

  beforeEach(() => {
    mockClient = { get: jest.fn(), put: jest.fn() };
    createOktaClient.mockResolvedValue(mockClient);
    tools = captureTools(registerAuthenticatorTools);
  });

  test('returns error when no settings provided', async () => {
    const result = await tools.okta_update_okta_verify_settings({});
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.ok).toBe(false);
    expect(result.isError).toBe(true);
  });

  test('auto-detects Okta Verify and enables number challenge', async () => {
    const verify = makeOktaVerify();
    mockClient.get
      .mockResolvedValueOnce({ data: [verify] })
      .mockResolvedValueOnce({ data: makeOktaVerifyEnabled() });
    mockClient.put.mockResolvedValue({ data: {} });

    const result = await tools.okta_update_okta_verify_settings({ numberChallenge: 'ENABLED' });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.ok).toBe(true);
    expect(parsed.appliedChanges.numberChallenge).toBe('ENABLED');
    expect(parsed.findingsAfter).toBe(0);
  });

  test('uses provided authenticatorId when supplied', async () => {
    const verify = makeOktaVerify();
    mockClient.get
      .mockResolvedValueOnce({ data: verify })
      .mockResolvedValueOnce({ data: makeOktaVerifyEnabled() });
    mockClient.put.mockResolvedValue({ data: {} });

    await tools.okta_update_okta_verify_settings({
      numberChallenge: 'ENABLED',
      authenticatorId: 'aut_verify_1',
    });
    expect(mockClient.get).toHaveBeenCalledWith('/api/v1/authenticators/aut_verify_1');
  });

  test('returns error when Okta Verify is not found', async () => {
    mockClient.get.mockResolvedValue({
      data: [{ id: 'aut_pwd', key: 'okta_password', name: 'Password', settings: {} }],
    });
    const result = await tools.okta_update_okta_verify_settings({ numberChallenge: 'ENABLED' });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.ok).toBe(false);
  });

  test('returns error when wrong authenticator key is provided via authenticatorId', async () => {
    mockClient.get.mockResolvedValue({
      data: { id: 'aut_email', key: 'okta_email', name: 'Email', settings: {} },
    });
    const result = await tools.okta_update_okta_verify_settings({
      numberChallenge: 'ENABLED',
      authenticatorId: 'aut_email',
    });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.ok).toBe(false);
  });

  test('PUT is called with the correct authenticator path', async () => {
    const verify = makeOktaVerify();
    mockClient.get
      .mockResolvedValueOnce({ data: [verify] })
      .mockResolvedValueOnce({ data: makeOktaVerifyEnabled() });
    mockClient.put.mockResolvedValue({ data: {} });

    await tools.okta_update_okta_verify_settings({ numberChallenge: 'ENABLED' });
    expect(mockClient.put).toHaveBeenCalledWith(
      '/api/v1/authenticators/aut_verify_1',
      expect.any(Object),
    );
  });

  test('re-fetches authenticator after PUT and uses GET response for audit', async () => {
    const verify = makeOktaVerify();
    mockClient.get
      .mockResolvedValueOnce({ data: [verify] })
      .mockResolvedValueOnce({ data: makeOktaVerifyEnabled() }); // re-fetch shows ALWAYS
    mockClient.put.mockResolvedValue({ data: {} }); // PUT response body ignored for audit

    const result = await tools.okta_update_okta_verify_settings({ numberChallenge: 'ENABLED' });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.findingsAfter).toBe(0);
    expect(parsed.propagationWarning).toBeUndefined();
  });

  test('propagationWarning when re-fetched state still shows old setting', async () => {
    const verify = makeOktaVerify(); // numberChallenge: DISABLED
    mockClient.get
      .mockResolvedValueOnce({ data: [verify] })
      .mockResolvedValueOnce({ data: verify }); // re-fetch still returns DISABLED
    mockClient.put.mockResolvedValue({ data: {} });

    const result = await tools.okta_update_okta_verify_settings({ numberChallenge: 'ENABLED' });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.ok).toBe(true);
    expect(parsed.findingsAfter).toBeGreaterThan(0);
    expect(parsed.propagationWarning).toMatch(/still shows findings/);
  });

  test('PUT body maps numberChallenge ENABLED to channelBinding.required ALWAYS', async () => {
    // makeOktaVerify includes appInstanceId in settings — it must be stripped from the PUT body
    mockClient.get
      .mockResolvedValueOnce({ data: [makeOktaVerify()] })
      .mockResolvedValueOnce({ data: makeOktaVerifyEnabled() });
    mockClient.put.mockResolvedValue({ data: {} });

    await tools.okta_update_okta_verify_settings({ numberChallenge: 'ENABLED' });

    const [, body] = mockClient.put.mock.calls[0];
    expect(body.key).toBe('okta_verify');
    expect(body.name).toBe('Okta Verify');
    // numberChallenge ENABLED must translate to channelBinding.required ALWAYS
    expect(body.settings.channelBinding).toEqual({ style: 'NUMBER_CHALLENGE', required: 'ALWAYS' });
    // appInstanceId stripped from settings
    expect(body.settings).not.toHaveProperty('appInstanceId');
    // Read-only top-level fields excluded
    expect(body).not.toHaveProperty('id');
    expect(body).not.toHaveProperty('status');
    expect(body).not.toHaveProperty('type');
  });

  test('PUT body maps numberChallenge DISABLED to channelBinding.required NEVER', async () => {
    mockClient.get
      .mockResolvedValueOnce({ data: [makeOktaVerifyEnabled()] })
      .mockResolvedValueOnce({ data: makeOktaVerify() });
    mockClient.put.mockResolvedValue({ data: {} });

    await tools.okta_update_okta_verify_settings({ numberChallenge: 'DISABLED' });

    const [, body] = mockClient.put.mock.calls[0];
    expect(body.settings.channelBinding).toEqual({ style: 'NUMBER_CHALLENGE', required: 'NEVER' });
  });

  test('diagnostics shows channelBinding.required in settingsSent and settingsReturnedByOkta', async () => {
    mockClient.get
      .mockResolvedValueOnce({ data: [makeOktaVerify()] })
      .mockResolvedValueOnce({ data: makeOktaVerifyEnabled() });
    mockClient.put.mockResolvedValue({ data: {} });

    const result = await tools.okta_update_okta_verify_settings({ numberChallenge: 'ENABLED' });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.diagnostics).toBeDefined();
    // settingsSent must use the real API field
    expect(parsed.diagnostics.settingsSent.channelBinding.required).toBe('ALWAYS');
    // settingsReturnedByOkta reflects what re-fetch returned
    expect(parsed.diagnostics.settingsReturnedByOkta.channelBinding.required).toBe('ALWAYS');
  });
});
