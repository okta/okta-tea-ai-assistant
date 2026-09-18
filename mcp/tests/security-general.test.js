'use strict';

const {
  registerSecurityGeneralTools,
  auditSecuritySettings,
  buildSecurityGeneralLogQueries,
  buildSecurityGeneralRiskAssessment,
  matchFeature,
} = require('../src/tools/security-general');

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

function makeFeature(overrides = {}) {
  return {
    id: 'feature_1',
    name: 'SUSPICIOUS_ACTIVITY_REPORTING',
    status: 'DISABLED',
    ...overrides,
  };
}

function makeAuditInputs({ attackProtection = {}, features = {}, orgSettings = {} } = {}) {
  return {
    attackProtection: { available: false, ...attackProtection },
    features: { available: true, features: [], ...features },
    orgSettings: { available: false, ...orgSettings },
  };
}

// ── matchFeature ──────────────────────────────────────────────────────────────

describe('matchFeature', () => {
  test('matches by name substring (case-insensitive)', () => {
    const features = [
      makeFeature({ id: 'f1', name: 'SUSPICIOUS_ACTIVITY_REPORTING' }),
      makeFeature({ id: 'f2', name: 'SOME_OTHER_FEATURE' }),
    ];
    const match = matchFeature(features, ['SUSPICIOUS_ACTIVITY_REPORTING']);
    expect(match).toBeTruthy();
    expect(match.id).toBe('f1');
  });

  test('returns null when no match', () => {
    const features = [makeFeature({ name: 'UNRELATED_FEATURE' })];
    const match = matchFeature(features, ['MISSING_FEATURE']);
    expect(match).toBeNull();
  });

  test('returns null for empty feature list', () => {
    expect(matchFeature([], ['ANYTHING'])).toBeNull();
  });

  test('matches by partial name', () => {
    const features = [makeFeature({ name: 'UNKNOWN_DEVICE_LOCKOUT_PROTECTION' })];
    const match = matchFeature(features, ['UNKNOWN_DEVICE']);
    expect(match).toBeTruthy();
  });
});

// ── auditSecuritySettings ─────────────────────────────────────────────────────

describe('auditSecuritySettings', () => {
  test('flags both findings when features API is empty', () => {
    const result = auditSecuritySettings(makeAuditInputs());
    expect(result.findingCount).toBe(2);
    const ids = result.findings.map((f) => f.id);
    expect(ids).toContain('UNKNOWN_DEVICE_BLOCKING');
    expect(ids).toContain('SUSPICIOUS_ACTIVITY_REPORTING');
  });

  test('does not flag UNKNOWN_DEVICE_BLOCKING when attack protection reports BLOCK', () => {
    const result = auditSecuritySettings(makeAuditInputs({
      attackProtection: {
        available: true,
        data: { unknownDevice: { action: 'BLOCK' } },
      },
    }));
    const ids = result.findings.map((f) => f.id);
    expect(ids).not.toContain('UNKNOWN_DEVICE_BLOCKING');
  });

  test('does not flag SUSPICIOUS_ACTIVITY_REPORTING when feature is ENABLED', () => {
    const result = auditSecuritySettings(makeAuditInputs({
      features: {
        available: true,
        features: [makeFeature({ name: 'SUSPICIOUS_ACTIVITY_REPORTING', status: 'ENABLED' })],
      },
    }));
    const ids = result.findings.map((f) => f.id);
    expect(ids).not.toContain('SUSPICIOUS_ACTIVITY_REPORTING');
  });

  test('does not flag UNKNOWN_DEVICE when matching feature is ENABLED', () => {
    const result = auditSecuritySettings(makeAuditInputs({
      features: {
        available: true,
        features: [makeFeature({ name: 'UNKNOWN_DEVICE_LOCKOUT_PROTECTION', status: 'ENABLED' })],
      },
    }));
    const ids = result.findings.map((f) => f.id);
    expect(ids).not.toContain('UNKNOWN_DEVICE_BLOCKING');
  });

  test('includes rawStatus with available flags', () => {
    const result = auditSecuritySettings(makeAuditInputs());
    expect(result.rawStatus).toHaveProperty('attackProtection');
    expect(result.rawStatus).toHaveProperty('unknownDeviceFeature');
    expect(result.rawStatus).toHaveProperty('suspiciousActivityFeature');
  });
});

// ── buildSecurityGeneralLogQueries ────────────────────────────────────────────

describe('buildSecurityGeneralLogQueries', () => {
  test('returns non-empty array with required fields', () => {
    const queries = buildSecurityGeneralLogQueries();
    expect(queries.length).toBeGreaterThan(0);
    for (const q of queries) {
      expect(q).toHaveProperty('filter');
      expect(q).toHaveProperty('description');
      expect(q).toHaveProperty('timeWindow');
    }
  });

  test('includes suspicious activity report query', () => {
    const queries = buildSecurityGeneralLogQueries();
    const found = queries.find((q) => q.filter.includes('report_suspicious_activity'));
    expect(found).toBeTruthy();
  });
});

// ── buildSecurityGeneralRiskAssessment ────────────────────────────────────────

describe('buildSecurityGeneralRiskAssessment', () => {
  test('changeRisk is LOW', () => {
    expect(buildSecurityGeneralRiskAssessment().changeRisk).toBe('LOW');
  });

  test('has rolloutSteps array', () => {
    const ra = buildSecurityGeneralRiskAssessment();
    expect(Array.isArray(ra.rolloutSteps)).toBe(true);
    expect(ra.rolloutSteps.length).toBeGreaterThan(0);
  });
});

// ── okta_get_security_general_settings tool ───────────────────────────────────

describe('okta_get_security_general_settings', () => {
  let tools;
  let mockClient;

  beforeEach(() => {
    mockClient = { get: jest.fn() };
    createOktaClient.mockResolvedValue(mockClient);
    tools = captureTools(registerSecurityGeneralTools);
  });

  test('returns ok:true even when all APIs return 404', async () => {
    const notFound = { response: { status: 404 } };
    mockClient.get.mockRejectedValue(notFound);

    const result = await tools.okta_get_security_general_settings({});
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.ok).toBe(true);
    expect(parsed.summary.findingCount).toBeGreaterThan(0);
  });

  test('returns findings when features API returns empty list', async () => {
    mockClient.get
      .mockRejectedValueOnce({ response: { status: 404 } }) // attack protection
      .mockResolvedValueOnce({ data: [] })                   // features
      .mockRejectedValueOnce({ response: { status: 403 } }); // org settings

    const result = await tools.okta_get_security_general_settings({});
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.ok).toBe(true);
    expect(parsed.summary.findingCount).toBe(2);
  });

  test('reports fewer findings when suspicious activity feature is enabled', async () => {
    const enabledFeature = makeFeature({ name: 'SUSPICIOUS_ACTIVITY_REPORTING', status: 'ENABLED' });
    mockClient.get
      .mockRejectedValueOnce({ response: { status: 404 } })
      .mockResolvedValueOnce({ data: [enabledFeature] })
      .mockRejectedValueOnce({ response: { status: 404 } });

    const result = await tools.okta_get_security_general_settings({});
    const parsed = JSON.parse(result.content[0].text);
    const ids = parsed.findings.map((f) => f.id);
    expect(ids).not.toContain('SUSPICIOUS_ACTIVITY_REPORTING');
  });

  test('includes manual console steps in remediation', async () => {
    mockClient.get.mockRejectedValue({ response: { status: 404 } });
    const result = await tools.okta_get_security_general_settings({});
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.remediation.adminConsoleSteps).toBeTruthy();
    expect(parsed.remediation.adminConsoleSteps.unknownDeviceBlocking).toBeTruthy();
    expect(parsed.remediation.adminConsoleSteps.suspiciousActivityReporting).toBeTruthy();
  });

  test('returns error on unexpected failure', async () => {
    createOktaClient.mockRejectedValue(new Error('Network failure'));
    const result = await tools.okta_get_security_general_settings({});
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.ok).toBe(false);
    expect(result.isError).toBe(true);
  });
});

// ── okta_enable_suspicious_device_blocking tool ───────────────────────────────

describe('okta_enable_suspicious_device_blocking', () => {
  let tools;
  let mockClient;

  beforeEach(() => {
    mockClient = { get: jest.fn(), post: jest.fn() };
    createOktaClient.mockResolvedValue(mockClient);
    tools = captureTools(registerSecurityGeneralTools);
  });

  test('returns ok:true with manual steps when API returns 404', async () => {
    mockClient.get.mockRejectedValue({ response: { status: 404 } });

    const result = await tools.okta_enable_suspicious_device_blocking({});
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.ok).toBe(true);
    expect(parsed.apiAvailable).toBe(false);
    expect(parsed.remediation.adminConsoleSteps).toBeTruthy();
  });

  test('returns ok:true with manual steps when API returns 405', async () => {
    mockClient.get.mockRejectedValue({ response: { status: 405 } });

    const result = await tools.okta_enable_suspicious_device_blocking({});
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.ok).toBe(true);
    expect(parsed.apiAvailable).toBe(false);
  });

  test('returns error on unexpected API failure', async () => {
    mockClient.get.mockResolvedValue({ data: {} });
    mockClient.post.mockRejectedValue(new Error('Internal server error'));

    const result = await tools.okta_enable_suspicious_device_blocking({});
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.ok).toBe(false);
    expect(result.isError).toBe(true);
  });

  test('succeeds via API when attack protection endpoint is available', async () => {
    const attackData = { unknownDevice: { action: 'AUDIT' } };
    const updatedData = { unknownDevice: { action: 'BLOCK' } };
    mockClient.get.mockResolvedValue({ data: attackData });
    mockClient.post.mockResolvedValue({ data: updatedData });

    const result = await tools.okta_enable_suspicious_device_blocking({});
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.ok).toBe(true);
    expect(parsed.apiAvailable).toBe(true);
  });
});

// ── okta_enable_suspicious_activity_reporting tool ────────────────────────────

describe('okta_enable_suspicious_activity_reporting', () => {
  let tools;
  let mockClient;

  beforeEach(() => {
    mockClient = { get: jest.fn(), post: jest.fn() };
    createOktaClient.mockResolvedValue(mockClient);
    tools = captureTools(registerSecurityGeneralTools);
  });

  test('returns ok:true with manual steps when feature not found', async () => {
    mockClient.get.mockResolvedValue({ data: [] });

    const result = await tools.okta_enable_suspicious_activity_reporting({});
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.ok).toBe(true);
    expect(parsed.apiAvailable).toBe(false);
  });

  test('reports already enabled when feature status is ENABLED', async () => {
    const enabledFeature = makeFeature({ name: 'SUSPICIOUS_ACTIVITY_REPORTING', status: 'ENABLED' });
    mockClient.get.mockResolvedValue({ data: [enabledFeature] });

    const result = await tools.okta_enable_suspicious_activity_reporting({});
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.ok).toBe(true);
    expect(parsed.message).toContain('already enabled');
  });

  test('enables feature when found and DISABLED', async () => {
    const disabledFeature = makeFeature({ id: 'f_suspicious', name: 'SUSPICIOUS_ACTIVITY_REPORTING', status: 'DISABLED' });
    const enabledFeature = makeFeature({ id: 'f_suspicious', name: 'SUSPICIOUS_ACTIVITY_REPORTING', status: 'ENABLED' });
    mockClient.get.mockResolvedValue({ data: [disabledFeature] });
    mockClient.post.mockResolvedValue({ data: enabledFeature });

    const result = await tools.okta_enable_suspicious_activity_reporting({});
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.ok).toBe(true);
    expect(mockClient.post).toHaveBeenCalledWith(
      '/api/v1/features/f_suspicious/lifecycle/enable',
      {},
    );
  });

  test('returns ok:true with manual steps when features API is unavailable', async () => {
    mockClient.get.mockRejectedValue({ response: { status: 404 } });

    const result = await tools.okta_enable_suspicious_activity_reporting({});
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.ok).toBe(true);
    expect(parsed.apiAvailable).toBe(false);
    expect(parsed.remediation.adminConsoleSteps).toBeTruthy();
  });

  test('returns error on unexpected failure', async () => {
    createOktaClient.mockRejectedValue(new Error('Auth failed'));
    const result = await tools.okta_enable_suspicious_activity_reporting({});
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.ok).toBe(false);
  });
});
