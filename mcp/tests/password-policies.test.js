'use strict';

const {
  registerPasswordPolicyTools,
  auditPolicy,
  buildPasswordPolicyTerraform,
  buildPasswordPolicyLogQueries,
  buildPasswordPolicyRiskAssessment,
} = require('../src/tools/password-policies');

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

function makePolicy(overrides = {}) {
  return {
    id: 'pol_abc123',
    name: 'Test Policy',
    type: 'PASSWORD',
    status: 'ACTIVE',
    settings: {
      password: {
        complexity: {
          minLength: 8,
          excludeUsername: false,
          dictionary: { common: { exclude: false } },
        },
        lockout: {
          maxAttempts: 5,
          autoUnlockMinutes: 0,
          showLockoutFailures: false,
        },
        age: {
          minAgeMinutes: 0,
          historyCount: 5,
        },
      },
    },
    ...overrides,
  };
}

// ── auditPolicy ───────────────────────────────────────────────────────────────

describe('auditPolicy', () => {
  test('flags all findings on a weak policy', () => {
    const result = auditPolicy(makePolicy());
    const ids = result.findings.map((f) => f.id);
    expect(ids).toContain('MIN_LENGTH');
    expect(ids).toContain('EXCLUDE_USERNAME');
    expect(ids).toContain('COMMON_PASSWORDS');
    expect(ids).toContain('LOCKOUT_EMAIL');
    expect(result.highCount).toBeGreaterThan(0);
  });

  test('no findings on a fully hardened policy', () => {
    const strong = makePolicy({
      settings: {
        password: {
          complexity: {
            minLength: 15,
            excludeUsername: true,
            dictionary: { common: { exclude: true } },
            minLowerCase: 1,
            minUpperCase: 1,
            minNumber: 1,
            minSymbol: 1,
          },
          lockout: {
            maxAttempts: 10,
            autoUnlockMinutes: 0,
            showLockoutFailures: true,
          },
          age: { minAgeMinutes: 1440, historyCount: 5 },
          breachedProtection: { logoutEnabled: true, expireAfterDays: 0 },
        },
      },
    });
    const result = auditPolicy(strong);
    expect(result.findingCount).toBe(0);
    expect(result.highCount).toBe(0);
  });

  test('flags MIN_LENGTH when minLength is exactly 14', () => {
    const policy = makePolicy();
    policy.settings.password.complexity.minLength = 14;
    const result = auditPolicy(policy);
    expect(result.findings.find((f) => f.id === 'MIN_LENGTH')).toBeTruthy();
  });

  test('does NOT flag MIN_LENGTH when minLength is exactly 15', () => {
    const policy = makePolicy();
    policy.settings.password.complexity.minLength = 15;
    policy.settings.password.complexity.excludeUsername = true;
    policy.settings.password.complexity.dictionary.common.exclude = true;
    policy.settings.password.lockout.maxAttempts = 10;
    policy.settings.password.lockout.showLockoutFailures = true;
    policy.settings.password.age.minAgeMinutes = 1440;
    const result = auditPolicy(policy);
    expect(result.findings.find((f) => f.id === 'MIN_LENGTH')).toBeUndefined();
  });

  test('flags LOCKOUT_ATTEMPTS when maxAttempts exceeds 10', () => {
    const policy = makePolicy();
    policy.settings.password.lockout.maxAttempts = 20;
    const result = auditPolicy(policy);
    expect(result.findings.find((f) => f.id === 'LOCKOUT_ATTEMPTS')).toBeTruthy();
  });

  test('does NOT flag LOCKOUT_ATTEMPTS when maxAttempts is exactly 10', () => {
    const policy = makePolicy();
    policy.settings.password.lockout.maxAttempts = 10;
    const result = auditPolicy(policy);
    expect(result.findings.find((f) => f.id === 'LOCKOUT_ATTEMPTS')).toBeUndefined();
  });

  test('flags MIN_AGE when minAgeMinutes is below 1440', () => {
    const policy = makePolicy();
    policy.settings.password.age.minAgeMinutes = 60;
    const result = auditPolicy(policy);
    expect(result.findings.find((f) => f.id === 'MIN_AGE')).toBeTruthy();
  });

  test('returns correct policyId and policyName', () => {
    const result = auditPolicy(makePolicy());
    expect(result.policyId).toBe('pol_abc123');
    expect(result.policyName).toBe('Test Policy');
  });

  test('handles missing settings gracefully', () => {
    const policy = makePolicy({ settings: {} });
    const result = auditPolicy(policy);
    expect(result.findingCount).toBeGreaterThan(0);
  });
});

// ── buildPasswordPolicyTerraform ──────────────────────────────────────────────

describe('buildPasswordPolicyTerraform', () => {
  test('includes policy id in a comment', () => {
    const tf = buildPasswordPolicyTerraform(makePolicy());
    expect(tf).toContain('pol_abc123');
  });

  test('includes resource block for password policy', () => {
    const tf = buildPasswordPolicyTerraform(makePolicy());
    expect(tf).toContain('resource "okta_policy_password"');
  });

  test('references TEA Findings in comments', () => {
    const tf = buildPasswordPolicyTerraform(makePolicy());
    expect(tf).toContain('TEA Finding  — minimum length');
    expect(tf).toContain('TEA Finding  — brute force protection');
    expect(tf).toContain('TEA Finding  — lockout');
    expect(tf).toContain('TEA Finding  — minimum password age');
  });

  test('sanitises policy name into a valid Terraform label', () => {
    const policy = makePolicy({ name: 'My Policy (Default)' });
    const tf = buildPasswordPolicyTerraform(policy);
    expect(tf).toContain('resource "okta_policy_password" "my_policy_default"');
  });
});

// ── buildPasswordPolicyLogQueries ─────────────────────────────────────────────

describe('buildPasswordPolicyLogQueries', () => {
  test('returns an array of queries', () => {
    const queries = buildPasswordPolicyLogQueries();
    expect(Array.isArray(queries)).toBe(true);
    expect(queries.length).toBeGreaterThan(0);
  });

  test('each query has required fields', () => {
    const queries = buildPasswordPolicyLogQueries();
    for (const q of queries) {
      expect(q).toHaveProperty('description');
      expect(q).toHaveProperty('filter');
      expect(q).toHaveProperty('timeWindow');
      expect(q).toHaveProperty('note');
    }
  });
});

// ── buildPasswordPolicyRiskAssessment ─────────────────────────────────────────

describe('buildPasswordPolicyRiskAssessment', () => {
  test('returns a risk assessment object with required fields', () => {
    const ra = buildPasswordPolicyRiskAssessment();
    expect(ra).toHaveProperty('teaSeverity');
    expect(ra).toHaveProperty('summary');
    expect(ra).toHaveProperty('rolloutSteps');
    expect(Array.isArray(ra.rolloutSteps)).toBe(true);
  });
});

// ── okta_list_password_policies tool ─────────────────────────────────────────

describe('okta_list_password_policies', () => {
  let tools;
  let mockClient;

  beforeEach(() => {
    mockClient = { get: jest.fn() };
    createOktaClient.mockResolvedValue(mockClient);
    tools = captureTools(registerPasswordPolicyTools);
  });

  test('returns ok:true with audit summary', async () => {
    mockClient.get.mockResolvedValue({ data: [makePolicy()] });
    const result = await tools.okta_list_password_policies({});
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.ok).toBe(true);
    expect(parsed.summary.totalPolicies).toBe(1);
  });

  test('counts high findings correctly', async () => {
    mockClient.get.mockResolvedValue({ data: [makePolicy()] });
    const result = await tools.okta_list_password_policies({});
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.summary.highFindings).toBeGreaterThan(0);
  });

  test('handles empty policy list', async () => {
    mockClient.get.mockResolvedValue({ data: [] });
    const result = await tools.okta_list_password_policies({});
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.ok).toBe(true);
    expect(parsed.summary.totalPolicies).toBe(0);
    expect(parsed.remediation.terraform).toBeNull();
  });

  test('returns error on API failure', async () => {
    createOktaClient.mockRejectedValue(new Error('Not authenticated'));
    const result = await tools.okta_list_password_policies({});
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.ok).toBe(false);
    expect(result.isError).toBe(true);
  });

  test('includes remediation with terraform, logQueries, adminConsoleSteps, riskAssessment', async () => {
    mockClient.get.mockResolvedValue({ data: [makePolicy()] });
    const result = await tools.okta_list_password_policies({});
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.remediation.terraform).toBeTruthy();
    expect(parsed.remediation.logQueries).toBeTruthy();
    expect(parsed.remediation.adminConsoleSteps).toBeTruthy();
    expect(parsed.remediation.riskAssessment).toBeTruthy();
  });
});

// ── okta_update_password_policy tool ─────────────────────────────────────────

describe('okta_update_password_policy', () => {
  let tools;
  let mockClient;

  beforeEach(() => {
    mockClient = { get: jest.fn(), put: jest.fn() };
    createOktaClient.mockResolvedValue(mockClient);
    tools = captureTools(registerPasswordPolicyTools);
  });

  test('returns error for wrong policy type', async () => {
    mockClient.get.mockResolvedValue({
      data: makePolicy({ type: 'ACCESS_POLICY' }),
    });
    const result = await tools.okta_update_password_policy({ policyId: 'pol_abc123', minLength: 15 });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.ok).toBe(false);
    expect(result.isError).toBe(true);
  });

  test('updates minLength and returns success', async () => {
    const original = makePolicy();
    const afterUpdate = makePolicy({ settings: { password: { ...original.settings.password, complexity: { ...original.settings.password.complexity, minLength: 15 } } } });
    mockClient.get.mockResolvedValue({ data: original });
    mockClient.put.mockResolvedValue({ data: afterUpdate });

    const result = await tools.okta_update_password_policy({ policyId: 'pol_abc123', minLength: 15 });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.ok).toBe(true);
    expect(parsed.appliedChanges.minLength).toBe(15);
  });

  test('PUT is called with correct policyId', async () => {
    const original = makePolicy();
    mockClient.get.mockResolvedValue({ data: original });
    mockClient.put.mockResolvedValue({ data: original });

    await tools.okta_update_password_policy({ policyId: 'pol_abc123', minLength: 15 });
    expect(mockClient.put).toHaveBeenCalledWith('/api/v1/policies/pol_abc123', expect.any(Object));
  });

  test('excludeCommonPasswords sets dictionary.common.exclude', async () => {
    const original = makePolicy();
    mockClient.get.mockResolvedValue({ data: original });
    mockClient.put.mockResolvedValue({
      data: makePolicy({
        settings: {
          password: {
            ...original.settings.password,
            complexity: {
              ...original.settings.password.complexity,
              dictionary: { common: { exclude: true } },
            },
          },
        },
      }),
    });

    const result = await tools.okta_update_password_policy({
      policyId: 'pol_abc123',
      excludeCommonPasswords: true,
    });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.ok).toBe(true);
    expect(parsed.appliedChanges.excludeCommonPasswords).toBe(true);
  });

  test('returns findingsBefore and findingsAfter', async () => {
    const original = makePolicy();
    const strongPolicy = makePolicy({
      settings: {
        password: {
          complexity: { minLength: 15, excludeUsername: true, dictionary: { common: { exclude: true } } },
          lockout: { maxAttempts: 10, autoUnlockMinutes: 0, showLockoutFailures: true },
          age: { minAgeMinutes: 1440, historyCount: 5 },
        },
      },
    });
    mockClient.get.mockResolvedValue({ data: original });
    mockClient.put.mockResolvedValue({ data: strongPolicy });

    const result = await tools.okta_update_password_policy({ policyId: 'pol_abc123', minLength: 15 });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.findingsBefore).toBeGreaterThan(parsed.findingsAfter);
  });

  test('returns error on API failure', async () => {
    mockClient.get.mockRejectedValue(new Error('Network error'));
    const result = await tools.okta_update_password_policy({ policyId: 'pol_abc123', minLength: 15 });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.ok).toBe(false);
  });
});
