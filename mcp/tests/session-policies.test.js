'use strict';

const {
  registerSessionPolicyTools,
  auditSessionPolicyRule,
  buildSessionPolicyTerraform,
  buildSessionPolicyLogQueries,
  buildSessionPolicyRiskAssessment,
} = require('../src/tools/session-policies');

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
    id: 'pol_session_1',
    name: 'Default Policy',
    type: 'OKTA_SIGN_ON',
    status: 'ACTIVE',
    ...overrides,
  };
}

function makeRule(overrides = {}) {
  return {
    id: 'rule_1',
    name: 'Default Rule',
    type: 'SIGN_ON',
    priority: 99,
    status: 'ACTIVE',
    _policyId: 'pol_session_1',
    actions: {
      signon: {
        access: 'ALLOW',
        requireFactor: false,
        factorPromptMode: 'ALWAYS',
        session: {
          usePersistentCookie: false,
          maxSessionIdleMinutes: 600,
          maxSessionLifetimeMinutes: 0,
        },
      },
    },
    ...overrides,
  };
}

// ── auditSessionPolicyRule ─────────────────────────────────────────────────────

describe('auditSessionPolicyRule', () => {
  test('flags all three findings on a weak rule', () => {
    const result = auditSessionPolicyRule('Default Policy', makeRule());
    const ids = result.findings.map((f) => f.id);
    expect(ids).toContain('MFA_NOT_REQUIRED');
    expect(ids).toContain('SESSION_LIFETIME');
    expect(ids).toContain('SESSION_IDLE');
  });

  test('no findings on a hardened rule', () => {
    const rule = makeRule({
      actions: {
        signon: {
          access: 'ALLOW',
          requireFactor: true,
          session: {
            maxSessionLifetimeMinutes: 720,
            maxSessionIdleMinutes: 120,
            usePersistentCookie: false,
          },
        },
      },
    });
    const result = auditSessionPolicyRule('Default Policy', rule);
    expect(result.findingCount).toBe(0);
  });

  test('flags SESSION_LIFETIME when unlimited (0)', () => {
    const rule = makeRule({
      actions: { signon: { requireFactor: true, session: { maxSessionLifetimeMinutes: 0, maxSessionIdleMinutes: 120 } } },
    });
    const result = auditSessionPolicyRule('Policy', rule);
    expect(result.findings.find((f) => f.id === 'SESSION_LIFETIME')).toBeTruthy();
  });

  test('flags SESSION_LIFETIME when greater than 720', () => {
    const rule = makeRule({
      actions: { signon: { requireFactor: true, session: { maxSessionLifetimeMinutes: 1440, maxSessionIdleMinutes: 120 } } },
    });
    const result = auditSessionPolicyRule('Policy', rule);
    expect(result.findings.find((f) => f.id === 'SESSION_LIFETIME')).toBeTruthy();
  });

  test('does NOT flag SESSION_LIFETIME when exactly 720', () => {
    const rule = makeRule({
      actions: { signon: { requireFactor: true, session: { maxSessionLifetimeMinutes: 720, maxSessionIdleMinutes: 120 } } },
    });
    const result = auditSessionPolicyRule('Policy', rule);
    expect(result.findings.find((f) => f.id === 'SESSION_LIFETIME')).toBeUndefined();
  });

  test('flags SESSION_IDLE when idle > 120', () => {
    const rule = makeRule({
      actions: { signon: { requireFactor: true, session: { maxSessionLifetimeMinutes: 720, maxSessionIdleMinutes: 600 } } },
    });
    const result = auditSessionPolicyRule('Policy', rule);
    expect(result.findings.find((f) => f.id === 'SESSION_IDLE')).toBeTruthy();
    expect(result.findings.find((f) => f.id === 'SESSION_IDLE').severity).toBe('MODERATE');
  });

  test('does NOT flag SESSION_IDLE when exactly 120', () => {
    const rule = makeRule({
      actions: { signon: { requireFactor: true, session: { maxSessionLifetimeMinutes: 720, maxSessionIdleMinutes: 120 } } },
    });
    const result = auditSessionPolicyRule('Policy', rule);
    expect(result.findings.find((f) => f.id === 'SESSION_IDLE')).toBeUndefined();
  });

  test('returns policyId and ruleId from rule', () => {
    const result = auditSessionPolicyRule('Default Policy', makeRule());
    expect(result.policyId).toBe('pol_session_1');
    expect(result.ruleId).toBe('rule_1');
  });

  test('handles missing signon actions gracefully', () => {
    const rule = makeRule({ actions: {} });
    const result = auditSessionPolicyRule('Policy', rule);
    expect(result.findingCount).toBeGreaterThan(0);
  });
});

// ── buildSessionPolicyTerraform ───────────────────────────────────────────────

describe('buildSessionPolicyTerraform', () => {
  test('includes policy and rule IDs in comments', () => {
    const tf = buildSessionPolicyTerraform(makePolicy(), makeRule());
    expect(tf).toContain('pol_session_1');
    expect(tf).toContain('rule_1');
  });

  test('references TEA Findings in comments', () => {
    const tf = buildSessionPolicyTerraform(makePolicy(), makeRule());
    expect(tf).toContain('TEA Finding — require MFA');
    expect(tf).toContain('TEA Finding — cap session lifetime');
    expect(tf).toContain('TEA Finding — idle timeout');
  });

  test('includes signon policy and rule resources', () => {
    const tf = buildSessionPolicyTerraform(makePolicy(), makeRule());
    expect(tf).toContain('resource "okta_policy_signon"');
    expect(tf).toContain('resource "okta_policy_rule_signon"');
  });
});

// ── buildSessionPolicyLogQueries ──────────────────────────────────────────────

describe('buildSessionPolicyLogQueries', () => {
  test('returns non-empty array with required fields', () => {
    const queries = buildSessionPolicyLogQueries();
    expect(queries.length).toBeGreaterThan(0);
    for (const q of queries) {
      expect(q).toHaveProperty('filter');
      expect(q).toHaveProperty('description');
    }
  });
});

// ── buildSessionPolicyRiskAssessment ──────────────────────────────────────────

describe('buildSessionPolicyRiskAssessment', () => {
  test('has required fields', () => {
    const ra = buildSessionPolicyRiskAssessment();
    expect(ra).toHaveProperty('teaSeverity');
    expect(ra).toHaveProperty('summary');
    expect(ra).toHaveProperty('rolloutSteps');
  });
});

// ── okta_list_session_policies tool ──────────────────────────────────────────

describe('okta_list_session_policies', () => {
  let tools;
  let mockClient;

  beforeEach(() => {
    mockClient = { get: jest.fn() };
    createOktaClient.mockResolvedValue(mockClient);
    tools = captureTools(registerSessionPolicyTools);
  });

  test('returns ok:true with audit summary', async () => {
    mockClient.get
      .mockResolvedValueOnce({ data: [makePolicy()] })          // policies list
      .mockResolvedValueOnce({ data: [makeRule()] });            // rules for policy

    const result = await tools.okta_list_session_policies({});
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.ok).toBe(true);
    expect(parsed.summary.totalPolicies).toBe(1);
    expect(parsed.summary.totalRules).toBe(1);
  });

  test('aggregates findings across multiple rules', async () => {
    mockClient.get
      .mockResolvedValueOnce({ data: [makePolicy()] })
      .mockResolvedValueOnce({ data: [makeRule(), makeRule({ id: 'rule_2', name: 'Rule 2' })] });

    const result = await tools.okta_list_session_policies({});
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.summary.totalRules).toBe(2);
    expect(parsed.summary.totalFindings).toBeGreaterThan(0);
  });

  test('returns error on API failure', async () => {
    createOktaClient.mockRejectedValue(new Error('Auth error'));
    const result = await tools.okta_list_session_policies({});
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.ok).toBe(false);
    expect(result.isError).toBe(true);
  });

  test('includes terraform and log queries in remediation', async () => {
    mockClient.get
      .mockResolvedValueOnce({ data: [makePolicy()] })
      .mockResolvedValueOnce({ data: [makeRule()] });

    const result = await tools.okta_list_session_policies({});
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.remediation.terraform).toBeTruthy();
    expect(parsed.remediation.logQueries).toBeTruthy();
  });
});

// ── okta_update_session_policy_rule tool ──────────────────────────────────────

describe('okta_update_session_policy_rule', () => {
  let tools;
  let mockClient;

  beforeEach(() => {
    mockClient = { get: jest.fn(), put: jest.fn() };
    createOktaClient.mockResolvedValue(mockClient);
    tools = captureTools(registerSessionPolicyTools);
  });

  test('returns error for wrong policy type', async () => {
    mockClient.get
      .mockResolvedValueOnce({ data: makePolicy({ type: 'PASSWORD' }) })
      .mockResolvedValueOnce({ data: makeRule() });

    const result = await tools.okta_update_session_policy_rule({
      policyId: 'pol_session_1',
      ruleId: 'rule_1',
      requireFactor: true,
    });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.ok).toBe(false);
    expect(result.isError).toBe(true);
  });

  test('updates requireFactor and returns success', async () => {
    const rule = makeRule();
    const updatedRule = makeRule({ actions: { signon: { ...rule.actions.signon, requireFactor: true } } });
    mockClient.get
      .mockResolvedValueOnce({ data: makePolicy() })
      .mockResolvedValueOnce({ data: rule });
    mockClient.put.mockResolvedValue({ data: updatedRule });

    const result = await tools.okta_update_session_policy_rule({
      policyId: 'pol_session_1',
      ruleId: 'rule_1',
      requireFactor: true,
    });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.ok).toBe(true);
    expect(parsed.appliedChanges.requireFactor).toBe(true);
  });

  test('PUT is called with correct path', async () => {
    const rule = makeRule();
    mockClient.get
      .mockResolvedValueOnce({ data: makePolicy() })
      .mockResolvedValueOnce({ data: rule });
    mockClient.put.mockResolvedValue({ data: rule });

    await tools.okta_update_session_policy_rule({
      policyId: 'pol_session_1',
      ruleId: 'rule_1',
      maxSessionLifetimeMinutes: 720,
    });
    expect(mockClient.put).toHaveBeenCalledWith(
      '/api/v1/policies/pol_session_1/rules/rule_1',
      expect.any(Object),
    );
  });

  test('returns findingsBefore and findingsAfter', async () => {
    const weak = makeRule();
    const strong = makeRule({
      actions: {
        signon: {
          requireFactor: true,
          session: { maxSessionLifetimeMinutes: 720, maxSessionIdleMinutes: 120 },
        },
      },
    });
    mockClient.get
      .mockResolvedValueOnce({ data: makePolicy() })
      .mockResolvedValueOnce({ data: weak });
    mockClient.put.mockResolvedValue({ data: strong });

    const result = await tools.okta_update_session_policy_rule({
      policyId: 'pol_session_1',
      ruleId: 'rule_1',
      requireFactor: true,
      maxSessionLifetimeMinutes: 720,
      maxSessionIdleMinutes: 120,
    });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.findingsBefore).toBeGreaterThan(parsed.findingsAfter);
  });
});
