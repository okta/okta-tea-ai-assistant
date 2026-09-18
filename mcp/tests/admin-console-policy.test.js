'use strict';

const {
  registerAdminConsolePolicyTools,
  parseIso8601ToMinutes,
  minutesToIso8601,
  auditAdminConsoleRule,
  buildAdminConsoleTerraform,
  buildAdminConsoleLogQueries,
  buildAdminConsoleRiskAssessment,
} = require('../src/tools/admin-console-policy');

jest.mock('../src/auth/okta-client', () => ({
  createOktaClient: jest.fn(),
}));

const { createOktaClient } = require('../src/auth/okta-client');

// ── Test helpers ───────────────────────────────────────────────────────────────

function captureTools(registerFn) {
  const tools = {};
  const mockServer = {
    tool(name, _desc, _schema, handler) { tools[name] = handler; },
  };
  registerFn(mockServer);
  return tools;
}

function makeApp(overrides = {}) {
  return {
    id: '0oa_admin_123',
    name: 'okta_admin_console',
    label: 'Okta Admin Console',
    status: 'ACTIVE',
    _links: {
      accessPolicy: { href: 'https://tenant.okta.com/api/v1/policies/rst_policy_1' },
    },
    ...overrides,
  };
}

function makePolicy(overrides = {}) {
  return {
    id: 'rst_policy_1',
    name: 'Admin Console Policy',
    type: 'ACCESS_POLICY',
    status: 'ACTIVE',
    ...overrides,
  };
}

function makeRule(overrides = {}) {
  return {
    id: '0pr_rule_1',
    name: 'Default Rule',
    priority: 99,
    status: 'ACTIVE',
    conditions: {
      network: { connection: 'ANYWHERE' },
    },
    actions: {
      appSignOn: {
        access: 'ALLOW',
        verificationMethod: {
          factorMode: '1FA',
          type: 'ASSURANCE',
          reauthenticateIn: 'PT0S',
        },
      },
    },
    _policyId: 'rst_policy_1',
    ...overrides,
  };
}

function makeHardenedRule(overrides = {}) {
  return makeRule({
    actions: {
      appSignOn: {
        access: 'ALLOW',
        verificationMethod: {
          factorMode: '2FA',
          type: 'ASSURANCE',
          reauthenticateIn: 'PT4H',
          constraints: [{ possession: { phishingResistant: 'REQUIRED' } }],
        },
      },
    },
    ...overrides,
  });
}

// ── parseIso8601ToMinutes ──────────────────────────────────────────────────────

describe('parseIso8601ToMinutes', () => {
  test('PT0S returns 0', () => expect(parseIso8601ToMinutes('PT0S')).toBe(0));
  test('absent returns 0', () => expect(parseIso8601ToMinutes(null)).toBe(0));
  test('PT4H returns 240', () => expect(parseIso8601ToMinutes('PT4H')).toBe(240));
  test('PT1H30M returns 90', () => expect(parseIso8601ToMinutes('PT1H30M')).toBe(90));
  test('PT30M returns 30', () => expect(parseIso8601ToMinutes('PT30M')).toBe(30));
  test('PT12H returns 720', () => expect(parseIso8601ToMinutes('PT12H')).toBe(720));
  test('unparseable string returns 0', () => expect(parseIso8601ToMinutes('INVALID')).toBe(0));
  test('PT30S rounds up to 1 minute', () => expect(parseIso8601ToMinutes('PT30S')).toBe(1));
});

// ── minutesToIso8601 ───────────────────────────────────────────────────────────

describe('minutesToIso8601', () => {
  test('0 returns PT0S', () => expect(minutesToIso8601(0)).toBe('PT0S'));
  test('null returns PT0S', () => expect(minutesToIso8601(null)).toBe('PT0S'));
  test('240 returns PT4H', () => expect(minutesToIso8601(240)).toBe('PT4H'));
  test('90 returns PT1H30M', () => expect(minutesToIso8601(90)).toBe('PT1H30M'));
  test('30 returns PT30M', () => expect(minutesToIso8601(30)).toBe('PT30M'));
  test('720 returns PT12H', () => expect(minutesToIso8601(720)).toBe('PT12H'));
});

// ── auditAdminConsoleRule ──────────────────────────────────────────────────────

describe('auditAdminConsoleRule', () => {
  test('flags ADMIN_CONSOLE_NO_MFA when factorMode is 1FA', () => {
    const result = auditAdminConsoleRule('Test Policy', makeRule(), false);
    expect(result.findings.find((f) => f.id === 'ADMIN_CONSOLE_NO_MFA')).toBeTruthy();
  });

  test('flags ADMIN_CONSOLE_REAUTH_NEVER when reauthenticateIn is PT0S', () => {
    const result = auditAdminConsoleRule('Test Policy', makeRule(), false);
    expect(result.findings.find((f) => f.id === 'ADMIN_CONSOLE_REAUTH_NEVER')).toBeTruthy();
  });

  test('NO_MFA and REAUTH_NEVER are both HIGH severity', () => {
    const result = auditAdminConsoleRule('Test Policy', makeRule(), false);
    const highFindings = result.findings.filter((f) => f.severity === 'HIGH');
    expect(highFindings.length).toBe(2);
    expect(result.highCount).toBe(2);
  });

  test('no findings when rule is fully hardened', () => {
    const result = auditAdminConsoleRule('Test Policy', makeHardenedRule(), false);
    expect(result.findingCount).toBe(0);
  });

  test('flags ADMIN_CONSOLE_REAUTH_TOO_LONG for reauthenticateIn > 4h', () => {
    const rule = makeHardenedRule({
      actions: {
        appSignOn: {
          access: 'ALLOW',
          verificationMethod: { factorMode: '2FA', reauthenticateIn: 'PT12H' },
        },
      },
    });
    const result = auditAdminConsoleRule('Test Policy', rule, false);
    const f = result.findings.find((f) => f.id === 'ADMIN_CONSOLE_REAUTH_TOO_LONG');
    expect(f).toBeTruthy();
    expect(f.severity).toBe('MODERATE');
    expect(f.current).toBe(720);
    expect(f.recommended).toBe(240);
  });

  test('flags ADMIN_CONSOLE_CATCH_ALL_ALLOWS on lowest-priority ALLOW rule', () => {
    const result = auditAdminConsoleRule('Test Policy', makeRule(), true);
    expect(result.findings.find((f) => f.id === 'ADMIN_CONSOLE_CATCH_ALL_ALLOWS')).toBeTruthy();
  });

  test('does NOT flag CATCH_ALL_ALLOWS when isLowestPriority is false', () => {
    const result = auditAdminConsoleRule('Test Policy', makeRule(), false);
    expect(result.findings.find((f) => f.id === 'ADMIN_CONSOLE_CATCH_ALL_ALLOWS')).toBeFalsy();
  });

  test('returns correct current state', () => {
    const result = auditAdminConsoleRule('Test Policy', makeRule(), false);
    expect(result.current.factorMode).toBe('1FA');
    expect(result.current.reauthenticateIn).toBe('PT0S');
    expect(result.current.reauthenticateInMinutes).toBe(0);
    expect(result.current.networkConnection).toBe('ANYWHERE');
  });

  test('defaults factorMode to 1FA when missing from rule', () => {
    const rule = makeRule({
      actions: { appSignOn: { access: 'ALLOW', verificationMethod: {} } },
    });
    const result = auditAdminConsoleRule('Test Policy', rule, false);
    expect(result.findings.find((f) => f.id === 'ADMIN_CONSOLE_NO_MFA')).toBeTruthy();
  });

  test('defaults reauthenticateIn to PT0S when missing from rule', () => {
    const rule = makeRule({
      actions: { appSignOn: { access: 'ALLOW', verificationMethod: { factorMode: '2FA' } } },
    });
    const result = auditAdminConsoleRule('Test Policy', rule, false);
    expect(result.findings.find((f) => f.id === 'ADMIN_CONSOLE_REAUTH_NEVER')).toBeTruthy();
  });
});

// ── buildAdminConsoleTerraform ────────────────────────────────────────────────

describe('buildAdminConsoleTerraform', () => {
  const auditResult = auditAdminConsoleRule('Admin Console Policy', makeRule(), false);

  test('includes app and policy IDs in comments', () => {
    const tf = buildAdminConsoleTerraform(makeApp(), makePolicy(), [auditResult]);
    expect(tf).toContain('0oa_admin_123');
    expect(tf).toContain('rst_policy_1');
  });

  test('sets factor_mode to 2FA', () => {
    const tf = buildAdminConsoleTerraform(makeApp(), makePolicy(), [auditResult]);
    expect(tf).toContain('factor_mode                 = "2FA"');
  });

  test('sets re_authentication_frequency to PT4H', () => {
    const tf = buildAdminConsoleTerraform(makeApp(), makePolicy(), [auditResult]);
    expect(tf).toContain('re_authentication_frequency = "PT4H"');
  });

  test('includes okta_app_signon_policy_rule resource', () => {
    const tf = buildAdminConsoleTerraform(makeApp(), makePolicy(), [auditResult]);
    expect(tf).toContain('resource "okta_app_signon_policy_rule"');
  });
});

// ── buildAdminConsoleLogQueries ───────────────────────────────────────────────

describe('buildAdminConsoleLogQueries', () => {
  test('returns non-empty array', () => {
    expect(buildAdminConsoleLogQueries().length).toBeGreaterThan(0);
  });

  test('includes admin app access event query', () => {
    const queries = buildAdminConsoleLogQueries();
    expect(queries.some((q) => q.filter.includes('access_admin_app'))).toBe(true);
  });
});

// ── buildAdminConsoleRiskAssessment ───────────────────────────────────────────

describe('buildAdminConsoleRiskAssessment', () => {
  test('changeRisk is LOW', () => {
    expect(buildAdminConsoleRiskAssessment().changeRisk).toBe('LOW');
  });

  test('includes rollout steps', () => {
    const ra = buildAdminConsoleRiskAssessment();
    expect(ra.rolloutSteps.length).toBeGreaterThan(0);
  });
});

// ── okta_list_admin_console_policy ───────────────────────────────────────────
//
// New discovery order:
//   Path A (primary)  — GET /api/v1/policies?type=ACCESS_POLICY  (okta.policies.read only)
//                       + GET /api/v1/apps (enrichment, non-fatal)
//                       + GET /api/v1/policies/{id}/rules
//   Path B (fallback) — GET /api/v1/apps?filter=...
//                       + GET /api/v1/policies/{id} (via _links)
//                       + GET /api/v1/policies/{id}/rules

describe('okta_list_admin_console_policy', () => {
  let tools;
  let mockClient;

  beforeEach(() => {
    mockClient = { get: jest.fn() };
    createOktaClient.mockResolvedValue(mockClient);
    tools = captureTools(registerAdminConsolePolicyTools);
  });

  // Path A: policies API finds the policy by name pattern
  test('returns ok:true via Path A (policies API)', async () => {
    mockClient.get
      .mockResolvedValueOnce({ data: [makePolicy()] })  // Path A: policies list — name matches
      .mockResolvedValueOnce({ data: [makeApp()] })     // Path A: app enrichment
      .mockResolvedValueOnce({ data: [makeRule()] });   // rules fetch

    const result = await tools.okta_list_admin_console_policy({});
    const parsed = JSON.parse(result.content[0].text);

    expect(parsed.ok).toBe(true);
    expect(parsed.summary.policyId).toBe('rst_policy_1');
    expect(parsed.summary.totalRules).toBe(1);
    expect(parsed.summary.totalFindings).toBeGreaterThan(0);
  });

  test('flags HIGH findings on a default unhardened rule (Path A)', async () => {
    mockClient.get
      .mockResolvedValueOnce({ data: [makePolicy()] })
      .mockResolvedValueOnce({ data: [makeApp()] })
      .mockResolvedValueOnce({ data: [makeRule()] });

    const result = await tools.okta_list_admin_console_policy({});
    const parsed = JSON.parse(result.content[0].text);
    const rule = parsed.rules[0];

    expect(rule.findings.find((f) => f.id === 'ADMIN_CONSOLE_NO_MFA')).toBeTruthy();
    expect(rule.findings.find((f) => f.id === 'ADMIN_CONSOLE_REAUTH_NEVER')).toBeTruthy();
  });

  test('zero findings when rule is fully hardened (Path A)', async () => {
    mockClient.get
      .mockResolvedValueOnce({ data: [makePolicy()] })
      .mockResolvedValueOnce({ data: [makeApp()] })
      .mockResolvedValueOnce({ data: [makeHardenedRule()] });

    const result = await tools.okta_list_admin_console_policy({});
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.summary.totalFindings).toBe(0);
  });

  // Path A succeeds even when the apps API returns 403 — the key scenario this refactor fixes
  test('succeeds via Path A even when apps API returns 403', async () => {
    const appsError = new Error('Forbidden');
    appsError.response = { status: 403, data: { errorCode: 'E0000006' } };

    mockClient.get
      .mockResolvedValueOnce({ data: [makePolicy()] })  // Path A: policies list — match found
      .mockRejectedValueOnce(appsError)                 // Path A: app enrichment 403 — non-fatal
      .mockResolvedValueOnce({ data: [makeRule()] });   // rules fetch

    const result = await tools.okta_list_admin_console_policy({});
    const parsed = JSON.parse(result.content[0].text);

    expect(parsed.ok).toBe(true);
    // app info is null but policy was still found
    expect(parsed.summary.appId).toBeNull();
    expect(parsed.summary.policyId).toBe('rst_policy_1');
    expect(parsed.summary.totalFindings).toBeGreaterThan(0);
  });

  // Path B: policies API returns no name match, falls back to apps API
  test('falls back to Path B (apps API) when policies API has no name match', async () => {
    const unrelatedPolicy = makePolicy({ id: 'rst_other', name: 'Some Other Policy' });
    mockClient.get
      .mockResolvedValueOnce({ data: [unrelatedPolicy] }) // Path A: no match
      .mockResolvedValueOnce({ data: [makeApp()] })       // Path B: apps name filter
      .mockResolvedValueOnce({ data: makePolicy() })      // Path B: resolve policy via _links
      .mockResolvedValueOnce({ data: [makeRule()] });     // rules fetch

    const result = await tools.okta_list_admin_console_policy({});
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.ok).toBe(true);
    expect(parsed.summary.policyId).toBe('rst_policy_1');
  });

  // Both paths fail → error with diagnostics
  test('returns error with diagnostics when both paths fail', async () => {
    mockClient.get
      .mockResolvedValueOnce({ data: [makePolicy({ id: 'other', name: 'Unrelated Policy' })] }) // Path A: no match
      .mockResolvedValueOnce({ data: [] })  // Path B: apps name filter empty
      .mockResolvedValueOnce({ data: [] }); // Path B: apps label search empty

    const result = await tools.okta_list_admin_console_policy({});
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.ok).toBe(false);
    expect(result.isError).toBe(true);
    expect(parsed.error).toContain('diagnostics');
  });

  test('catches lowest-priority catch-all rule', async () => {
    const ruleHigh = makeRule({ id: '0pr_rule_high', priority: 1 });
    const ruleLow = makeRule({ id: '0pr_rule_low', priority: 99 });
    mockClient.get
      .mockResolvedValueOnce({ data: [makePolicy()] })
      .mockResolvedValueOnce({ data: [makeApp()] })
      .mockResolvedValueOnce({ data: [ruleHigh, ruleLow] });

    const result = await tools.okta_list_admin_console_policy({});
    const parsed = JSON.parse(result.content[0].text);
    const lowRule = parsed.rules.find((r) => r.ruleId === '0pr_rule_low');
    expect(lowRule.findings.find((f) => f.id === 'ADMIN_CONSOLE_CATCH_ALL_ALLOWS')).toBeTruthy();

    const highRule = parsed.rules.find((r) => r.ruleId === '0pr_rule_high');
    expect(highRule.findings.find((f) => f.id === 'ADMIN_CONSOLE_CATCH_ALL_ALLOWS')).toBeFalsy();
  });

  test('returns error on authentication failure', async () => {
    createOktaClient.mockRejectedValue(new Error('Unauthorized'));
    const result = await tools.okta_list_admin_console_policy({});
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.ok).toBe(false);
    expect(result.isError).toBe(true);
  });
});

// ── okta_update_admin_console_policy_rule ────────────────────────────────────

describe('okta_update_admin_console_policy_rule', () => {
  let tools;
  let mockClient;

  beforeEach(() => {
    mockClient = { get: jest.fn(), put: jest.fn() };
    createOktaClient.mockResolvedValue(mockClient);
    tools = captureTools(registerAdminConsolePolicyTools);
  });

  test('returns error when no settings provided', async () => {
    const result = await tools.okta_update_admin_console_policy_rule({
      policyId: 'rst_policy_1', ruleId: '0pr_rule_1',
    });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.ok).toBe(false);
    expect(result.isError).toBe(true);
  });

  test('sets factorMode to 2FA on the rule', async () => {
    mockClient.get
      .mockResolvedValueOnce({ data: makePolicy() })       // policy fetch (parallel)
      .mockResolvedValueOnce({ data: makeRule() })         // rule fetch (parallel)
      .mockResolvedValueOnce({ data: [makePolicy()] })     // discoverAdminConsolePolicy Path A
      .mockResolvedValueOnce({ data: [makeApp()] });       // app enrichment

    mockClient.put.mockResolvedValue({ data: makeHardenedRule() });

    const result = await tools.okta_update_admin_console_policy_rule({
      policyId: 'rst_policy_1',
      ruleId: '0pr_rule_1',
      factorMode: '2FA',
    });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.ok).toBe(true);
    expect(parsed.appliedChanges.factorMode).toBe('2FA');
  });

  test('converts reauthenticateInMinutes to ISO 8601 in the PUT body', async () => {
    mockClient.get
      .mockResolvedValueOnce({ data: makePolicy() })
      .mockResolvedValueOnce({ data: makeRule() })
      .mockResolvedValueOnce({ data: [makePolicy()] })
      .mockResolvedValueOnce({ data: [makeApp()] });

    mockClient.put.mockResolvedValue({ data: makeHardenedRule() });

    await tools.okta_update_admin_console_policy_rule({
      policyId: 'rst_policy_1',
      ruleId: '0pr_rule_1',
      reauthenticateInMinutes: 240,
    });

    const [, body] = mockClient.put.mock.calls[0];
    expect(body.actions.appSignOn.verificationMethod.reauthenticateIn).toBe('PT4H');
  });

  test('appliedChanges includes both reauthenticateInMinutes and ISO string', async () => {
    mockClient.get
      .mockResolvedValueOnce({ data: makePolicy() })
      .mockResolvedValueOnce({ data: makeRule() })
      .mockResolvedValueOnce({ data: [makePolicy()] })
      .mockResolvedValueOnce({ data: [makeApp()] });

    mockClient.put.mockResolvedValue({ data: makeHardenedRule() });

    const result = await tools.okta_update_admin_console_policy_rule({
      policyId: 'rst_policy_1',
      ruleId: '0pr_rule_1',
      reauthenticateInMinutes: 240,
    });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.appliedChanges.reauthenticateInMinutes).toBe(240);
    expect(parsed.appliedChanges.reauthenticateIn).toBe('PT4H');
  });

  test('PUT preserves all existing rule fields (deep clone)', async () => {
    const ruleWithConditions = makeRule({
      conditions: {
        network: { connection: 'ZONE', include: ['zone123'] },
        groups: { include: ['grp456'] },
      },
    });
    mockClient.get
      .mockResolvedValueOnce({ data: makePolicy() })
      .mockResolvedValueOnce({ data: ruleWithConditions })
      .mockResolvedValueOnce({ data: [makePolicy()] })
      .mockResolvedValueOnce({ data: [makeApp()] });

    mockClient.put.mockResolvedValue({ data: makeHardenedRule() });

    await tools.okta_update_admin_console_policy_rule({
      policyId: 'rst_policy_1',
      ruleId: '0pr_rule_1',
      factorMode: '2FA',
    });

    const [, body] = mockClient.put.mock.calls[0];
    expect(body.conditions.network.connection).toBe('ZONE');
    expect(body.conditions.groups.include).toContain('grp456');
  });

  test('returns error when wrong policy type is provided', async () => {
    mockClient.get
      .mockResolvedValueOnce({ data: makePolicy({ type: 'OKTA_SIGN_ON' }) })
      .mockResolvedValueOnce({ data: makeRule() });

    const result = await tools.okta_update_admin_console_policy_rule({
      policyId: 'rst_policy_1',
      ruleId: '0pr_rule_1',
      factorMode: '2FA',
    });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.ok).toBe(false);
    expect(parsed.error).toContain('ACCESS_POLICY');
  });

  test('findingsBefore and findingsAfter reflect the actual change', async () => {
    mockClient.get
      .mockResolvedValueOnce({ data: makePolicy() })
      .mockResolvedValueOnce({ data: makeRule() })         // before: 1FA + PT0S
      .mockResolvedValueOnce({ data: [makePolicy()] })     // discoverAdminConsolePolicy Path A
      .mockResolvedValueOnce({ data: [makeApp()] });       // app enrichment

    mockClient.put.mockResolvedValue({ data: makeHardenedRule() });

    const result = await tools.okta_update_admin_console_policy_rule({
      policyId: 'rst_policy_1',
      ruleId: '0pr_rule_1',
      factorMode: '2FA',
      reauthenticateInMinutes: 240,
    });
    const parsed = JSON.parse(result.content[0].text);
    expect(parsed.findingsBefore).toBeGreaterThan(0);
    expect(parsed.findingsAfter).toBe(0);
  });
});
