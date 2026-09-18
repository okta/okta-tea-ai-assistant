'use strict';

const { z } = require('zod');
const { buildMcpOk, buildMcpError, buildMcpOffline, buildMcpReadOnly } = require('./resolver-utils');
const { createOktaClient } = require('../auth/okta-client');

const POLICY_TYPE = 'PASSWORD';
const MIN_LENGTH_RECOMMENDED     = 15;
const MIN_AGE_MINUTES_RECOMMENDED = 1440; // 24 hours
const MAX_ATTEMPTS_RECOMMENDED   = 10;
const MIN_HISTORY_COUNT          = 4;

// ── Audit helpers ──────────────────────────────────────────────────────────────

function auditPolicy(policy) {
  const pw         = policy.settings?.password || {};
  const complexity = pw.complexity || {};
  const lockout    = pw.lockout || {};
  const age        = pw.age || {};
  const breached   = pw.breachedProtection || {};

  const findings = [];

  // minimum password length
  if ((complexity.minLength || 0) < MIN_LENGTH_RECOMMENDED) {
    findings.push({
      id: 'MIN_LENGTH',
      severity: 'HIGH',
      description: `Minimum length is ${complexity.minLength || 'not set'} — must be ≥ ${MIN_LENGTH_RECOMMENDED} (NIST SP 800-63B).`,
      recommendation: `Set minLength to ${MIN_LENGTH_RECOMMENDED}.`,
    });
  }

  // brute force: username exclusion
  if (complexity.excludeUsername !== true) {
    findings.push({
      id: 'EXCLUDE_USERNAME',
      severity: 'HIGH',
      description: 'Users may include their username in passwords.',
      recommendation: 'Set excludeUsername to true.',
    });
  }

  // brute force: common password dictionary
  if (!complexity.dictionary?.common?.exclude) {
    findings.push({
      id: 'COMMON_PASSWORDS',
      severity: 'HIGH',
      description: 'Common passwords are not blocked.',
      recommendation: 'Enable dictionary.common.exclude.',
    });
  }

  // lockout maxAttempts
  if (!lockout.maxAttempts || lockout.maxAttempts > MAX_ATTEMPTS_RECOMMENDED) {
    findings.push({
      id: 'LOCKOUT_ATTEMPTS',
      severity: 'HIGH',
      description: `Lockout maxAttempts is ${lockout.maxAttempts ?? 'not set'} — should be ≤ ${MAX_ATTEMPTS_RECOMMENDED}.`,
      recommendation: `Set maxAttempts to ${MAX_ATTEMPTS_RECOMMENDED}.`,
    });
  }

  // character class requirements (PasswordPolicyCharacters — LOW)
  const missingClasses = [];
  if ((complexity.minLowerCase ?? 0) === 0) missingClasses.push('lowercase');
  if ((complexity.minUpperCase ?? 0) === 0) missingClasses.push('uppercase');
  if ((complexity.minNumber    ?? 0) === 0) missingClasses.push('numbers');
  if ((complexity.minSymbol    ?? 0) === 0) missingClasses.push('symbols');
  if (missingClasses.length > 0) {
    findings.push({
      id: 'CHARACTER_REQUIREMENTS',
      severity: 'LOW',
      description: `Policy does not require: ${missingClasses.join(', ')}. All four character classes strengthen password entropy.`,
      recommendation: `Set minLowerCase, minUpperCase, minNumber, and minSymbol to at least 1 each.`,
    });
  }

  // password history / reuse prevention (PasswordPolicyPreventPasswordReuse — LOW)
  if ((age.historyCount ?? 0) < MIN_HISTORY_COUNT) {
    findings.push({
      id: 'PASSWORD_HISTORY',
      severity: 'LOW',
      description: `Password history is ${age.historyCount ?? 'not set'} — should be ≥ ${MIN_HISTORY_COUNT} to prevent reuse of recent passwords.`,
      recommendation: `Set historyCount to at least ${MIN_HISTORY_COUNT}.`,
    });
  }

  // breached credential detection (PasswordPolicyBreachedPasswordDetectionEnabled — MODERATE)
  // "Good" state: logoutEnabled === true AND expireAfterDays === 0 (terminate sessions, force-reset immediately)
  const breachedFullyEnabled = breached.logoutEnabled === true && (breached.expireAfterDays ?? -1) === 0;
  if (!breachedFullyEnabled) {
    findings.push({
      id: 'BREACHED_CREDENTIAL_DETECTION',
      severity: 'MODERATE',
      description:
        'Breached credential detection is not fully enabled on this policy. ' +
        'The strongest configuration sets logoutEnabled: true (terminate active sessions on detection) ' +
        'and expireAfterDays: 0 (force immediate password reset). ' +
        (breached.logoutEnabled !== true
          ? 'logoutEnabled is currently not true. '
          : '') +
        ((breached.expireAfterDays ?? -1) !== 0
          ? `expireAfterDays is currently ${breached.expireAfterDays ?? 'not set'} (should be 0). `
          : ''),
      recommendation:
        'Under Security > Authenticators > Password > Edit policy, enable ' +
        '"Breached password detection" with action "Force user to reset password" and logout enabled.',
    });
  }

  // minimum password age
  if ((age.minAgeMinutes || 0) < MIN_AGE_MINUTES_RECOMMENDED) {
    findings.push({
      id: 'MIN_AGE',
      severity: 'LOW',
      description: `Minimum age is ${age.minAgeMinutes || 'not set'} minutes — should be ≥ ${MIN_AGE_MINUTES_RECOMMENDED} (24 h) to prevent rapid cycling.`,
      recommendation: `Set minAgeMinutes to ${MIN_AGE_MINUTES_RECOMMENDED}.`,
    });
  }

  // lockout email notification
  if (!lockout.showLockoutFailures) {
    findings.push({
      id: 'LOCKOUT_EMAIL',
      severity: 'INFO',
      description: 'Users are not notified when locked out.',
      recommendation: 'Set showLockoutFailures to true.',
    });
  }

  return {
    policyId: policy.id,
    policyName: policy.name,
    status: policy.status,
    findingCount: findings.length,
    highCount: findings.filter((f) => f.severity === 'HIGH').length,
    findings,
    current: {
      minLength:               complexity.minLength,
      minLowerCase:            complexity.minLowerCase,
      minUpperCase:            complexity.minUpperCase,
      minNumber:               complexity.minNumber,
      minSymbol:               complexity.minSymbol,
      excludeUsername:         complexity.excludeUsername,
      commonPasswordsExcluded: complexity.dictionary?.common?.exclude ?? false,
      historyCount:            age.historyCount,
      maxAttempts:             lockout.maxAttempts,
      autoUnlockMinutes:       lockout.autoUnlockMinutes,
      showLockoutFailures:     lockout.showLockoutFailures,
      minAgeMinutes:           age.minAgeMinutes,
      breachedProtection: {
        logoutEnabled:    breached.logoutEnabled ?? null,
        expireAfterDays:  breached.expireAfterDays ?? null,
      },
    },
  };
}

// ── Terraform builder ──────────────────────────────────────────────────────────

function buildPasswordPolicyTerraform(policy) {
  const pw         = policy.settings?.password || {};
  const complexity = pw.complexity || {};
  const lockout    = pw.lockout || {};
  const age        = pw.age || {};

  const resourceLabel = (policy.name || policy.id)
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '') || 'password_policy';

  return `# Terraform — Okta Password Policy (TEA hardening)
#
# Provider setup:
#   https://developer.okta.com/docs/guides/terraform-enable-org-access/main/
# Resource reference:
#   https://registry.terraform.io/providers/okta/okta/latest/docs/resources/policy_password

terraform {
  required_providers {
    okta = {
      source  = "okta/okta"
      version = "~> 4.0"
    }
  }
}

provider "okta" {
  org_name    = "<YOUR_OKTA_ORG>"
  base_url    = "okta.com"
  client_id   = "<YOUR_CLIENT_ID>"
  scopes      = ["okta.policies.manage"]
  private_key = "<PATH_OR_CONTENT_OF_PRIVATE_KEY>"
}

# Policy ID: ${policy.id}
resource "okta_policy_password" "${resourceLabel}" {
  name   = "${policy.name}"
  status = "${policy.status || 'ACTIVE'}"

  # TEA Finding  — minimum length (≥ 15, NIST SP 800-63B)
  password_min_length = ${complexity.minLength ?? MIN_LENGTH_RECOMMENDED}

  # character class requirements
  password_min_lowercase = ${complexity.minLowerCase ?? 1}
  password_min_uppercase = ${complexity.minUpperCase ?? 1}
  password_min_number    = ${complexity.minNumber ?? 1}
  password_min_symbol    = ${complexity.minSymbol ?? 1}

  # TEA Finding  — brute force protection
  password_exclude_username  = ${complexity.excludeUsername ?? true}
  password_dictionary_lookup = ${complexity.dictionary?.common?.exclude ?? true}

  # TEA Finding  — lockout
  password_lockout_tries       = ${lockout.maxAttempts ?? MAX_ATTEMPTS_RECOMMENDED}
  password_auto_unlock_minutes = ${lockout.autoUnlockMinutes ?? 0}

  # TEA Finding  — minimum password age (prevents rapid cycling; history prevents reuse)
  password_min_age_minutes = ${age.minAgeMinutes ?? MIN_AGE_MINUTES_RECOMMENDED}
  password_history_count   = ${age.historyCount ?? MIN_HISTORY_COUNT}

  # notify user on lockout
  password_show_lockout_failures = ${lockout.showLockoutFailures ?? true}

  # Breached credential detection: configure via Security > Authenticators > Password > Edit policy
  # in the Admin Console (select "Force user to reset password" with logout enabled).
  # The okta_policy_password Terraform resource does not expose breachedProtection directly —
  # use the Okta Admin Console or the Policies API PATCH to set:
  #   settings.password.breachedProtection.logoutEnabled = true
  #   settings.password.breachedProtection.expireAfterDays = 0
}
`;
}

// ── Log queries ────────────────────────────────────────────────────────────────

function buildPasswordPolicyLogQueries() {
  return [
    {
      description: 'Password policy changes — audit trail',
      filter: 'eventType eq "policy.lifecycle.update"',
      timeWindow: 'last 90 days',
      note: 'Tracks who changed password policy settings and when.',
    },
    {
      description: 'Account lockout events — brute force protection active',
      filter: 'eventType eq "user.account.lock"',
      timeWindow: 'last 30 days',
      note: 'Confirm lockout policy is triggering. Spike after policy change indicates correct enforcement.',
    },
    {
      description: 'Lockout notification emails sent',
      filter: 'eventType eq "system.email.account_unlock.sent_message"',
      timeWindow: 'last 7 days',
      note: 'Verify lockout emails fire after enabling showLockoutFailures.',
    },
    {
      description: 'Breached credential detections',
      filter: 'eventType eq "security.breached_credential.detected"',
      timeWindow: 'last 30 days',
      note: 'Monitor for breached credentials caught by Okta\'s protection layer.',
    },
    {
      description: 'Password changes — volume indicator after min-length increase',
      filter: 'eventType eq "user.account.update_password"',
      timeWindow: 'last 7 days',
      note: 'Watch for gradual increase in password changes after raising minimum length — existing users comply at next reset or expiry, not immediately at login.',
    },
  ];
}

// ── Admin console steps ────────────────────────────────────────────────────────

function buildPasswordPolicyAdminSteps(policyName) {
  return [
    'Sign in to the Okta Admin Console.',
    'Go to Security > Authenticators, click the Password authenticator, then open the Enrollment tab to see which policies apply.',
    `Navigate to Security > Authentication > Password (or find the policy named "${policyName}").`,
    'Click the policy name, then click "Edit" on the settings.',
    'Under Password Settings, configure:',
    '  • Minimum length: 15',
    '  • Enable "Does not contain username"',
    '  • Enable "Does not contain commonly used password"',
    '  • Character requirements: enable Lowercase letter, Uppercase letter, Number, and Symbol (≥ 1 each)',
    '  • Password history: enforce last 4 passwords (prevents reuse)',
    '  • Max attempts before lockout: 10',
    '  • Enable "Send lockout email to user"',
    '  • Minimum password age: 1 day / 1440 minutes',
    'Click Save.',
    'Under the same policy, scroll to "Breached Password Detection":',
    '  • Enable breached password detection',
    '  • Set action to "Force user to reset password"',
    '  • Enable "Log out all active sessions when breached password is detected"',
    'Click Save.',
    'Verify via Reports > System Log: filter eventType eq "policy.lifecycle.update".',
  ];
}

// ── Risk assessment ────────────────────────────────────────────────────────────

function buildPasswordPolicyRiskAssessment() {
  return {
    teaSeverity: 'HIGH',
    changeRisk:  'LOW',
    summary:
      'Password policy hardening reduces credential-based attack success. ' +
      'Minimum length ≥ 15 is the highest-impact single change — short passwords ' +
      'are highly vulnerable to offline brute force after credential theft. ' +
      'Enforcement is gradual: changes apply when a user next resets their password or when ' +
      'their password expires, not immediately at login. New accounts created after the policy ' +
      'change are subject to the new requirements from the moment the account is provisioned.',
    preChangeChecks: [
      'No immediate lockout risk — password policy changes are not enforced on existing sessions or passwords.',
      'Review the current password expiry window to estimate how long full enforcement will take to roll out across the user base.',
      'Confirm that any SAML or federated-identity users are excluded from the Okta password policy (they authenticate against their IdP, not Okta passwords).',
    ],
    blastRadius:
      'Password policy changes do not force immediate re-authentication or password resets for existing users — ' +
      'a user must comply with new requirements only when they next reset their password or when their current one expires. ' +
      'Full population enforcement may take weeks or months depending on your password expiry window. ' +
      'The minimum age setting (minAgeMinutes: 1440) prevents users from cycling through passwords to re-use an old one — ' +
      'this is a standard control, not an access restriction.',
    rolloutSteps: [
      'Step 1 — Raise minLength to 15 (highest security impact, zero lockout risk).',
      'Step 2 — Enable excludeUsername and common password dictionary.',
      'Step 3 — Set maxAttempts: 10 and showLockoutFailures: true.',
      'Step 4 — Set minAgeMinutes: 1440.',
      'Step 5 — Monitor System Log for lockout events and password change volume (see postChangeMonitoring queries).',
    ],
    postChangeMonitoring: {
      description:
        'After tightening password policies, watch for unusual lockout volume and track password change adoption. ' +
        'Full enforcement only completes once all existing passwords have expired or been voluntarily reset.',
      logQueries: [
        {
          description: 'Password changes post-policy-tightening (rollout adoption)',
          filter: 'eventType eq "user.account.update_password"',
          timeWindow: 'first 30 days post-change',
          note: 'Gradual increase is expected as passwords expire. A stall here means many users still have pre-change passwords.',
        },
        {
          description: 'Account lockout events post-change',
          filter: 'eventType eq "user.account.lock"',
          timeWindow: 'first 14 days post-change',
          note: 'A spike in lockouts after setting maxAttempts may indicate brute force activity against new policy, or users confused by new requirements.',
        },
      ],
    },
    rollback:
      'Password policy changes are immediately reversible in the Admin Console or via API. ' +
      'Existing authenticated sessions are not terminated by policy changes. ' +
      'Rollbacks also propagate gradually — users who already reset their passwords under the new ' +
      'policy are not forced to change again until their next expiry.',
  };
}

// ── Tool registration ─────────────────────────────────────────────────────────

function registerPasswordPolicyTools(server) {
  server.tool(
    'okta_list_password_policies',
    'List all Okta password policies with a TEA-aligned security audit. ' +
    'Flags policies for: minimum length < 15, missing character class requirements ' +
    '(lowercase/uppercase/numbers/symbols), brute force protection gaps ' +
    '(username exclusion and common password blocking), missing password history ' +
    '(reuse prevention), breached credential detection not fully enabled, ' +
    'minimum password age not set, and lockout notifications disabled. ' +
    'Returns a per-policy compliance summary with current settings, Terraform HCL, ' +
    'and remediation guidance.',
    {},
    async () => {
      if (process.env.OFFLINE_MODE === 'true') {
        const defaultPolicy = { id: '<POLICY_ID>', name: 'Default Policy', status: 'ACTIVE', settings: {} };
        return buildMcpOffline({
          remediation: {
            terraform:         buildPasswordPolicyTerraform(defaultPolicy),
            logQueries:        buildPasswordPolicyLogQueries(),
            adminConsoleSteps: buildPasswordPolicyAdminSteps('Default Policy'),
            riskAssessment:    buildPasswordPolicyRiskAssessment(),
          },
        });
      }
      try {
        const client = await createOktaClient();
        const { data: policies } = await client.get('/api/v1/policies', {
          params: { type: POLICY_TYPE },
        });

        const auditResults = policies.map(auditPolicy);
        const totalFindings = auditResults.reduce((n, r) => n + r.findingCount, 0);
        const highFindings = auditResults.reduce((n, r) => n + r.highCount, 0);

        const flaggedPolicies = policies.filter((p) =>
          auditResults.find((r) => r.policyId === p.id && r.findingCount > 0)
        );
        const terraform = flaggedPolicies.length > 0
          ? flaggedPolicies.map(buildPasswordPolicyTerraform).join('\n\n')
          : (policies.length > 0 ? buildPasswordPolicyTerraform(policies[0]) : null);

        return buildMcpOk({
          summary: {
            totalPolicies: policies.length,
            totalFindings,
            highFindings,
            policiesWithHighFindings: auditResults.filter((r) => r.highCount > 0).length,
          },
          policies: auditResults,
          remediation: {
            terraform,
            logQueries: buildPasswordPolicyLogQueries(),
            adminConsoleSteps: buildPasswordPolicyAdminSteps('<policy name>'),
            riskAssessment: buildPasswordPolicyRiskAssessment(),
          },
        });
      } catch (err) {
        return buildMcpError(err);
      }
    },
  );

  server.tool(
    'okta_update_password_policy',
    'Update an Okta password policy to address TEA security findings. ' +
    'Patches only the fields you provide — all others are left unchanged. ' +
    'Addresses: minimum length, character class requirements, excludeUsername, ' +
    'excludeCommonPasswords, password history, maxAttempts, showLockoutFailures, ' +
    'minAgeMinutes, and breached credential detection. ' +
    'Write operation — confirm with the admin before calling.',
    {
      policyId: z.string().describe('Okta password policy ID (from okta_list_password_policies).'),
      minLength: z.number().int().min(1).max(100).optional()
        .describe('Minimum password length. TEA recommendation: 15.'),
      minLowerCase: z.number().int().min(0).max(1).optional()
        .describe('Minimum lowercase characters required (0 = not required, 1 = required). TEA recommendation: 1.'),
      minUpperCase: z.number().int().min(0).max(1).optional()
        .describe('Minimum uppercase characters required (0 = not required, 1 = required). TEA recommendation: 1.'),
      minNumber: z.number().int().min(0).max(1).optional()
        .describe('Minimum numeric characters required (0 = not required, 1 = required). TEA recommendation: 1.'),
      minSymbol: z.number().int().min(0).max(1).optional()
        .describe('Minimum symbol characters required (0 = not required, 1 = required). TEA recommendation: 1.'),
      excludeUsername: z.boolean().optional()
        .describe('Prevent users from including their username in passwords.'),
      excludeCommonPasswords: z.boolean().optional()
        .describe('Block commonly used passwords via dictionary lookup.'),
      historyCount: z.number().int().min(0).max(24).optional()
        .describe('Number of previous passwords to prevent reuse. TEA recommendation: 4.'),
      maxAttempts: z.number().int().min(1).max(100).optional()
        .describe('Failed login attempts before lockout. TEA recommendation: 10.'),
      autoUnlockMinutes: z.number().int().min(0).optional()
        .describe('Minutes until locked account auto-unlocks. 0 = admin must unlock manually.'),
      showLockoutFailures: z.boolean().optional()
        .describe('Send lockout notification email to user.'),
      minAgeMinutes: z.number().int().min(0).optional()
        .describe('Minimum minutes before user can change password again. TEA recommendation: 1440.'),
      breachedProtectionEnabled: z.boolean().optional()
        .describe(
          'When true, sets breachedProtection.logoutEnabled = true and expireAfterDays = 0 ' +
          '(terminate sessions and force immediate reset on breached credential detection). ' +
          'When false, disables breach protection on this policy.',
        ),
    },
    async ({
      policyId,
      minLength,
      minLowerCase,
      minUpperCase,
      minNumber,
      minSymbol,
      excludeUsername,
      excludeCommonPasswords,
      historyCount,
      maxAttempts,
      autoUnlockMinutes,
      showLockoutFailures,
      minAgeMinutes,
      breachedProtectionEnabled,
    }) => {
      if (process.env.OFFLINE_MODE === 'true') {
        return buildMcpOffline({ skipped: true, message: 'Write operations are not available in offline mode.' });
      }
      if (process.env.PROD_MODE === 'true') {
        return buildMcpReadOnly();
      }
      try {
        const client = await createOktaClient();
        const { data: policy } = await client.get(`/api/v1/policies/${policyId}`);

        if (policy.type !== POLICY_TYPE) {
          return buildMcpError(new Error(
            `Policy "${policyId}" is type "${policy.type}", not PASSWORD. ` +
            'Use okta_list_password_policies to find valid password policy IDs.',
          ));
        }

        // Deep-clone and merge only provided fields
        const settings = JSON.parse(JSON.stringify(policy.settings || {}));
        const pw         = (settings.password    = settings.password    || {});
        const complexity = (pw.complexity        = pw.complexity        || {});
        const lockout    = (pw.lockout           = pw.lockout           || {});
        const age        = (pw.age               = pw.age               || {});
        const breached   = (pw.breachedProtection = pw.breachedProtection || {});

        if (minLength          !== undefined) { complexity.minLength        = minLength; }
        if (minLowerCase       !== undefined) { complexity.minLowerCase     = minLowerCase; }
        if (minUpperCase       !== undefined) { complexity.minUpperCase     = minUpperCase; }
        if (minNumber          !== undefined) { complexity.minNumber        = minNumber; }
        if (minSymbol          !== undefined) { complexity.minSymbol        = minSymbol; }
        if (excludeUsername    !== undefined) { complexity.excludeUsername  = excludeUsername; }
        if (excludeCommonPasswords !== undefined) {
          complexity.dictionary = complexity.dictionary || {};
          complexity.dictionary.common = { exclude: excludeCommonPasswords };
        }
        if (historyCount       !== undefined) { age.historyCount            = historyCount; }
        if (maxAttempts        !== undefined) { lockout.maxAttempts         = maxAttempts; }
        if (autoUnlockMinutes  !== undefined) { lockout.autoUnlockMinutes   = autoUnlockMinutes; }
        if (showLockoutFailures !== undefined) { lockout.showLockoutFailures = showLockoutFailures; }
        if (minAgeMinutes      !== undefined) { age.minAgeMinutes           = minAgeMinutes; }
        if (breachedProtectionEnabled !== undefined) {
          breached.logoutEnabled   = breachedProtectionEnabled;
          breached.expireAfterDays = breachedProtectionEnabled ? 0 : breached.expireAfterDays;
        }

        const { data: updated } = await client.put(`/api/v1/policies/${policyId}`, {
          ...policy,
          settings,
        });

        const auditBefore = auditPolicy(policy);
        const auditAfter  = auditPolicy(updated);

        const appliedChanges = {};
        if (minLength              !== undefined) { appliedChanges.minLength              = minLength; }
        if (minLowerCase           !== undefined) { appliedChanges.minLowerCase           = minLowerCase; }
        if (minUpperCase           !== undefined) { appliedChanges.minUpperCase           = minUpperCase; }
        if (minNumber              !== undefined) { appliedChanges.minNumber              = minNumber; }
        if (minSymbol              !== undefined) { appliedChanges.minSymbol              = minSymbol; }
        if (excludeUsername        !== undefined) { appliedChanges.excludeUsername        = excludeUsername; }
        if (excludeCommonPasswords !== undefined) { appliedChanges.excludeCommonPasswords = excludeCommonPasswords; }
        if (historyCount           !== undefined) { appliedChanges.historyCount           = historyCount; }
        if (maxAttempts            !== undefined) { appliedChanges.maxAttempts            = maxAttempts; }
        if (autoUnlockMinutes      !== undefined) { appliedChanges.autoUnlockMinutes      = autoUnlockMinutes; }
        if (showLockoutFailures    !== undefined) { appliedChanges.showLockoutFailures    = showLockoutFailures; }
        if (minAgeMinutes          !== undefined) { appliedChanges.minAgeMinutes          = minAgeMinutes; }
        if (breachedProtectionEnabled !== undefined) { appliedChanges.breachedProtectionEnabled = breachedProtectionEnabled; }

        return buildMcpOk({
          message: `Password policy "${updated.name}" updated successfully.`,
          policyId: updated.id,
          policyName: updated.name,
          appliedChanges,
          findingsBefore: auditBefore.findingCount,
          findingsAfter: auditAfter.findingCount,
          remainingFindings: auditAfter.findings,
          remediation: {
            terraform: buildPasswordPolicyTerraform(updated),
            logQueries: buildPasswordPolicyLogQueries(),
            adminConsoleSteps: buildPasswordPolicyAdminSteps(updated.name),
            riskAssessment: buildPasswordPolicyRiskAssessment(),
          },
        });
      } catch (err) {
        return buildMcpError(err);
      }
    },
  );
}

module.exports = {
  registerPasswordPolicyTools,
  auditPolicy,
  buildPasswordPolicyTerraform,
  buildPasswordPolicyLogQueries,
  buildPasswordPolicyRiskAssessment,
};
