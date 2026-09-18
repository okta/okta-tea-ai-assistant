'use strict';

const { buildMcpOk, buildMcpError, buildMcpOffline } = require('./resolver-utils');
const { createOktaClient } = require('../auth/okta-client');

// ── API paths ──────────────────────────────────────────────────────────────────

// Org-level settings (contains end-user notification preferences)
const ORG_PATH = '/api/v1/org';
// Brand email customisation (v2 API — OIE tenants)
const BRANDS_PATH = '/api/v1/brands';

// ── Fetchers ───────────────────────────────────────────────────────────────────

async function fetchOrgSettings(client) {
  try {
    const { data } = await client.get(ORG_PATH);
    return { available: true, data };
  } catch (err) {
    return { available: false, reason: err.message };
  }
}

async function fetchBrands(client) {
  try {
    const { data } = await client.get(BRANDS_PATH);
    // Okta may return a plain array or a wrapper object with a brands/value/_embedded key
    const brands = Array.isArray(data) ? data
      : Array.isArray(data?.brands)             ? data.brands
      : Array.isArray(data?._embedded?.brands)  ? data._embedded.brands
      : Array.isArray(data?.value)              ? data.value
      : [];
    return { available: true, brands };
  } catch (err) {
    return { available: false, reason: err.message, brands: [] };
  }
}

async function fetchEmailSettings(client, brandId) {
  try {
    const { data } = await client.get(`${BRANDS_PATH}/${brandId}/email-settings`);
    return { available: true, data };
  } catch (err) {
    const status = err.response?.status;
    if (status === 404 || status === 405) {
      return { available: false, reason: `Not supported on this tenant (HTTP ${status}).` };
    }
    return { available: false, reason: err.message };
  }
}

// ── Audit ──────────────────────────────────────────────────────────────────────

function auditNotificationSettings({ orgSettings, emailSettings }) {
  const findings = [];

  // Check whether end-user security notification emails are sent.
  // The org API exposes optOutCommunicationEmails which, when true, suppresses
  // ALL admin-facing Okta communication. The brand email-settings API (OIE) gives
  // per-email-template control. We flag any detectable suppression.
  if (orgSettings.available) {
    const optOut = orgSettings.data?.settings?.app?.optOutCommunicationEmails;
    if (optOut === true) {
      findings.push({
        id: 'ORG_OPT_OUT_EMAILS',
        severity: 'HIGH',
        description:
          'Org-level "Opt out of communication emails" is enabled. This suppresses ' +
          'Okta security notification emails to administrators. Re-enable to receive ' +
          'security alerts.',
        recommendation: 'In the Okta Admin Console go to Settings > Account and disable ' +
          '"Opt out of communication emails from Okta".',
      });
    }

    const notifyNewDeviceEnabled =
      orgSettings.data?.settings?.app?.notifyEndUserOnAccountDeactivation !== undefined
        ? orgSettings.data.settings.app.notifyEndUserOnAccountDeactivation
        : null;

    if (notifyNewDeviceEnabled === false) {
      findings.push({
        id: 'DEACTIVATION_NOTIFY_DISABLED',
        severity: 'LOW', // not a TEA-backed finding — lower severity than TEA validators
        description: 'End-user notification on account deactivation is disabled.',
        recommendation: 'Enable account deactivation notifications under org settings.',
      });
    }
  }

  // Brand-level email settings (OIE brands API).
  // Some tenants (Classic Engine or restricted orgs) return 404/405 on this endpoint.
  // In that case emit CANNOT_VERIFY findings so the caller knows to check manually
  // rather than silently passing the audit.
  if (emailSettings.available && emailSettings.data) {
    const data = emailSettings.data;
    // Use != true (not strict ===) to catch both false and null, which some tenants return
    // for disabled settings instead of an explicit boolean false.
    if (data.reportSuspiciousActivityEnabled === false || data.reportSuspiciousActivityEnabled === null) {
      findings.push({
        id: 'BRAND_SUSPICIOUS_ACTIVITY_EMAIL_DISABLED',
        severity: 'MODERATE',
        description:
          '"Report Suspicious Activity" link in notification emails is disabled at brand level.',
        recommendation: 'Enable via the Brands email-settings API or Admin Console > Customizations > Emails.',
      });
    }
    if (data.sendEmailForFactorEnrollmentEnabled === false || data.sendEmailForFactorEnrollmentEnabled === null) {
      findings.push({
        id: 'BRAND_FACTOR_ENROLL_EMAIL_DISABLED',
        severity: 'LOW',
        description: 'Authenticator enrolled notification email is disabled.',
        recommendation: 'Enable via Admin Console > Security > General > Security Notification Emails.',
      });
    }
    // TEA OrgEmailSettingCheck audits email.factorReset separately from email.factorEnrollment.
    // Factor reset (authenticator removed/reset by an admin) is more security-sensitive than
    // enrollment — users must know if their MFA is stripped as part of an account takeover.
    if (data.sendEmailForFactorResetEnabled === false || data.sendEmailForFactorResetEnabled === null) {
      findings.push({
        id: 'BRAND_FACTOR_RESET_EMAIL_DISABLED',
        severity: 'MODERATE',
        description: 'Authenticator reset notification email is disabled. Users will not be alerted when an authenticator is removed or reset — a key indicator of account takeover.',
        recommendation: 'Enable via Admin Console > Security > General > Security Notification Emails.',
      });
    }
    if (data.sendEmailForNewDeviceEnabled === false || data.sendEmailForNewDeviceEnabled === null) {
      findings.push({
        id: 'BRAND_NEW_DEVICE_EMAIL_DISABLED',
        severity: 'LOW',
        description: 'New sign-on notification email is disabled.',
        recommendation: 'Enable via Admin Console > Security > General > Security Notification Emails.',
      });
    }
    if (data.sendEmailForPasswordChangedEnabled === false || data.sendEmailForPasswordChangedEnabled === null) {
      findings.push({
        id: 'BRAND_PASSWORD_CHANGED_EMAIL_DISABLED',
        severity: 'LOW',
        description: 'Password changed notification email is disabled.',
        recommendation: 'Enable via Admin Console > Security > General > Security Notification Emails.',
      });
    }
  } else if (!emailSettings.available) {
    // The brands email-settings endpoint is not supported on this tenant.
    // Emit explicit CANNOT_VERIFY findings rather than silently skipping the check.
    const cannotVerify = [
      {
        id: 'CANNOT_VERIFY_SUSPICIOUS_ACTIVITY_EMAIL',
        severity: 'MODERATE',
        setting: '"Report Suspicious Activity" email',
      },
      {
        id: 'CANNOT_VERIFY_FACTOR_RESET_EMAIL',
        severity: 'MODERATE',
        setting: 'Authenticator reset notification email',
      },
      {
        id: 'CANNOT_VERIFY_NEW_DEVICE_EMAIL',
        severity: 'LOW',
        setting: 'New sign-on notification email',
      },
      {
        id: 'CANNOT_VERIFY_FACTOR_ENROLLMENT_EMAIL',
        severity: 'LOW',
        setting: 'Authenticator enrolled notification email',
      },
      {
        id: 'CANNOT_VERIFY_PASSWORD_CHANGED_EMAIL',
        severity: 'LOW',
        setting: 'Password changed notification email',
      },
    ];
    for (const item of cannotVerify) {
      findings.push({
        id: item.id,
        severity: item.severity,
        description:
          `${item.setting} status could not be verified via API (${emailSettings.reason}). ` +
          'Verify the current state manually.',
        recommendation:
          'Admin Console → Security → General → Security Notification Emails — confirm the toggle is enabled.',
      });
    }
  }

  if (findings.length === 0 && !orgSettings.available) {
    findings.push({
      id: 'API_UNAVAILABLE',
      severity: 'INFO',
      description:
        'Security notification email settings could not be read via API on this tenant. ' +
        'Verify manually using the Admin Console steps below.',
      recommendation: 'Follow manual verification steps in Security > General and Customizations > Emails.',
    });
  }

  return findings;
}

// ── Admin console steps ────────────────────────────────────────────────────────

function buildAdminConsoleSteps() {
  return [
    'Sign in to the Okta Admin Console.',
    'Go to Security > General.',
    'Scroll to the "Security Notification Emails" section.',
    'Review each notification type and ensure the appropriate ones are enabled:',
    '  • "Report suspicious activity via email" — adds a reporting link to sign-in notifications.',
    '  • New device sign-in notification — alerts users when a new device logs in.',
    '  • Password change notification — alerts users when their password changes.',
    '  • Authenticator enrollment notification — alerts users when a new authenticator is added.',
    '  • Authenticator reset notification — alerts users when an authenticator is removed or reset (TEA: email.factorReset, security_impact MODERATE).',
    'Click Save after making any changes.',
    '(Optional) Go to Customizations > Emails to review and customise the email templates.',
    'Complement technical controls with user awareness: train users to identify phishing and AiTM attacks. Direct users to report suspicious emails and unexpected sign-in notifications using the "Report Suspicious Activity" link enabled above.',
  ];
}

// ── Risk assessment ────────────────────────────────────────────────────────────

function buildRiskAssessment() {
  return {
    // TEA has two validators: SecurityNotificationsEnabled (LOW) and OrgEmailSettingCheck (MODERATE).
    // The higher of the two governs — MODERATE.
    teaSeverity: 'MODERATE',
    changeRisk:  'LOW',
    summary:
      'Enabling security notification emails has minimal adverse user-experience impact and ' +
      'significantly improves visibility into account-level events. ' +
      'Paired with phishing awareness training, the "Report Suspicious Activity" link creates ' +
      'a direct user-to-security-team reporting channel for credential phishing attempts.',
    preChangeChecks: [
      'No prerequisites — security notification settings are safe to enable immediately.',
      'Review Admin Console > Customizations > Emails to confirm notification email templates are active and not suppressed.',
    ],
    blastRadius:
      'All notifications are event-driven (new device, password change, factor enroll). ' +
      'Users on read-only email addresses may receive unexpected emails, but this is a security improvement. ' +
      'There are no polling or periodic notifications that could feel spammy.',
    rolloutSteps: [
      'Step 1 — Enable "Report suspicious activity via email" (creates a user-reporting channel).',
      'Step 2 — Enable new device sign-in and password change notifications.',
      'Step 3 — Enable authenticator enrollment notifications.',
      'Step 4 — Enable authenticator reset notifications (email.factorReset — highest security value, flags account takeover).',
      'Step 5 — Verify templates are active in Admin Console > Customizations > Emails.',
    ],
    postChangeMonitoring: {
      description:
        'After enabling notifications, confirm user-submitted suspicious activity reports are flowing ' +
        'to your security team and that notification events appear in System Log.',
      logQueries: [
        {
          description: 'User-submitted suspicious activity reports',
          filter: 'eventType eq "user.account.report_suspicious_activity_by_enduser"',
          timeWindow: 'first 30 days post-change',
          note: 'These events appear when a user clicks "Report Suspicious Activity". An increase confirms the feature is working.',
        },
        {
          description: 'Email template settings changes audit',
          filter: 'eventType eq "system.email.template.settings_changed"',
          timeWindow: 'last 7 days',
          note: 'Confirms email notification template settings were changed. Note: Okta does not emit a dedicated security-notification-settings event — this is the closest available event for notification config changes.',
        },
      ],
    },
    rollback:
      'Each setting can be disabled independently at any time from Security > General.',
  };
}

// ── Log queries ────────────────────────────────────────────────────────────────

function buildLogQueries() {
  return [
    {
      description: 'User-submitted suspicious activity reports',
      filter: 'eventType eq "user.account.report_suspicious_activity_by_enduser"',
      timeWindow: 'last 30 days',
      note: 'These events appear when a user clicks "Report Suspicious Activity" in a notification email.',
    },
    {
      description: 'Email template settings changes',
      filter: 'eventType eq "system.email.template.settings_changed"',
      timeWindow: 'last 90 days',
      note: 'Audit trail of email notification template configuration changes. Note: Okta does not emit a dedicated security-notification-settings event.',
    },
    {
      description: 'New device sign-in events',
      filter: 'eventType eq "user.authentication.auth_via_mfa" AND debugContext.debugData.requestUri ew "/login/token/redirect"',
      timeWindow: 'last 7 days',
      note: 'Verifies that notification emails would be triggered on new device sign-ins.',
    },
  ];
}

// ── Tool registration ─────────────────────────────────────────────────────────

function registerSecurityNotificationTools(server) {
  server.tool(
    'okta_get_security_notification_emails',
    'Audit Security Notification Email settings for this Okta tenant (Security > General). ' +
    'Checks: opt-out of communication emails, "Report suspicious activity via email", ' +
    'new device sign-in notification, password change notification, and factor enrollment ' +
    'notification. Reads from the org API and brands email-settings API with fallback to ' +
    'manual console steps when endpoints are unavailable.',
    {},
    async () => {
      if (process.env.OFFLINE_MODE === 'true') {
        return buildMcpOffline({
          remediation: {
            adminConsoleSteps: buildAdminConsoleSteps(),
            riskAssessment:    buildRiskAssessment(),
            logQueries:        buildLogQueries(),
          },
        });
      }
      try {
        const client = await createOktaClient();

        const [orgSettings, brandsResult] = await Promise.all([
          fetchOrgSettings(client),
          fetchBrands(client),
        ]);

        let emailSettings = { available: false, reason: 'No brands found.' };
        if (brandsResult.available && brandsResult.brands.length > 0) {
          const defaultBrand = brandsResult.brands.find((b) => b.isDefault) || brandsResult.brands[0];
          emailSettings = await fetchEmailSettings(client, defaultBrand.id);
        }

        const findings = auditNotificationSettings({ orgSettings, emailSettings });

        return buildMcpOk({
          summary: {
            findingCount: findings.length,
            highFindings: findings.filter((f) => f.severity === 'HIGH').length,
            apiCoverage: {
              orgSettingsAvailable: orgSettings.available,
              emailSettingsAvailable: emailSettings.available,
            },
          },
          findings,
          rawStatus: {
            orgOptOut: orgSettings.available
              ? orgSettings.data?.settings?.app?.optOutCommunicationEmails ?? 'not returned'
              : 'unavailable',
            emailSettings: emailSettings.available ? emailSettings.data : null,
            emailSettingsNote: !emailSettings.available ? emailSettings.reason : null,
          },
          remediation: {
            logQueries: buildLogQueries(),
            adminConsoleSteps: buildAdminConsoleSteps(),
            riskAssessment: buildRiskAssessment(),
          },
        });
      } catch (err) {
        return buildMcpError(err);
      }
    },
  );
}

module.exports = { registerSecurityNotificationTools };
