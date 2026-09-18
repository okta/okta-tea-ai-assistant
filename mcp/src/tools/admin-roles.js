'use strict';

const { buildMcpOk, buildMcpError, buildMcpOffline } = require('./resolver-utils');
const { createOktaClient } = require('../auth/okta-client');

// Standard role type string for Super Administrator (confirmed via Okta role assignment API)
const SUPER_ADMIN_TYPE = 'SUPER_ADMIN';

// Flag when more than this many users hold a standing super admin role
const SUPER_ADMIN_THRESHOLD = 1;

// Service account detection heuristics.
// There is no first-class service account flag in Okta user profiles; these
// patterns cover the most common conventions seen across tenants.
const SVC_LOGIN_PREFIXES = [
  'svc.', 'svc-', 'sa.', 'sa-',
  'service.', 'service-',
  'bot.', 'bot-',
  'api.', 'api-',
  'automation.', 'automation-',
  'integration.', 'integration-',
  'system.', 'system-',
];
const SVC_NAME_KEYWORDS = [
  'service', 'bot', 'automation', 'integration',
  'system', 'api', 'robot', 'svc', 'serviceaccount',
];

// ── Helpers ───────────────────────────────────────────────────────────────────

function detectServiceAccountHeuristic(login, email, nameStr, userType) {
  if (['service', 'serviceaccount', 'sa'].includes(userType)) return 'userType attribute';
  if (SVC_LOGIN_PREFIXES.some((p) => login.startsWith(p))) return 'login prefix';
  if (SVC_LOGIN_PREFIXES.some((p) => email.startsWith(p))) return 'email prefix';
  if (SVC_NAME_KEYWORDS.some((k) => nameStr.includes(k))) return 'name keyword';
  return null;
}

function classifyUser(user) {
  const profile   = user.profile || user;
  const login     = (profile.login || user.login || '').toLowerCase();
  const email     = (profile.email || '').toLowerCase();
  const firstName = (profile.firstName || '').toLowerCase();
  const lastName  = (profile.lastName  || '').toLowerCase();
  const display   = (profile.displayName || `${firstName} ${lastName}`).trim();
  const userType  = (profile.userType || '').toLowerCase();
  const nameStr   = `${firstName} ${lastName} ${display}`;

  const heuristic = detectServiceAccountHeuristic(login, email, nameStr, userType);
  return {
    id:          user.id,
    login:       profile.login || user.login || '<unknown>',
    displayName: display || '<unknown>',
    status:      user.status,
    isServiceAccount: heuristic !== null,
    serviceAccountHeuristic: heuristic,
  };
}

// ── Fetcher ───────────────────────────────────────────────────────────────────
//
// Two-step approach:
//
//   1. GET /api/v1/users?limit=200 — enumerate all users (paginated via Link
//      response header, which is the standard Okta pagination mechanism).
//      There is no direct endpoint to filter users by standard org role type.
//      /api/v1/iam/assignees/users only covers custom IAM role assignees and
//      does NOT include users with standard org roles like SUPER_ADMIN.
//
//   2. GET /api/v1/users/{id}/roles — per-user role check. Returns the flat
//      array of role objects; filter for type === SUPER_ADMIN_TYPE.
//      Users from step 1 already include the full profile, so no second fetch
//      is needed once SUPER_ADMIN is confirmed.

async function fetchSuperAdminUsers(client) {
  // Step 1: collect all users via pagination (Link header, not _links body)
  const allUsers = [];
  let nextUrl = '/api/v1/users?limit=200';

  try {
    while (nextUrl) {
      const response = await client.get(nextUrl);
      const page = Array.isArray(response.data) ? response.data : [];
      allUsers.push(...page);
      // Okta standard API endpoints paginate via the Link response header:
      //   Link: <https://...>; rel="next"
      const linkHeader = response.headers?.link || '';
      const match = linkHeader.match(/<([^>]+)>;\s*rel="next"/);
      nextUrl = match ? match[1] : null;
    }
  } catch (err) {
    const status = err.response?.status;
    const detail = err.response?.data ? JSON.stringify(err.response.data) : err.message;

    if (status === 403) {
      return {
        available: false,
        reason:
          `API returned 403 — token likely lacks okta.users.read scope. ` +
          `Delete ~/.okta-tea-ai-assistant/tokens.json and re-authenticate with that scope added. ` +
          `Detail: ${detail}`,
      };
    }
    return { available: false, reason: err.message };
  }

  // Step 2: check each user's roles in parallel batches and keep SUPER_ADMINs.
  // The user object from the listing already has the full profile, so no second
  // fetch is needed after confirming the role.
  const BATCH_SIZE = 25;
  const users = [];

  for (let i = 0; i < allUsers.length; i += BATCH_SIZE) {
    const batch = allUsers.slice(i, i + BATCH_SIZE);
    const results = await Promise.all(
      batch.map(async (user) => {
        try {
          const { data: roles } = await client.get(`/api/v1/users/${user.id}/roles`);
          const hasSuperAdmin = Array.isArray(roles) && roles.some((r) => r.type === SUPER_ADMIN_TYPE);
          return hasSuperAdmin ? user : null;
        } catch {
          return null;
        }
      }),
    );
    users.push(...results.filter(Boolean));
  }

  return { available: true, users };
}

// ── Terraform ────────────────────────────────────────────────────────────────

function buildAdminRolesTerraform(superAdmins) {
  const humanAdmins = (superAdmins || []).filter((u) => !u.isServiceAccount);
  const svcAdmins   = (superAdmins || []).filter((u) => u.isServiceAccount);

  const userBlocks = humanAdmins
    .map((u) => `# User: ${u.displayName} (${u.login})  id: ${u.id}
# resource "okta_user_admin_roles" "${u.login.replace(/[^a-z0-9]/gi, '_')}_roles" {
#   user_id     = "${u.id}"
#   admin_roles = []   # empty removes all direct admin role assignments
# }`)
    .join('\n\n');

  return `# Terraform — Remove standing SUPER_ADMIN role assignments
#
# Goal: implement zero standing privileges for Super Administrators.
# After removing these assignments, admins request time-bound access on-demand
# via Security → Identity Governance → Govern Admin Roles (requires Okta IGA subscription).
#
# CRITICAL: Before applying, ensure Govern Admin Roles is configured with working
# conditions and at least one approved request path. Removing all super admin
# assignments without a break-glass account will lock your org.
# Keep exactly ONE break-glass account with a standing SUPER_ADMIN assignment.
#
# Provider setup:
#   https://developer.okta.com/docs/guides/terraform-enable-org-access/main/
# Resource reference:
#   https://registry.terraform.io/providers/okta/okta/latest/docs/resources/user_admin_roles

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
  scopes      = ["okta.users.manage"]
  private_key = "<PATH_OR_CONTENT_OF_PRIVATE_KEY>"
}

# ── Human admins to migrate to time-bound access ─────────────────────────────
# Uncomment and apply AFTER Govern Admin Roles is configured and tested.
${userBlocks || '# (no non-service-account super admins to migrate)'}

# ── Service accounts ─────────────────────────────────────────────────────────
# Service accounts cannot use the Govern Admin Roles request workflow.
# Migrate them to a least-privilege custom admin role instead.
${svcAdmins.map((u) => `# Service account: ${u.login}  id: ${u.id}  heuristic: ${u.serviceAccountHeuristic}`).join('\n') || '# (none detected)'}
`;
}

// ── Log queries ───────────────────────────────────────────────────────────────

function buildAdminRolesLogQueries() {
  return [
    {
      description: 'Super admin role grants — all SUPER_ADMIN assignments',
      filter: 'eventType eq "user.account.privilege.grant"',
      timeWindow: 'last 90 days',
      note: 'With zero standing privileges enforced, this event should only appear when Govern Admin Roles approves a time-bound request. Any out-of-band privilege.grant events warrant review.',
    },
    {
      description: 'Super admin role revocations — standing access removal',
      filter: 'eventType eq "user.account.privilege.revoke"',
      timeWindow: 'last 90 days',
      note: 'Tracks admin role removal events. Use alongside privilege.grant to audit the full time-bound access lifecycle.',
    },
    {
      description: 'Admin Console sessions — super admin footprint',
      filter: 'eventType eq "user.session.access_admin_app"',
      timeWindow: 'last 30 days',
      note: 'Shows which admins are actively using elevated access. Frequent access by service accounts or automated tooling warrants review of whether SUPER_ADMIN is actually needed.',
    },
    {
      description: 'Admin role privilege changes — grant and revoke events',
      filter: 'eventType sw "user.account.privilege."',
      timeWindow: 'last 30 days',
      note: 'Captures user.account.privilege.grant and user.account.privilege.revoke — all admin role assignments and removals.',
    },
  ];
}

// ── Admin console steps ───────────────────────────────────────────────────────

function buildAdminRolesAdminSteps() {
  return [
    'Sign in to the Okta Admin Console.',
    'Go to Directory → People → filter by role "Super Administrator" to see all current super admins.',

    '── Step 1: Designate a break-glass account ──',
    '  Identify one shared break-glass account (store credentials in a privileged vault).',
    '  This account retains a standing SUPER_ADMIN assignment as the emergency recovery path.',
    '  All other super admins will transition to on-demand time-bound access.',

    '── Step 2: Enable and configure Govern Admin Roles ──',
    '  (Requires Okta Identity Governance subscription.)',
    '  Go to Security → Identity Governance → Govern Admin Roles.',
    '  Create an "Admin role bundle": pair the SUPER_ADMIN role with the target resource set.',
    '  Create a Condition defining:',
    '    • Who can request the bundle (e.g. a specific "potential-super-admins" group)',
    '    • Maximum access duration (e.g. 4 hours or 8 hours)',
    '    • Approval sequence (who must approve — require at least two approvers for SUPER_ADMIN)',

    '── Step 3: Test the request workflow end-to-end ──',
    '  Have a non-break-glass admin submit a test request from the End-User Dashboard.',
    '  Confirm the approval flow works and access is granted for the configured duration.',
    '  Confirm the access expires automatically when the duration elapses.',

    '── Step 4: Communicate and set a migration deadline ──',
    '  Notify all current super admins of the transition timeline.',
    '  Confirm they know how to request time-bound access from the End-User Dashboard.',

    '── Step 5: Remove standing assignments ──',
    '  For each non-break-glass super admin:',
    '    Directory → People → [user] → Admin Roles tab → remove Super Administrator.',
    '  For service accounts with SUPER_ADMIN: evaluate whether a least-privilege',
    '  custom admin role is sufficient and migrate accordingly.',

    '── Step 6: Monitor ──',
    '  In Reports → System Log, watch for user.account.privilege.grant events.',
    '  Any grant occurring outside the Govern Admin Roles workflow warrants review.',
  ];
}

// ── Risk assessment ───────────────────────────────────────────────────────────

function buildAdminRolesRiskAssessment(counts) {
  const total   = counts?.totalSuperAdmins ?? 0;
  const svcCount = counts?.serviceAccountSuperAdmins ?? 0;

  return {
    teaSeverity: 'HIGH',
    changeRisk:  'MODERATE',
    summary:
      `${total} user${total !== 1 ? 's' : ''} hold a standing SUPER_ADMIN role` +
      (svcCount > 0
        ? `, including ${svcCount} apparent service account${svcCount !== 1 ? 's' : ''}`
        : '') +
      '. Each standing super admin is a permanently-elevated attack surface — a single ' +
      'compromised account gives full org control over all users, apps, and policies. ' +
      'Zero standing privileges via Okta "Govern Admin Roles" replaces permanent assignments ' +
      'with time-bound, approval-gated access that expires automatically. ' +
      'Okta Identity Governance subscription is required for this feature.',
    preChangeChecks: [
      'Designate exactly one break-glass super admin account before removing any standing assignments.',
      'Verify the Okta Identity Governance subscription is active (required for Govern Admin Roles).',
      'Configure and test the Govern Admin Roles request-and-approval workflow end-to-end before removing standing assignments.',
      'Separately identify service accounts with SUPER_ADMIN — they cannot use the End-User Dashboard and need a different remediation path.',
      'Service account classification in this tool is heuristic — manually verify each flagged account before treating it as a service account.',
      'This tool reports only direct user role assignments — SUPER_ADMIN assigned via a group is not reflected. Check Directory > Groups > [group] > Roles tab separately.',
    ],
    blastRadius:
      'Removing standing SUPER_ADMIN assignments before Govern Admin Roles is configured ' +
      'and tested will lock affected admins out permanently. ' +
      'Service accounts cannot use the End-User Dashboard to request time-bound access — ' +
      'they must be migrated to least-privilege custom admin roles rather than time-bound SUPER_ADMIN.',
    rolloutSteps: [
      'Step 1 — Designate one break-glass super admin account; document it in your runbook.',
      'Step 2 — Obtain an Okta Identity Governance subscription if not already active.',
      'Step 3 — Configure Govern Admin Roles: create the SUPER_ADMIN bundle, conditions, and approval sequence.',
      'Step 4 — Test the request-and-approval flow end-to-end before removing standing assignments.',
      'Step 5 — Notify affected admins and set a migration deadline.',
      'Step 6 — Remove standing SUPER_ADMIN assignments from all non-break-glass accounts.',
      'Step 7 — Migrate service accounts with SUPER_ADMIN to least-privilege custom roles.',
      'Step 8 — Monitor System Log for super admin grants outside the governed workflow (see postChangeMonitoring queries).',
    ],
    postChangeMonitoring: {
      description:
        'After removing standing SUPER_ADMIN assignments, watch for any new super admin grants that occur ' +
        'outside the Govern Admin Roles workflow — these indicate the process is being bypassed.',
      logQueries: [
        {
          description: 'Super admin role grants (any assignment)',
          filter: 'eventType eq "user.account.privilege.grant"',
          timeWindow: 'ongoing post-change',
          note: 'Any SUPER_ADMIN grant occurring outside normal business hours or outside the governed workflow warrants immediate investigation.',
        },
        {
          description: 'Time-bound admin access requests via Govern Admin Roles',
          filter: 'eventType sw "access.request."',
          timeWindow: 'ongoing post-change',
          note: 'Okta Identity Governance role requests fire under the access.request.* namespace (create, approve, reject, resolve, expire). Zero events here after migration could mean admins are bypassing the process.',
        },
      ],
    },
    rollback:
      'Admin role assignments can be restored immediately: Directory > People > [user] > Admin Roles. ' +
      'The Govern Admin Roles configuration does not affect existing standing assignments — ' +
      'it only governs the on-demand request flow. Standing assignments can always be re-added.',
  };
}

// ── Tool registration ─────────────────────────────────────────────────────────

function registerAdminRolesTools(server) {
  server.tool(
    'okta_audit_super_admins',
    'Audit users holding a standing SUPER_ADMIN (Super Administrator) role. ' +
    'Flags orgs with more than one super admin and identifies apparent service accounts ' +
    'with super admin access. Recommends zero standing privileges via the Okta ' +
    '"Govern Admin Roles" feature (requires Okta Identity Governance subscription). ' +
    'Reports direct user role assignments only — group-based SUPER_ADMIN assignments ' +
    'are not included in the count.',
    {},
    async () => {
      if (process.env.OFFLINE_MODE === 'true') {
        // Representative offline counts matching the TEA example scenario
        const mockCounts = { totalSuperAdmins: 11, serviceAccountSuperAdmins: 2, humanAdmins: 9 };
        return buildMcpOffline({
          remediation: {
            terraform:         buildAdminRolesTerraform([]),
            logQueries:        buildAdminRolesLogQueries(),
            adminConsoleSteps: buildAdminRolesAdminSteps(),
            riskAssessment:    buildAdminRolesRiskAssessment(mockCounts),
          },
        });
      }

      try {
        const client = await createOktaClient();
        const { available, users, reason } = await fetchSuperAdminUsers(client);

        if (!available) {
          return buildMcpError(new Error(
            `Could not retrieve super admin list: ${reason}`,
          ));
        }

        const classified     = users.map(classifyUser);
        const serviceAccts   = classified.filter((u) => u.isServiceAccount);
        const humanAdmins    = classified.filter((u) => !u.isServiceAccount);
        const counts = {
          totalSuperAdmins:        classified.length,
          serviceAccountSuperAdmins: serviceAccts.length,
          humanAdmins:             humanAdmins.length,
        };

        const findings = [];

        if (classified.length > SUPER_ADMIN_THRESHOLD) {
          findings.push({
            id:       'SUPER_ADMIN_COUNT_EXCEEDS_THRESHOLD',
            severity: 'HIGH',
            description:
              `${classified.length} users hold a standing SUPER_ADMIN role. ` +
              `Recommendation: reduce to 1 break-glass account and use Govern Admin Roles ` +
              `for all other super admin access.`,
            recommendation:
              'Implement zero standing privileges via Security → Identity Governance → ' +
              'Govern Admin Roles. Retain exactly one break-glass account.',
          });
        }

        if (serviceAccts.length > 0) {
          findings.push({
            id:       'SERVICE_ACCOUNT_HAS_SUPER_ADMIN',
            severity: 'HIGH',
            description:
              `${serviceAccts.length} apparent service account${serviceAccts.length !== 1 ? 's' : ''} ` +
              `hold SUPER_ADMIN. Service accounts cannot use the Govern Admin Roles ` +
              `time-bound request workflow — they need a different remediation path.`,
            recommendation:
              'Migrate service accounts to a least-privilege custom admin role scoped to ' +
              'only the resources and actions they actually need.',
          });
        }

        return buildMcpOk({
          summary: {
            ...counts,
            findingCount: findings.length,
            highFindings: findings.filter((f) => f.severity === 'HIGH').length,
          },
          findings,
          superAdmins: classified,
          remediation: {
            terraform:         buildAdminRolesTerraform(classified),
            logQueries:        buildAdminRolesLogQueries(),
            adminConsoleSteps: buildAdminRolesAdminSteps(),
            riskAssessment:    buildAdminRolesRiskAssessment(counts),
          },
        });
      } catch (err) {
        return buildMcpError(err);
      }
    },
  );
}

module.exports = {
  registerAdminRolesTools,
  buildAdminRolesTerraform,
  buildAdminRolesLogQueries,
  buildAdminRolesRiskAssessment,
};
