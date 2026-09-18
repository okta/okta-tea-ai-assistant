'use strict';

const { buildMcpOk, buildMcpError, buildMcpOffline } = require('./resolver-utils');
const { createOktaClient } = require('../auth/okta-client');

// ── Fetchers ───────────────────────────────────────────────────────────────────

async function fetchLogStreams(client) {
  try {
    const { data } = await client.get('/api/v1/logStreams');
    return { available: true, streams: Array.isArray(data) ? data : [] };
  } catch (err) {
    const status = err.response?.status;
    if (status === 404 || status === 403) {
      return {
        available: false,
        reason: `API returned ${status} — Log Streaming may not be provisioned or requires okta.logStreams.read scope.`,
        streams: [],
      };
    }
    return { available: false, reason: err.message, streams: [] };
  }
}

// ── Audit ──────────────────────────────────────────────────────────────────────

function auditLogStreams({ streams }) {
  const findings = [];
  const activeStreams = streams.filter((s) => s.status === 'ACTIVE');

  if (streams.length === 0) {
    findings.push({
      id: 'LOG_STREAMING_NOT_CONFIGURED',
      severity: 'LOW',
      description:
        'No log streams are configured. Okta System Log events are not being forwarded ' +
        'to a SIEM or external security monitoring platform. Without log streaming, ' +
        'security events are only visible in the Okta Admin Console and are not ' +
        'available for automated alerting or long-term retention.',
      recommendation:
        'Configure a log stream under Reports > Log Streaming. ' +
        'Supported destinations include AWS EventBridge, Splunk, and other SIEM platforms.',
    });
  } else if (activeStreams.length === 0) {
    findings.push({
      id: 'LOG_STREAMING_ALL_INACTIVE',
      severity: 'LOW',
      description:
        `${streams.length} log stream(s) are configured but none have status ACTIVE. ` +
        'Inactive streams are not forwarding events.',
      recommendation:
        'Activate at least one log stream under Reports > Log Streaming.',
    });
  }

  return {
    findingCount: findings.length,
    findings,
    summary: {
      totalStreams: streams.length,
      activeStreams: activeStreams.length,
      streams: streams.map((s) => ({
        id: s.id,
        name: s.name,
        type: s.type,
        status: s.status,
        created: s.created,
        lastUpdated: s.lastUpdated,
      })),
    },
  };
}

// ── Terraform ──────────────────────────────────────────────────────────────────

function buildLogStreamTerraform() {
  return `# Terraform — Okta Log Streaming
#
# Provider setup:
#   https://developer.okta.com/docs/guides/terraform-enable-org-access/main/
# Resource reference:
#   https://registry.terraform.io/providers/okta/okta/latest/docs/resources/log_stream

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
  scopes      = ["okta.logStreams.manage"]
  private_key = "<PATH_OR_CONTENT_OF_PRIVATE_KEY>"
}

# Example: AWS EventBridge log stream
resource "okta_log_stream" "siem_eventbridge" {
  name   = "SIEM Log Stream — AWS EventBridge"
  type   = "aws_eventbridge"
  status = "ACTIVE"

  settings {
    account_id   = "<YOUR_AWS_ACCOUNT_ID>"
    event_source = "okta.<YOUR_OKTA_ORG>"
    region       = "<AWS_REGION>"  # e.g. us-east-1
  }
}

# Example: Splunk log stream (uncomment and adapt)
# resource "okta_log_stream" "siem_splunk" {
#   name   = "SIEM Log Stream — Splunk"
#   type   = "splunk_cloud_logstreaming"
#   status = "ACTIVE"
#
#   settings {
#     host          = "<YOUR_SPLUNK_HOST>"
#     token         = "<YOUR_SPLUNK_HEC_TOKEN>"
#     edition       = "aws"  # or "gcp"
#   }
# }
`;
}

// ── Log queries ────────────────────────────────────────────────────────────────

function buildLogStreamLogQueries() {
  return [
    {
      description: 'Log stream configuration changes',
      filter: 'eventType sw "system.log_stream."',
      timeWindow: 'last 90 days',
      note: 'Audit trail of log stream create, update, activate, deactivate, and delete events.',
    },
    {
      description: 'Log stream activation and lifecycle events',
      filter: 'eventType sw "system.log_stream.lifecycle."',
      timeWindow: 'last 7 days',
      note: 'Covers system.log_stream.lifecycle.create, .activate, .deactivate, .update, .delete. Note: Okta does not emit per-message delivery events — verify log stream health by confirming events arrive in your SIEM directly.',
    },
  ];
}

// ── Admin console steps ────────────────────────────────────────────────────────

function buildLogStreamAdminSteps() {
  return [
    'Sign in to the Okta Admin Console.',
    'Go to Reports > Log Streaming.',
    'Click "Add log stream" and select your SIEM destination:',
    '  • AWS EventBridge — requires AWS account ID, region, and event source name',
    '  • Splunk Cloud — requires HEC token and Splunk host',
    '  • Other integrations may be available depending on your Okta edition',
    'Complete the configuration wizard and save.',
    'Verify the stream status shows "Active" in the Log Streaming list.',
    'Test delivery by triggering a login event and confirming it appears in your SIEM.',
  ];
}

// ── Risk assessment ────────────────────────────────────────────────────────────

function buildLogStreamRiskAssessment() {
  return {
    teaSeverity: 'LOW',
    changeRisk:  'LOW',
    summary:
      'Without log streaming, security events exist only in the Okta Admin Console with ' +
      'limited retention. Streaming to an external SIEM provides tamper-resistant audit trails, ' +
      'enables automated alerting, and supports compliance requirements. ' +
      'This is a visibility gap rather than an active exploit path — enabling it carries no blast radius.',
    preChangeChecks: [
      'Confirm your SIEM destination is ready to receive events (AWS EventBridge bus, Splunk HEC endpoint, etc.).',
      'Gather the credentials/tokens required for the log stream configuration before starting.',
      'Verify you have okta.logStreams.manage scope on your OAuth service app.',
    ],
    blastRadius:
      'Log streaming is additive and read-only — it copies events to the destination without modifying ' +
      'Okta authentication behaviour. No authentication flows are affected by enabling it. ' +
      'There may be a small increase in outbound network traffic from your Okta tenant.',
    rolloutSteps: [
      'Step 1 — Identify your SIEM destination (AWS EventBridge, Splunk, etc.).',
      'Step 2 — Create the log stream and verify ACTIVE status.',
      'Step 3 — Confirm events are arriving in your SIEM.',
      'Step 4 — Create SIEM alerts for high-risk Okta event types (admin actions, MFA changes, user deactivations).',
    ],
    postChangeMonitoring: {
      description:
        'After activating a log stream, verify events are flowing within 15 minutes by triggering a test ' +
        'login and checking the SIEM for the corresponding user.session.start event.',
      logQueries: [
        {
          description: 'Log stream lifecycle events post-activation',
          filter: 'eventType sw "system.log_stream.lifecycle."',
          timeWindow: 'first 24 hours post-change',
          note: 'Confirms the log stream was activated. Note: Okta does not emit per-message delivery failure events — verify delivery by checking whether events arrive in your SIEM directly.',
        },
        {
          description: 'Log stream activation audit event',
          filter: 'eventType sw "system.log_stream." AND outcome.result eq "SUCCESS"',
          timeWindow: 'last 1 hour',
          note: 'Confirms the log stream was activated successfully.',
        },
      ],
    },
    rollback:
      'Log streams can be deactivated or deleted at any time from Reports > Log Streaming.',
  };
}

// ── Tool registration ─────────────────────────────────────────────────────────

function registerLogStreamingTools(server) {
  server.tool(
    'okta_get_log_streaming_config',
    'Audit Okta Log Streaming configuration — checks whether at least one active log stream ' +
    'is forwarding Okta System Log events to a SIEM or external security platform. ' +
    'Log streaming is required for tamper-resistant audit trails, automated alerting, ' +
    'and long-term event retention. Returns stream status and setup guidance.',
    {},
    async () => {
      if (process.env.OFFLINE_MODE === 'true') {
        return buildMcpOffline({
          remediation: {
            terraform:         buildLogStreamTerraform(),
            logQueries:        buildLogStreamLogQueries(),
            adminConsoleSteps: buildLogStreamAdminSteps(),
            riskAssessment:    buildLogStreamRiskAssessment(),
          },
        });
      }
      try {
        const client = await createOktaClient();
        const result = await fetchLogStreams(client);

        if (!result.available) {
          return buildMcpOk({
            available: false,
            reason: result.reason,
            summary: { totalStreams: 0, activeStreams: 0, streams: [] },
            findings: [{
              id: 'LOG_STREAM_API_UNAVAILABLE',
              severity: 'INFO',
              description: `Log Streaming API unavailable: ${result.reason}`,
              recommendation: 'Verify manually under Reports > Log Streaming in the Admin Console.',
            }],
          });
        }

        const audit = auditLogStreams(result);

        return buildMcpOk({
          ...audit,
          remediation: {
            terraform: buildLogStreamTerraform(),
            logQueries: buildLogStreamLogQueries(),
            adminConsoleSteps: buildLogStreamAdminSteps(),
            riskAssessment: buildLogStreamRiskAssessment(),
          },
        });
      } catch (err) {
        return buildMcpError(err);
      }
    },
  );
}

module.exports = { registerLogStreamingTools };
