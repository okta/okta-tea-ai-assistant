#!/usr/bin/env node
'use strict';

const { McpServer } = require('@modelcontextprotocol/sdk/server/mcp.js');
const { StdioServerTransport } = require('@modelcontextprotocol/sdk/server/stdio.js');

const { registerAuthTools } = require('./tools/auth');
const { registerThreatInsightTools } = require('./tools/threatinsight');
const { registerNetworkZoneTools } = require('./tools/network-zones');
const { registerSecurityZoneTools } = require('./tools/security-zones');
const { registerPasswordPolicyTools } = require('./tools/password-policies');
const { registerSessionPolicyTools } = require('./tools/session-policies');
const { registerAuthenticatorTools } = require('./tools/authenticators');
const { registerSecurityGeneralTools } = require('./tools/security-general');
const { registerAdminConsolePolicyTools } = require('./tools/admin-console-policy');
const { registerSecurityNotificationTools } = require('./tools/security-notifications');
const { registerOAuthGrantTools } = require('./tools/oauth-grants');
const { registerAccountMgmtPolicyTools } = require('./tools/account-management-policy');
const { registerITPTools } = require('./tools/identity-threat-protection');
const { registerIdentityProofingTools } = require('./tools/identity-proofing');
const { registerDeviceAssuranceTools } = require('./tools/device-assurance');
const { registerDeviceIntegrationTools } = require('./tools/device-integration');
const { registerBehaviorDetectionTools } = require('./tools/behavior-detection');
const { registerLogStreamingTools } = require('./tools/log-streaming');
const { registerCaptchaTools } = require('./tools/captcha');
const { registerAuthorizationServerTools } = require('./tools/authorization-servers');
const { registerAttackProtectionTools } = require('./tools/attack-protection');
const { registerAuthenticationPolicyTools } = require('./tools/authentication-policies');
const { registerIdPConfigTools } = require('./tools/idp-config');
const { registerDefaultPolicyAuditTools } = require('./tools/default-policy-audit');
const { registerAdminRolesTools } = require('./tools/admin-roles');
const { registerApiTokenTools } = require('./tools/api-tokens');
const { registerSyslogTools } = require('./tools/syslog');

async function main() {
  const server = new McpServer({
    name: 'okta-resolver',
    version: '1.0.0',
  });

  registerAuthTools(server);
  registerThreatInsightTools(server);
  registerNetworkZoneTools(server);
  registerSecurityZoneTools(server);
  registerPasswordPolicyTools(server);
  registerSessionPolicyTools(server);
  registerAuthenticatorTools(server);
  registerSecurityGeneralTools(server);
  registerAdminConsolePolicyTools(server);
  registerSecurityNotificationTools(server);
  registerOAuthGrantTools(server);
  registerAccountMgmtPolicyTools(server);
  registerITPTools(server);
  registerIdentityProofingTools(server);
  registerDeviceAssuranceTools(server);
  registerDeviceIntegrationTools(server);
  registerBehaviorDetectionTools(server);
  registerLogStreamingTools(server);
  registerCaptchaTools(server);
  registerAuthorizationServerTools(server);
  registerAttackProtectionTools(server);
  registerAuthenticationPolicyTools(server);
  registerIdPConfigTools(server);
  registerDefaultPolicyAuditTools(server);
  registerAdminRolesTools(server);
  registerApiTokenTools(server);
  registerSyslogTools(server);

  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch((err) => {
  process.stderr.write(`okta-tea-ai-assistant: fatal error: ${err.message}\n`);
  process.exit(1);
});
