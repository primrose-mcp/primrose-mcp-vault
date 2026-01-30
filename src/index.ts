/**
 * Vault MCP Server - Main Entry Point
 *
 * This file sets up the MCP server using Cloudflare's Agents SDK.
 * It supports both stateless (McpServer) and stateful (McpAgent) modes.
 *
 * MULTI-TENANT ARCHITECTURE:
 * Tenant credentials (Vault tokens, addresses) are parsed from request headers,
 * allowing a single server deployment to serve multiple Vault instances.
 *
 * Required Headers:
 * - X-Vault-Token: Authentication token for Vault
 * - X-Vault-Address: Vault server address (e.g., https://vault.example.com)
 *
 * Optional Headers:
 * - X-Vault-Namespace: Vault namespace (Enterprise feature)
 */

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { McpAgent } from 'agents/mcp';
import { createVaultClient } from './client.js';
import {
  registerSystemTools,
  registerTokenTools,
  registerLeaseTools,
  registerWrappingTools,
  registerKvTools,
  registerTransitTools,
  registerPkiTools,
  registerDatabaseTools,
  registerSshTools,
  registerTotpTools,
  registerCubbyholeTools,
  registerAwsTools,
  registerIdentityTools,
  registerRabbitmqTools,
  registerConsulTools,
  registerAppRoleTools,
  registerUserpassTools,
  registerJwtTools,
  registerGithubTools,
  registerLdapTools,
  registerKubernetesTools,
  registerCertTools,
} from './tools/index.js';
import {
  type Env,
  type TenantCredentials,
  parseTenantCredentials,
  validateCredentials,
} from './types/env.js';

// =============================================================================
// MCP Server Configuration
// =============================================================================

const SERVER_NAME = 'primrose-mcp-vault';
const SERVER_VERSION = '1.0.0';

// =============================================================================
// MCP Agent (Stateful - uses Durable Objects)
// =============================================================================

/**
 * McpAgent provides stateful MCP sessions backed by Durable Objects.
 *
 * NOTE: For multi-tenant deployments, use the stateless mode (Option 2) instead.
 * The stateful McpAgent is better suited for single-tenant deployments where
 * credentials can be stored as wrangler secrets.
 *
 * @deprecated For multi-tenant support, use stateless mode with per-request credentials
 */
export class VaultMcpAgent extends McpAgent<Env> {
  server = new McpServer({
    name: SERVER_NAME,
    version: SERVER_VERSION,
  });

  async init() {
    throw new Error(
      'Stateful mode (McpAgent) is not supported for multi-tenant deployments. ' +
        'Use the stateless /mcp endpoint with X-Vault-Token and X-Vault-Address headers instead.'
    );
  }
}

// =============================================================================
// Stateless MCP Server (Recommended - no Durable Objects needed)
// =============================================================================

/**
 * Creates a stateless MCP server instance with tenant-specific credentials.
 *
 * MULTI-TENANT: Each request provides credentials via headers, allowing
 * a single server deployment to serve multiple Vault instances.
 *
 * @param credentials - Tenant credentials parsed from request headers
 */
function createStatelessServer(credentials: TenantCredentials): McpServer {
  const server = new McpServer({
    name: SERVER_NAME,
    version: SERVER_VERSION,
  });

  // Create client with tenant-specific credentials
  const client = createVaultClient(credentials);

  // Register all Vault tool modules
  // System and Core
  registerSystemTools(server, client);
  registerTokenTools(server, client);
  registerLeaseTools(server, client);
  registerWrappingTools(server, client);

  // Secrets Engines
  registerKvTools(server, client);
  registerTransitTools(server, client);
  registerPkiTools(server, client);
  registerDatabaseTools(server, client);
  registerSshTools(server, client);
  registerTotpTools(server, client);
  registerCubbyholeTools(server, client);
  registerAwsTools(server, client);
  registerIdentityTools(server, client);
  registerRabbitmqTools(server, client);
  registerConsulTools(server, client);

  // Auth Methods
  registerAppRoleTools(server, client);
  registerUserpassTools(server, client);
  registerJwtTools(server, client);
  registerGithubTools(server, client);
  registerLdapTools(server, client);
  registerKubernetesTools(server, client);
  registerCertTools(server, client);

  // Test connection tool
  server.tool('vault_test_connection', 'Test the connection to Vault by checking health status', {}, async () => {
    try {
      const health = await client.getHealth();
      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify(
              {
                success: true,
                message: 'Connection successful',
                health,
              },
              null,
              2
            ),
          },
        ],
      };
    } catch (error) {
      return {
        content: [
          {
            type: 'text',
            text: `Connection failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
          },
        ],
        isError: true,
      };
    }
  });

  return server;
}

// =============================================================================
// Worker Export
// =============================================================================

export default {
  /**
   * Main fetch handler for the Worker
   */
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);

    // Health check endpoint
    if (url.pathname === '/health') {
      return new Response(JSON.stringify({ status: 'ok', server: SERVER_NAME }), {
        headers: { 'Content-Type': 'application/json' },
      });
    }

    // ==========================================================================
    // Stateless MCP with Streamable HTTP (Recommended for multi-tenant)
    // ==========================================================================
    if (url.pathname === '/mcp' && request.method === 'POST') {
      // Parse tenant credentials from request headers
      const credentials = parseTenantCredentials(request);

      // Validate credentials are present
      try {
        validateCredentials(credentials);
      } catch (error) {
        return new Response(
          JSON.stringify({
            error: 'Unauthorized',
            message: error instanceof Error ? error.message : 'Invalid credentials',
            required_headers: ['X-Vault-Token', 'X-Vault-Address'],
          }),
          {
            status: 401,
            headers: { 'Content-Type': 'application/json' },
          }
        );
      }

      // Create server with tenant-specific credentials
      const server = createStatelessServer(credentials);

      // Import and use createMcpHandler for streamable HTTP
      const { createMcpHandler } = await import('agents/mcp');
      const handler = createMcpHandler(server);
      return handler(request, env, ctx);
    }

    // SSE endpoint for legacy clients
    if (url.pathname === '/sse') {
      return new Response('SSE endpoint requires Durable Objects. Enable in wrangler.jsonc.', {
        status: 501,
      });
    }

    // Default response
    return new Response(
      JSON.stringify({
        name: SERVER_NAME,
        version: SERVER_VERSION,
        description: 'Multi-tenant HashiCorp Vault MCP Server',
        endpoints: {
          mcp: '/mcp (POST) - Streamable HTTP MCP endpoint',
          health: '/health - Health check',
        },
        authentication: {
          description: 'Pass tenant credentials via request headers',
          required_headers: {
            'X-Vault-Token': 'Vault authentication token',
            'X-Vault-Address': 'Vault server address (e.g., https://vault.example.com)',
          },
          optional_headers: {
            'X-Vault-Namespace': 'Vault namespace (Enterprise feature)',
          },
        },
        tools: {
          system: 'Health, seal status, mounts, auth methods, policies, audit devices, capabilities',
          tokens: 'Token creation, lookup, renewal, revocation, accessors, roles',
          leases: 'Lease lookup, renewal, revocation',
          wrapping: 'Response wrapping (wrap, unwrap, rewrap, lookup), random, hash',
          kv: 'KV v1 and v2 secrets engine (read, write, delete, list, metadata)',
          transit: 'Encryption, decryption, signing, verification, key management, hashing',
          pki: 'Certificate issuance, revocation, CA management, roles, issuers',
          database: 'Dynamic credentials, connections, roles, static roles',
          ssh: 'SSH key signing, OTP, CA management, roles',
          totp: 'Time-based OTP key management, code generation, validation',
          cubbyhole: 'Token-isolated secret storage',
          aws: 'AWS IAM credentials, STS, static roles',
          identity: 'Entities, entity aliases, groups, group aliases',
          rabbitmq: 'RabbitMQ credentials, connection config, roles',
          consul: 'Consul ACL tokens, access config, roles',
          approle: 'AppRole auth (roles, role IDs, secret IDs, login)',
          userpass: 'Username/password auth (users, passwords, policies)',
          jwt: 'JWT/OIDC auth (config, roles, login)',
          github: 'GitHub auth (config, team/user mappings, login)',
          ldap: 'LDAP auth (config, groups, users, login)',
          kubernetes: 'Kubernetes auth (config, roles, login)',
          cert: 'TLS Certificate auth (config, certs, CRLs, login)',
        },
      }),
      {
        headers: { 'Content-Type': 'application/json' },
      }
    );
  },
};
