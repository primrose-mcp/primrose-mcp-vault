/**
 * Consul Secrets Engine Tools
 *
 * MCP tools for Consul secrets engine operations including
 * access configuration, role management, and token generation.
 */

import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import type { VaultClient } from '../client.js';
import { formatError } from '../utils/formatters.js';

export function registerConsulTools(server: McpServer, client: VaultClient): void {
  // ===========================================================================
  // Configuration
  // ===========================================================================

  server.tool(
    'vault_consul_read_access_config',
    'Read the Consul access configuration.',
    {
      mount_path: z.string().default('consul').describe('Mount path of the Consul engine'),
    },
    async ({ mount_path }) => {
      try {
        const response = await (client as any).request(`/${mount_path}/config/access`);
        return {
          content: [{ type: 'text', text: JSON.stringify(response.data || response, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_consul_write_access_config',
    'Configure the Consul access credentials.',
    {
      mount_path: z.string().default('consul').describe('Mount path of the Consul engine'),
      address: z.string().describe('Consul server address'),
      scheme: z.string().optional().describe('URL scheme (http or https)'),
      token: z.string().describe('Consul ACL token with appropriate permissions'),
      ca_cert: z.string().optional().describe('CA certificate for TLS'),
      client_cert: z.string().optional().describe('Client certificate for TLS'),
      client_key: z.string().optional().describe('Client key for TLS'),
    },
    async ({ mount_path, address, scheme, token, ca_cert, client_cert, client_key }) => {
      try {
        await (client as any).request(`/${mount_path}/config/access`, {
          method: 'POST',
          body: JSON.stringify({ address, scheme, token, ca_cert, client_cert, client_key }),
        });
        return {
          content: [{ type: 'text', text: JSON.stringify({ success: true, message: 'Consul access configuration updated' }, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Role Management
  // ===========================================================================

  server.tool(
    'vault_consul_list_roles',
    'List all Consul roles.',
    {
      mount_path: z.string().default('consul').describe('Mount path of the Consul engine'),
    },
    async ({ mount_path }) => {
      try {
        const response = await (client as any).list(`/${mount_path}/roles`);
        const roles = response.data?.keys || [];
        return {
          content: [{ type: 'text', text: JSON.stringify({ roles, count: roles.length }, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_consul_read_role',
    'Read a Consul role.',
    {
      mount_path: z.string().default('consul').describe('Mount path of the Consul engine'),
      name: z.string().describe('Role name'),
    },
    async ({ mount_path, name }) => {
      try {
        const response = await (client as any).request(`/${mount_path}/roles/${name}`);
        return {
          content: [{ type: 'text', text: JSON.stringify(response.data || response, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_consul_create_role',
    'Create or update a Consul role.',
    {
      mount_path: z.string().default('consul').describe('Mount path of the Consul engine'),
      name: z.string().describe('Role name'),
      consul_policies: z.array(z.string()).optional().describe('Consul ACL policies to attach'),
      consul_roles: z.array(z.string()).optional().describe('Consul ACL roles to attach'),
      service_identities: z.array(z.string()).optional().describe('Service identities'),
      node_identities: z.array(z.string()).optional().describe('Node identities'),
      consul_namespace: z.string().optional().describe('Consul namespace'),
      partition: z.string().optional().describe('Consul admin partition'),
      ttl: z.string().optional().describe('Token TTL'),
      max_ttl: z.string().optional().describe('Maximum token TTL'),
      local: z.boolean().optional().describe('Generate local tokens'),
    },
    async ({ mount_path, name, consul_policies, consul_roles, service_identities, node_identities, consul_namespace, partition, ttl, max_ttl, local }) => {
      try {
        await (client as any).request(`/${mount_path}/roles/${name}`, {
          method: 'POST',
          body: JSON.stringify({
            consul_policies, consul_roles, service_identities,
            node_identities, consul_namespace, partition,
            ttl, max_ttl, local,
          }),
        });
        return {
          content: [{ type: 'text', text: JSON.stringify({ success: true, message: `Consul role '${name}' created/updated` }, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_consul_delete_role',
    'Delete a Consul role.',
    {
      mount_path: z.string().default('consul').describe('Mount path of the Consul engine'),
      name: z.string().describe('Role name'),
    },
    async ({ mount_path, name }) => {
      try {
        await (client as any).request(`/${mount_path}/roles/${name}`, { method: 'DELETE' });
        return {
          content: [{ type: 'text', text: JSON.stringify({ success: true, message: `Consul role '${name}' deleted` }, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Credential Generation
  // ===========================================================================

  server.tool(
    'vault_consul_generate_credentials',
    'Generate Consul credentials (ACL token) for a role.',
    {
      mount_path: z.string().default('consul').describe('Mount path of the Consul engine'),
      role_name: z.string().describe('Role name'),
    },
    async ({ mount_path, role_name }) => {
      try {
        const response = await (client as any).request(`/${mount_path}/creds/${role_name}`);
        return {
          content: [{ type: 'text', text: JSON.stringify(response.data, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );
}
