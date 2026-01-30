/**
 * RabbitMQ Secrets Engine Tools
 *
 * MCP tools for RabbitMQ secrets engine operations including
 * connection configuration, role management, and credential generation.
 */

import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import type { VaultClient } from '../client.js';
import { formatError } from '../utils/formatters.js';

export function registerRabbitmqTools(server: McpServer, client: VaultClient): void {
  // ===========================================================================
  // Configuration
  // ===========================================================================

  server.tool(
    'vault_rabbitmq_write_connection_config',
    'Configure the RabbitMQ connection.',
    {
      mount_path: z.string().default('rabbitmq').describe('Mount path of the RabbitMQ engine'),
      connection_uri: z.string().describe('RabbitMQ management API URI'),
      username: z.string().describe('RabbitMQ admin username'),
      password: z.string().describe('RabbitMQ admin password'),
      verify_connection: z.boolean().optional().describe('Verify connection on write'),
      password_policy: z.string().optional().describe('Password policy name'),
      username_template: z.string().optional().describe('Username template'),
    },
    async ({ mount_path, connection_uri, username, password, verify_connection, password_policy, username_template }) => {
      try {
        await (client as any).request(`/${mount_path}/config/connection`, {
          method: 'POST',
          body: JSON.stringify({ connection_uri, username, password, verify_connection, password_policy, username_template }),
        });
        return {
          content: [{ type: 'text', text: JSON.stringify({ success: true, message: 'RabbitMQ connection configured' }, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_rabbitmq_write_lease_config',
    'Configure the RabbitMQ lease settings.',
    {
      mount_path: z.string().default('rabbitmq').describe('Mount path of the RabbitMQ engine'),
      ttl: z.string().optional().describe('Default TTL'),
      max_ttl: z.string().optional().describe('Maximum TTL'),
    },
    async ({ mount_path, ttl, max_ttl }) => {
      try {
        await (client as any).request(`/${mount_path}/config/lease`, {
          method: 'POST',
          body: JSON.stringify({ ttl, max_ttl }),
        });
        return {
          content: [{ type: 'text', text: JSON.stringify({ success: true, message: 'RabbitMQ lease configuration updated' }, null, 2) }],
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
    'vault_rabbitmq_list_roles',
    'List all RabbitMQ roles.',
    {
      mount_path: z.string().default('rabbitmq').describe('Mount path of the RabbitMQ engine'),
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
    'vault_rabbitmq_read_role',
    'Read a RabbitMQ role.',
    {
      mount_path: z.string().default('rabbitmq').describe('Mount path of the RabbitMQ engine'),
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
    'vault_rabbitmq_create_role',
    'Create or update a RabbitMQ role.',
    {
      mount_path: z.string().default('rabbitmq').describe('Mount path of the RabbitMQ engine'),
      name: z.string().describe('Role name'),
      tags: z.string().optional().describe('Comma-separated RabbitMQ tags (e.g., "administrator,management")'),
      vhosts: z.string().optional().describe('JSON vhost permissions (e.g., {"/":{...}})'),
      vhost_topics: z.string().optional().describe('JSON vhost topic permissions'),
    },
    async ({ mount_path, name, tags, vhosts, vhost_topics }) => {
      try {
        await (client as any).request(`/${mount_path}/roles/${name}`, {
          method: 'POST',
          body: JSON.stringify({ tags, vhosts, vhost_topics }),
        });
        return {
          content: [{ type: 'text', text: JSON.stringify({ success: true, message: `RabbitMQ role '${name}' created/updated` }, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_rabbitmq_delete_role',
    'Delete a RabbitMQ role.',
    {
      mount_path: z.string().default('rabbitmq').describe('Mount path of the RabbitMQ engine'),
      name: z.string().describe('Role name'),
    },
    async ({ mount_path, name }) => {
      try {
        await (client as any).request(`/${mount_path}/roles/${name}`, { method: 'DELETE' });
        return {
          content: [{ type: 'text', text: JSON.stringify({ success: true, message: `RabbitMQ role '${name}' deleted` }, null, 2) }],
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
    'vault_rabbitmq_generate_credentials',
    'Generate RabbitMQ credentials for a role.',
    {
      mount_path: z.string().default('rabbitmq').describe('Mount path of the RabbitMQ engine'),
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
