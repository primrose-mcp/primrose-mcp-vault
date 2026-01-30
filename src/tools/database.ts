/**
 * Database Secrets Engine Tools
 *
 * MCP tools for Database secrets engine operations including connection
 * management, dynamic roles, static roles, and credential generation.
 */

import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import type { VaultClient } from '../client.js';
import { formatError } from '../utils/formatters.js';

export function registerDatabaseTools(server: McpServer, client: VaultClient): void {
  // ===========================================================================
  // Connection Management
  // ===========================================================================

  server.tool(
    'vault_db_list_connections',
    'List all database connections configured in the Database secrets engine.',
    {
      mount_path: z.string().default('database').describe('Mount path of the Database engine'),
    },
    async ({ mount_path }) => {
      try {
        const connections = await client.dbListConnections(mount_path);
        return {
          content: [{ type: 'text', text: JSON.stringify({ connections, count: connections.length }, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_db_read_connection',
    'Read configuration of a database connection.',
    {
      mount_path: z.string().default('database').describe('Mount path of the Database engine'),
      name: z.string().describe('Connection name'),
    },
    async ({ mount_path, name }) => {
      try {
        const connection = await client.dbReadConnection(mount_path, name);
        return {
          content: [{ type: 'text', text: JSON.stringify(connection, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_db_create_connection',
    'Create or update a database connection.',
    {
      mount_path: z.string().default('database').describe('Mount path of the Database engine'),
      name: z.string().describe('Connection name'),
      plugin_name: z.string().describe('Database plugin (postgresql-database-plugin, mysql-database-plugin, etc.)'),
      connection_url: z.string().describe('Connection URL with {{username}} and {{password}} templates'),
      username: z.string().optional().describe('Root username for the database'),
      password: z.string().optional().describe('Root password for the database'),
      allowed_roles: z.array(z.string()).optional().describe('Roles allowed to use this connection'),
      verify_connection: z.boolean().optional().describe('Verify connection on creation'),
    },
    async ({ mount_path, name, plugin_name, connection_url, username, password, allowed_roles, verify_connection }) => {
      try {
        await client.dbCreateConnection(mount_path, name, {
          plugin_name,
          connection_url,
          username,
          password,
          allowed_roles,
          verify_connection,
        });
        return {
          content: [{ type: 'text', text: JSON.stringify({ success: true, message: `Database connection '${name}' created/updated` }, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_db_delete_connection',
    'Delete a database connection.',
    {
      mount_path: z.string().default('database').describe('Mount path of the Database engine'),
      name: z.string().describe('Connection name to delete'),
    },
    async ({ mount_path, name }) => {
      try {
        await client.dbDeleteConnection(mount_path, name);
        return {
          content: [{ type: 'text', text: JSON.stringify({ success: true, message: `Database connection '${name}' deleted` }, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_db_reset_connection',
    'Reset a database connection by closing and reconnecting.',
    {
      mount_path: z.string().default('database').describe('Mount path of the Database engine'),
      name: z.string().describe('Connection name to reset'),
    },
    async ({ mount_path, name }) => {
      try {
        await client.dbResetConnection(mount_path, name);
        return {
          content: [{ type: 'text', text: JSON.stringify({ success: true, message: `Database connection '${name}' reset` }, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_db_rotate_root',
    'Rotate the root credentials for a database connection.',
    {
      mount_path: z.string().default('database').describe('Mount path of the Database engine'),
      name: z.string().describe('Connection name'),
    },
    async ({ mount_path, name }) => {
      try {
        await client.dbRotateRoot(mount_path, name);
        return {
          content: [{ type: 'text', text: JSON.stringify({ success: true, message: `Root credentials for '${name}' rotated` }, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Dynamic Roles
  // ===========================================================================

  server.tool(
    'vault_db_list_roles',
    'List all dynamic roles in the Database secrets engine.',
    {
      mount_path: z.string().default('database').describe('Mount path of the Database engine'),
    },
    async ({ mount_path }) => {
      try {
        const roles = await client.dbListRoles(mount_path);
        return {
          content: [{ type: 'text', text: JSON.stringify({ roles, count: roles.length }, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_db_read_role',
    'Read configuration of a dynamic database role.',
    {
      mount_path: z.string().default('database').describe('Mount path of the Database engine'),
      name: z.string().describe('Role name'),
    },
    async ({ mount_path, name }) => {
      try {
        const role = await client.dbReadRole(mount_path, name);
        return {
          content: [{ type: 'text', text: JSON.stringify(role, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_db_create_role',
    'Create or update a dynamic database role.',
    {
      mount_path: z.string().default('database').describe('Mount path of the Database engine'),
      name: z.string().describe('Role name'),
      db_name: z.string().describe('Database connection to use'),
      creation_statements: z.array(z.string()).describe('SQL statements to create user'),
      revocation_statements: z.array(z.string()).optional().describe('SQL statements to revoke user'),
      default_ttl: z.string().optional().describe('Default credential TTL (e.g., "1h")'),
      max_ttl: z.string().optional().describe('Maximum credential TTL'),
    },
    async ({ mount_path, name, db_name, creation_statements, revocation_statements, default_ttl, max_ttl }) => {
      try {
        await client.dbCreateRole(mount_path, name, {
          db_name,
          creation_statements,
          revocation_statements,
          default_ttl,
          max_ttl,
        });
        return {
          content: [{ type: 'text', text: JSON.stringify({ success: true, message: `Database role '${name}' created/updated` }, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_db_delete_role',
    'Delete a dynamic database role.',
    {
      mount_path: z.string().default('database').describe('Mount path of the Database engine'),
      name: z.string().describe('Role name to delete'),
    },
    async ({ mount_path, name }) => {
      try {
        await client.dbDeleteRole(mount_path, name);
        return {
          content: [{ type: 'text', text: JSON.stringify({ success: true, message: `Database role '${name}' deleted` }, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_db_generate_credentials',
    'Generate dynamic database credentials for a role.',
    {
      mount_path: z.string().default('database').describe('Mount path of the Database engine'),
      role_name: z.string().describe('Role name to generate credentials for'),
    },
    async ({ mount_path, role_name }) => {
      try {
        const creds = await client.dbGenerateCredentials(mount_path, role_name);
        return {
          content: [{ type: 'text', text: JSON.stringify(creds, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Static Roles
  // ===========================================================================

  server.tool(
    'vault_db_list_static_roles',
    'List all static roles in the Database secrets engine.',
    {
      mount_path: z.string().default('database').describe('Mount path of the Database engine'),
    },
    async ({ mount_path }) => {
      try {
        const roles = await client.dbListStaticRoles(mount_path);
        return {
          content: [{ type: 'text', text: JSON.stringify({ roles, count: roles.length }, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_db_read_static_role',
    'Read configuration of a static database role.',
    {
      mount_path: z.string().default('database').describe('Mount path of the Database engine'),
      name: z.string().describe('Role name'),
    },
    async ({ mount_path, name }) => {
      try {
        const role = await client.dbReadStaticRole(mount_path, name);
        return {
          content: [{ type: 'text', text: JSON.stringify(role, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_db_create_static_role',
    'Create or update a static database role.',
    {
      mount_path: z.string().default('database').describe('Mount path of the Database engine'),
      name: z.string().describe('Role name'),
      db_name: z.string().describe('Database connection to use'),
      username: z.string().describe('Database username to manage'),
      rotation_period: z.string().optional().describe('Password rotation period (e.g., "24h")'),
      rotation_statements: z.array(z.string()).optional().describe('SQL statements for password rotation'),
    },
    async ({ mount_path, name, db_name, username, rotation_period, rotation_statements }) => {
      try {
        await client.dbCreateStaticRole(mount_path, name, {
          db_name,
          username,
          rotation_period,
          rotation_statements,
        });
        return {
          content: [{ type: 'text', text: JSON.stringify({ success: true, message: `Static role '${name}' created/updated` }, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_db_delete_static_role',
    'Delete a static database role.',
    {
      mount_path: z.string().default('database').describe('Mount path of the Database engine'),
      name: z.string().describe('Role name to delete'),
    },
    async ({ mount_path, name }) => {
      try {
        await client.dbDeleteStaticRole(mount_path, name);
        return {
          content: [{ type: 'text', text: JSON.stringify({ success: true, message: `Static role '${name}' deleted` }, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_db_get_static_credentials',
    'Get current credentials for a static role.',
    {
      mount_path: z.string().default('database').describe('Mount path of the Database engine'),
      role_name: z.string().describe('Role name to get credentials for'),
    },
    async ({ mount_path, role_name }) => {
      try {
        const creds = await client.dbGetStaticCredentials(mount_path, role_name);
        return {
          content: [{ type: 'text', text: JSON.stringify(creds, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_db_rotate_static_role',
    'Manually rotate the password for a static role.',
    {
      mount_path: z.string().default('database').describe('Mount path of the Database engine'),
      role_name: z.string().describe('Role name to rotate'),
    },
    async ({ mount_path, role_name }) => {
      try {
        await client.dbRotateStaticRole(mount_path, role_name);
        return {
          content: [{ type: 'text', text: JSON.stringify({ success: true, message: `Static role '${role_name}' password rotated` }, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );
}
