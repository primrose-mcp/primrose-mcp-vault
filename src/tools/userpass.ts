/**
 * Userpass Auth Method Tools
 *
 * MCP tools for Userpass authentication including user management,
 * password updates, and login operations.
 */

import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import type { VaultClient } from '../client.js';
import { formatError } from '../utils/formatters.js';

export function registerUserpassTools(server: McpServer, client: VaultClient): void {
  // ===========================================================================
  // User Management
  // ===========================================================================

  server.tool(
    'vault_userpass_list_users',
    'List all userpass users.',
    {
      mount_path: z.string().default('userpass').describe('Mount path of the Userpass auth method'),
    },
    async ({ mount_path }) => {
      try {
        const users = await client.userpassListUsers(mount_path);
        return {
          content: [{ type: 'text', text: JSON.stringify({ users, count: users.length }, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_userpass_read_user',
    'Read a userpass user configuration.',
    {
      mount_path: z.string().default('userpass').describe('Mount path of the Userpass auth method'),
      username: z.string().describe('Username'),
    },
    async ({ mount_path, username }) => {
      try {
        const user = await client.userpassReadUser(mount_path, username);
        return {
          content: [{ type: 'text', text: JSON.stringify(user, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_userpass_create_user',
    'Create or update a userpass user.',
    {
      mount_path: z.string().default('userpass').describe('Mount path of the Userpass auth method'),
      username: z.string().describe('Username'),
      password: z.string().describe('Password'),
      token_policies: z.array(z.string()).optional().describe('Policies to attach to token'),
      token_ttl: z.string().optional().describe('Token TTL'),
      token_max_ttl: z.string().optional().describe('Maximum token TTL'),
      token_bound_cidrs: z.array(z.string()).optional().describe('CIDRs that can use the token'),
      token_no_default_policy: z.boolean().optional().describe('Do not attach default policy'),
      token_num_uses: z.number().int().optional().describe('Number of times token can be used'),
      token_period: z.string().optional().describe('Token period for periodic tokens'),
      token_type: z.string().optional().describe('Token type (service, batch, default)'),
    },
    async ({ mount_path, username, password, token_policies, token_ttl, token_max_ttl, token_bound_cidrs, token_no_default_policy, token_num_uses, token_period, token_type }) => {
      try {
        await client.userpassCreateUser(mount_path, username, {
          password,
          token_policies,
          token_ttl,
          token_max_ttl,
          token_bound_cidrs,
          token_no_default_policy,
          token_num_uses,
          token_period,
          token_type,
        });
        return {
          content: [{ type: 'text', text: JSON.stringify({ success: true, message: `User '${username}' created/updated` }, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_userpass_delete_user',
    'Delete a userpass user.',
    {
      mount_path: z.string().default('userpass').describe('Mount path of the Userpass auth method'),
      username: z.string().describe('Username to delete'),
    },
    async ({ mount_path, username }) => {
      try {
        await client.userpassDeleteUser(mount_path, username);
        return {
          content: [{ type: 'text', text: JSON.stringify({ success: true, message: `User '${username}' deleted` }, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Credential Management
  // ===========================================================================

  server.tool(
    'vault_userpass_update_password',
    'Update a user password.',
    {
      mount_path: z.string().default('userpass').describe('Mount path of the Userpass auth method'),
      username: z.string().describe('Username'),
      password: z.string().describe('New password'),
    },
    async ({ mount_path, username, password }) => {
      try {
        await client.userpassUpdatePassword(mount_path, username, password);
        return {
          content: [{ type: 'text', text: JSON.stringify({ success: true, message: `Password updated for '${username}'` }, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_userpass_update_policies',
    'Update policies for a user.',
    {
      mount_path: z.string().default('userpass').describe('Mount path of the Userpass auth method'),
      username: z.string().describe('Username'),
      policies: z.array(z.string()).describe('New list of policies'),
    },
    async ({ mount_path, username, policies }) => {
      try {
        await client.userpassUpdatePolicies(mount_path, username, policies);
        return {
          content: [{ type: 'text', text: JSON.stringify({ success: true, message: `Policies updated for '${username}'` }, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Login
  // ===========================================================================

  server.tool(
    'vault_userpass_login',
    'Login using userpass credentials to obtain a token.',
    {
      mount_path: z.string().default('userpass').describe('Mount path of the Userpass auth method'),
      username: z.string().describe('Username'),
      password: z.string().describe('Password'),
    },
    async ({ mount_path, username, password }) => {
      try {
        const auth = await client.userpassLogin(mount_path, username, password);
        return {
          content: [{ type: 'text', text: JSON.stringify(auth, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );
}
