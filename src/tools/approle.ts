/**
 * AppRole Auth Method Tools
 *
 * MCP tools for AppRole authentication including role management,
 * role IDs, secret IDs, and login operations.
 */

import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import type { VaultClient } from '../client.js';
import { formatError } from '../utils/formatters.js';

export function registerAppRoleTools(server: McpServer, client: VaultClient): void {
  // ===========================================================================
  // Role Management
  // ===========================================================================

  server.tool(
    'vault_approle_list_roles',
    'List all AppRole roles.',
    {
      mount_path: z.string().default('approle').describe('Mount path of the AppRole auth method'),
    },
    async ({ mount_path }) => {
      try {
        const roles = await client.approleListRoles(mount_path);
        return {
          content: [{ type: 'text', text: JSON.stringify({ roles, count: roles.length }, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_approle_read_role',
    'Read configuration of an AppRole role.',
    {
      mount_path: z.string().default('approle').describe('Mount path of the AppRole auth method'),
      role_name: z.string().describe('Role name'),
    },
    async ({ mount_path, role_name }) => {
      try {
        const role = await client.approleReadRole(mount_path, role_name);
        return {
          content: [{ type: 'text', text: JSON.stringify(role, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_approle_create_role',
    'Create or update an AppRole role.',
    {
      mount_path: z.string().default('approle').describe('Mount path of the AppRole auth method'),
      role_name: z.string().describe('Role name'),
      bind_secret_id: z.boolean().optional().describe('Require secret ID for login (default: true)'),
      secret_id_bound_cidrs: z.array(z.string()).optional().describe('CIDRs that can use secret IDs'),
      secret_id_num_uses: z.number().int().optional().describe('Number of times a secret ID can be used (0 = unlimited)'),
      secret_id_ttl: z.string().optional().describe('TTL for secret IDs (e.g., "24h")'),
      token_policies: z.array(z.string()).optional().describe('Policies to attach to tokens'),
      token_ttl: z.string().optional().describe('Default token TTL'),
      token_max_ttl: z.string().optional().describe('Maximum token TTL'),
      token_num_uses: z.number().int().optional().describe('Number of times a token can be used'),
      token_bound_cidrs: z.array(z.string()).optional().describe('CIDRs that can use tokens'),
    },
    async ({ mount_path, role_name, bind_secret_id, secret_id_bound_cidrs, secret_id_num_uses, secret_id_ttl, token_policies, token_ttl, token_max_ttl, token_num_uses, token_bound_cidrs }) => {
      try {
        await client.approleCreateRole(mount_path, role_name, {
          bind_secret_id,
          secret_id_bound_cidrs,
          secret_id_num_uses,
          secret_id_ttl,
          token_policies,
          token_ttl,
          token_max_ttl,
          token_num_uses,
          token_bound_cidrs,
        });
        return {
          content: [{ type: 'text', text: JSON.stringify({ success: true, message: `AppRole '${role_name}' created/updated` }, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_approle_delete_role',
    'Delete an AppRole role.',
    {
      mount_path: z.string().default('approle').describe('Mount path of the AppRole auth method'),
      role_name: z.string().describe('Role name to delete'),
    },
    async ({ mount_path, role_name }) => {
      try {
        await client.approleDeleteRole(mount_path, role_name);
        return {
          content: [{ type: 'text', text: JSON.stringify({ success: true, message: `AppRole '${role_name}' deleted` }, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Role ID Operations
  // ===========================================================================

  server.tool(
    'vault_approle_get_role_id',
    'Get the Role ID for an AppRole role.',
    {
      mount_path: z.string().default('approle').describe('Mount path of the AppRole auth method'),
      role_name: z.string().describe('Role name'),
    },
    async ({ mount_path, role_name }) => {
      try {
        const roleId = await client.approleGetRoleId(mount_path, role_name);
        return {
          content: [{ type: 'text', text: JSON.stringify({ role_id: roleId }, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_approle_set_role_id',
    'Set a custom Role ID for an AppRole role.',
    {
      mount_path: z.string().default('approle').describe('Mount path of the AppRole auth method'),
      role_name: z.string().describe('Role name'),
      role_id: z.string().describe('Custom Role ID to set'),
    },
    async ({ mount_path, role_name, role_id }) => {
      try {
        await client.approleSetRoleId(mount_path, role_name, role_id);
        return {
          content: [{ type: 'text', text: JSON.stringify({ success: true, message: `Role ID for '${role_name}' updated` }, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Secret ID Operations
  // ===========================================================================

  server.tool(
    'vault_approle_generate_secret_id',
    'Generate a new Secret ID for an AppRole role.',
    {
      mount_path: z.string().default('approle').describe('Mount path of the AppRole auth method'),
      role_name: z.string().describe('Role name'),
      metadata: z.string().optional().describe('JSON metadata to attach to the secret ID'),
      cidr_list: z.array(z.string()).optional().describe('CIDRs that can use this secret ID'),
      num_uses: z.number().int().optional().describe('Number of times this secret ID can be used'),
      ttl: z.string().optional().describe('TTL for this secret ID'),
    },
    async ({ mount_path, role_name, metadata, cidr_list, num_uses, ttl }) => {
      try {
        const secretId = await client.approleGenerateSecretId(mount_path, role_name, {
          metadata,
          cidr_list,
          num_uses,
          ttl,
        });
        return {
          content: [{ type: 'text', text: JSON.stringify(secretId, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_approle_list_secret_ids',
    'List all Secret ID accessors for an AppRole role.',
    {
      mount_path: z.string().default('approle').describe('Mount path of the AppRole auth method'),
      role_name: z.string().describe('Role name'),
    },
    async ({ mount_path, role_name }) => {
      try {
        const accessors = await client.approleListSecretIds(mount_path, role_name);
        return {
          content: [{ type: 'text', text: JSON.stringify({ accessors, count: accessors.length }, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_approle_lookup_secret_id',
    'Look up a Secret ID by its value.',
    {
      mount_path: z.string().default('approle').describe('Mount path of the AppRole auth method'),
      role_name: z.string().describe('Role name'),
      secret_id: z.string().describe('Secret ID to look up'),
    },
    async ({ mount_path, role_name, secret_id }) => {
      try {
        const info = await client.approleLookupSecretId(mount_path, role_name, secret_id);
        return {
          content: [{ type: 'text', text: JSON.stringify(info, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_approle_destroy_secret_id',
    'Destroy a Secret ID.',
    {
      mount_path: z.string().default('approle').describe('Mount path of the AppRole auth method'),
      role_name: z.string().describe('Role name'),
      secret_id: z.string().describe('Secret ID to destroy'),
    },
    async ({ mount_path, role_name, secret_id }) => {
      try {
        await client.approleDestroySecretId(mount_path, role_name, secret_id);
        return {
          content: [{ type: 'text', text: JSON.stringify({ success: true, message: 'Secret ID destroyed' }, null, 2) }],
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
    'vault_approle_login',
    'Login using AppRole credentials to obtain a token.',
    {
      mount_path: z.string().default('approle').describe('Mount path of the AppRole auth method'),
      role_id: z.string().describe('Role ID'),
      secret_id: z.string().describe('Secret ID'),
    },
    async ({ mount_path, role_id, secret_id }) => {
      try {
        const auth = await client.approleLogin(mount_path, role_id, secret_id);
        return {
          content: [{ type: 'text', text: JSON.stringify(auth, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );
}
