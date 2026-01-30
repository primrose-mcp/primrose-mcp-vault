/**
 * Token Tools
 *
 * MCP tools for Vault token management including creation, lookup,
 * renewal, revocation, and roles.
 */

import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import type { VaultClient } from '../client.js';
import { formatError } from '../utils/formatters.js';

export function registerTokenTools(server: McpServer, client: VaultClient): void {
  // ===========================================================================
  // Token Lookup
  // ===========================================================================

  server.tool(
    'vault_lookup_self',
    'Look up information about the current token.',
    {},
    async () => {
      try {
        const info = await client.lookupSelf();
        return {
          content: [{ type: 'text', text: JSON.stringify(info, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_lookup_token',
    'Look up information about a specific token.',
    {
      token: z.string().describe('Token to look up'),
    },
    async ({ token }) => {
      try {
        const info = await client.lookupToken(token);
        return {
          content: [{ type: 'text', text: JSON.stringify(info, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Token Creation
  // ===========================================================================

  server.tool(
    'vault_create_token',
    'Create a new token with specified policies and settings.',
    {
      policies: z.array(z.string()).optional().describe('List of policies to attach'),
      ttl: z.string().optional().describe('Token TTL (e.g., "1h", "24h", "768h")'),
      renewable: z.boolean().optional().describe('Whether token can be renewed'),
      display_name: z.string().optional().describe('Display name for the token'),
      num_uses: z.number().int().optional().describe('Number of times token can be used (0 = unlimited)'),
      no_parent: z.boolean().optional().describe('Create orphan token'),
      no_default_policy: z.boolean().optional().describe('Do not attach default policy'),
      metadata: z.record(z.string(), z.string()).optional().describe('Metadata to attach to the token'),
    },
    async ({ policies, ttl, renewable, display_name, num_uses, no_parent, no_default_policy, metadata }) => {
      try {
        const auth = await client.createToken({
          policies,
          ttl,
          renewable,
          display_name,
          num_uses,
          no_parent,
          no_default_policy,
          meta: metadata,
        });
        return {
          content: [{ type: 'text', text: JSON.stringify(auth, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Token Renewal
  // ===========================================================================

  server.tool(
    'vault_renew_self',
    'Renew the current token.',
    {
      increment: z.string().optional().describe('Requested increment for the renewal (e.g., "1h")'),
    },
    async ({ increment }) => {
      try {
        const auth = await client.renewSelf(increment);
        return {
          content: [{ type: 'text', text: JSON.stringify(auth, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_renew_token',
    'Renew a specific token.',
    {
      token: z.string().describe('Token to renew'),
      increment: z.string().optional().describe('Requested increment for the renewal'),
    },
    async ({ token, increment }) => {
      try {
        const auth = await client.renewToken(token, increment);
        return {
          content: [{ type: 'text', text: JSON.stringify(auth, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Token Revocation
  // ===========================================================================

  server.tool(
    'vault_revoke_self',
    'Revoke the current token and all its child tokens.',
    {},
    async () => {
      try {
        await client.revokeSelf();
        return {
          content: [{ type: 'text', text: JSON.stringify({ success: true, message: 'Token revoked' }, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_revoke_token',
    'Revoke a specific token and all its child tokens.',
    {
      token: z.string().describe('Token to revoke'),
    },
    async ({ token }) => {
      try {
        await client.revokeToken(token);
        return {
          content: [{ type: 'text', text: JSON.stringify({ success: true, message: 'Token revoked' }, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_revoke_accessor',
    'Revoke a token using its accessor.',
    {
      accessor: z.string().describe('Token accessor'),
    },
    async ({ accessor }) => {
      try {
        await client.revokeAccessor(accessor);
        return {
          content: [{ type: 'text', text: JSON.stringify({ success: true, message: 'Token revoked via accessor' }, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Token Accessors
  // ===========================================================================

  server.tool(
    'vault_list_accessors',
    'List all token accessors. Requires sudo capability.',
    {},
    async () => {
      try {
        const accessors = await client.listAccessors();
        return {
          content: [{ type: 'text', text: JSON.stringify({ accessors, count: accessors.length }, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Token Roles
  // ===========================================================================

  server.tool(
    'vault_list_token_roles',
    'List all token roles.',
    {},
    async () => {
      try {
        const roles = await client.listTokenRoles();
        return {
          content: [{ type: 'text', text: JSON.stringify({ roles, count: roles.length }, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_get_token_role',
    'Get configuration for a token role.',
    {
      name: z.string().describe('Role name'),
    },
    async ({ name }) => {
      try {
        const role = await client.getTokenRole(name);
        return {
          content: [{ type: 'text', text: JSON.stringify(role, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_create_token_role',
    'Create or update a token role.',
    {
      name: z.string().describe('Role name'),
      allowed_policies: z.array(z.string()).optional().describe('Allowed policies for tokens'),
      disallowed_policies: z.array(z.string()).optional().describe('Disallowed policies'),
      orphan: z.boolean().optional().describe('Tokens created are orphans'),
      renewable: z.boolean().optional().describe('Tokens are renewable'),
      token_period: z.number().int().optional().describe('Token period in seconds'),
      token_explicit_max_ttl: z.number().int().optional().describe('Explicit max TTL in seconds'),
    },
    async ({ name, allowed_policies, disallowed_policies, orphan, renewable, token_period, token_explicit_max_ttl }) => {
      try {
        await client.createTokenRole(name, {
          allowed_policies,
          disallowed_policies,
          orphan,
          renewable,
          token_period,
          token_explicit_max_ttl,
        });
        return {
          content: [{ type: 'text', text: JSON.stringify({ success: true, message: `Token role '${name}' created/updated` }, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_delete_token_role',
    'Delete a token role.',
    {
      name: z.string().describe('Role name to delete'),
    },
    async ({ name }) => {
      try {
        await client.deleteTokenRole(name);
        return {
          content: [{ type: 'text', text: JSON.stringify({ success: true, message: `Token role '${name}' deleted` }, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );
}
