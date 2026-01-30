/**
 * LDAP Auth Method Tools
 *
 * MCP tools for LDAP authentication including configuration,
 * group/user mappings, and login operations.
 */

import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import type { VaultClient } from '../client.js';
import { formatError } from '../utils/formatters.js';

export function registerLdapTools(server: McpServer, client: VaultClient): void {
  // ===========================================================================
  // Configuration
  // ===========================================================================

  server.tool(
    'vault_ldap_read_config',
    'Read the LDAP auth method configuration.',
    {
      mount_path: z.string().default('ldap').describe('Mount path of the LDAP auth method'),
    },
    async ({ mount_path }) => {
      try {
        const response = await (client as any).request(`/auth/${mount_path}/config`);
        return {
          content: [{ type: 'text', text: JSON.stringify(response.data || response, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_ldap_write_config',
    'Configure the LDAP auth method.',
    {
      mount_path: z.string().default('ldap').describe('Mount path of the LDAP auth method'),
      url: z.string().describe('LDAP URL (ldap:// or ldaps://)'),
      userdn: z.string().optional().describe('User DN for binding'),
      userattr: z.string().optional().describe('User attribute for matching (default: cn)'),
      binddn: z.string().optional().describe('Distinguished name for binding'),
      bindpass: z.string().optional().describe('Password for binding'),
      groupdn: z.string().optional().describe('Group search base DN'),
      groupattr: z.string().optional().describe('Group attribute (default: cn)'),
      groupfilter: z.string().optional().describe('Group search filter'),
      upndomain: z.string().optional().describe('UPN domain for userPrincipalName'),
      starttls: z.boolean().optional().describe('Use STARTTLS'),
      insecure_tls: z.boolean().optional().describe('Skip TLS verification'),
      certificate: z.string().optional().describe('CA certificate for TLS'),
      ttl: z.string().optional().describe('Token TTL'),
      max_ttl: z.string().optional().describe('Maximum token TTL'),
      token_policies: z.array(z.string()).optional().describe('Default policies'),
    },
    async ({ mount_path, url, userdn, userattr, binddn, bindpass, groupdn, groupattr, groupfilter, upndomain, starttls, insecure_tls, certificate, ttl, max_ttl, token_policies }) => {
      try {
        await (client as any).request(`/auth/${mount_path}/config`, {
          method: 'POST',
          body: JSON.stringify({
            url, userdn, userattr, binddn, bindpass, groupdn, groupattr,
            groupfilter, upndomain, starttls, insecure_tls, certificate,
            ttl, max_ttl, token_policies,
          }),
        });
        return {
          content: [{ type: 'text', text: JSON.stringify({ success: true, message: 'LDAP configuration updated' }, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Group Management
  // ===========================================================================

  server.tool(
    'vault_ldap_list_groups',
    'List all LDAP group mappings.',
    {
      mount_path: z.string().default('ldap').describe('Mount path of the LDAP auth method'),
    },
    async ({ mount_path }) => {
      try {
        const response = await (client as any).list(`/auth/${mount_path}/groups`);
        const groups = response.data?.keys || [];
        return {
          content: [{ type: 'text', text: JSON.stringify({ groups, count: groups.length }, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_ldap_read_group',
    'Read an LDAP group mapping.',
    {
      mount_path: z.string().default('ldap').describe('Mount path of the LDAP auth method'),
      name: z.string().describe('Group name'),
    },
    async ({ mount_path, name }) => {
      try {
        const response = await (client as any).request(`/auth/${mount_path}/groups/${name}`);
        return {
          content: [{ type: 'text', text: JSON.stringify(response.data || response, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_ldap_write_group',
    'Create or update an LDAP group mapping.',
    {
      mount_path: z.string().default('ldap').describe('Mount path of the LDAP auth method'),
      name: z.string().describe('Group name'),
      policies: z.array(z.string()).optional().describe('Policies to attach'),
    },
    async ({ mount_path, name, policies }) => {
      try {
        await (client as any).request(`/auth/${mount_path}/groups/${name}`, {
          method: 'POST',
          body: JSON.stringify({ policies: policies?.join(',') }),
        });
        return {
          content: [{ type: 'text', text: JSON.stringify({ success: true, message: `Group '${name}' mapping updated` }, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_ldap_delete_group',
    'Delete an LDAP group mapping.',
    {
      mount_path: z.string().default('ldap').describe('Mount path of the LDAP auth method'),
      name: z.string().describe('Group name'),
    },
    async ({ mount_path, name }) => {
      try {
        await (client as any).request(`/auth/${mount_path}/groups/${name}`, { method: 'DELETE' });
        return {
          content: [{ type: 'text', text: JSON.stringify({ success: true, message: `Group '${name}' mapping deleted` }, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // User Management
  // ===========================================================================

  server.tool(
    'vault_ldap_list_users',
    'List all LDAP user mappings.',
    {
      mount_path: z.string().default('ldap').describe('Mount path of the LDAP auth method'),
    },
    async ({ mount_path }) => {
      try {
        const response = await (client as any).list(`/auth/${mount_path}/users`);
        const users = response.data?.keys || [];
        return {
          content: [{ type: 'text', text: JSON.stringify({ users, count: users.length }, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_ldap_read_user',
    'Read an LDAP user mapping.',
    {
      mount_path: z.string().default('ldap').describe('Mount path of the LDAP auth method'),
      username: z.string().describe('Username'),
    },
    async ({ mount_path, username }) => {
      try {
        const response = await (client as any).request(`/auth/${mount_path}/users/${username}`);
        return {
          content: [{ type: 'text', text: JSON.stringify(response.data || response, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_ldap_write_user',
    'Create or update an LDAP user mapping.',
    {
      mount_path: z.string().default('ldap').describe('Mount path of the LDAP auth method'),
      username: z.string().describe('Username'),
      policies: z.array(z.string()).optional().describe('Policies to attach'),
      groups: z.array(z.string()).optional().describe('Groups to assign'),
    },
    async ({ mount_path, username, policies, groups }) => {
      try {
        await (client as any).request(`/auth/${mount_path}/users/${username}`, {
          method: 'POST',
          body: JSON.stringify({ policies: policies?.join(','), groups: groups?.join(',') }),
        });
        return {
          content: [{ type: 'text', text: JSON.stringify({ success: true, message: `User '${username}' mapping updated` }, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_ldap_delete_user',
    'Delete an LDAP user mapping.',
    {
      mount_path: z.string().default('ldap').describe('Mount path of the LDAP auth method'),
      username: z.string().describe('Username'),
    },
    async ({ mount_path, username }) => {
      try {
        await (client as any).request(`/auth/${mount_path}/users/${username}`, { method: 'DELETE' });
        return {
          content: [{ type: 'text', text: JSON.stringify({ success: true, message: `User '${username}' mapping deleted` }, null, 2) }],
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
    'vault_ldap_login',
    'Login using LDAP credentials.',
    {
      mount_path: z.string().default('ldap').describe('Mount path of the LDAP auth method'),
      username: z.string().describe('LDAP username'),
      password: z.string().describe('LDAP password'),
    },
    async ({ mount_path, username, password }) => {
      try {
        const response = await (client as any).request(`/auth/${mount_path}/login/${username}`, {
          method: 'POST',
          body: JSON.stringify({ password }),
        }, true);
        return {
          content: [{ type: 'text', text: JSON.stringify(response.auth, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );
}
