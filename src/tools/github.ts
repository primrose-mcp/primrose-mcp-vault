/**
 * GitHub Auth Method Tools
 *
 * MCP tools for GitHub authentication including configuration,
 * team/user mappings, and login operations.
 */

import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import type { VaultClient } from '../client.js';
import { formatError } from '../utils/formatters.js';

export function registerGithubTools(server: McpServer, client: VaultClient): void {
  server.tool(
    'vault_github_read_config',
    'Read the GitHub auth method configuration.',
    {
      mount_path: z.string().default('github').describe('Mount path of the GitHub auth method'),
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
    'vault_github_write_config',
    'Configure the GitHub auth method.',
    {
      mount_path: z.string().default('github').describe('Mount path of the GitHub auth method'),
      organization: z.string().describe('GitHub organization name'),
      base_url: z.string().optional().describe('GitHub API base URL (for Enterprise)'),
      ttl: z.string().optional().describe('Token TTL'),
      max_ttl: z.string().optional().describe('Maximum token TTL'),
      token_policies: z.array(z.string()).optional().describe('Policies to attach to tokens'),
    },
    async ({ mount_path, organization, base_url, ttl, max_ttl, token_policies }) => {
      try {
        await (client as any).request(`/auth/${mount_path}/config`, {
          method: 'POST',
          body: JSON.stringify({ organization, base_url, ttl, max_ttl, token_policies }),
        });
        return {
          content: [{ type: 'text', text: JSON.stringify({ success: true, message: 'GitHub configuration updated' }, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_github_list_teams',
    'List all GitHub team mappings.',
    {
      mount_path: z.string().default('github').describe('Mount path of the GitHub auth method'),
    },
    async ({ mount_path }) => {
      try {
        const response = await (client as any).list(`/auth/${mount_path}/map/teams`);
        const teams = response.data?.keys || [];
        return {
          content: [{ type: 'text', text: JSON.stringify({ teams, count: teams.length }, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_github_read_team',
    'Read a GitHub team mapping.',
    {
      mount_path: z.string().default('github').describe('Mount path of the GitHub auth method'),
      team_name: z.string().describe('GitHub team name'),
    },
    async ({ mount_path, team_name }) => {
      try {
        const response = await (client as any).request(`/auth/${mount_path}/map/teams/${team_name}`);
        return {
          content: [{ type: 'text', text: JSON.stringify(response.data || response, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_github_write_team',
    'Create or update a GitHub team mapping.',
    {
      mount_path: z.string().default('github').describe('Mount path of the GitHub auth method'),
      team_name: z.string().describe('GitHub team name'),
      policies: z.array(z.string()).optional().describe('Policies to attach'),
    },
    async ({ mount_path, team_name, policies }) => {
      try {
        await (client as any).request(`/auth/${mount_path}/map/teams/${team_name}`, {
          method: 'POST',
          body: JSON.stringify({ value: policies?.join(',') }),
        });
        return {
          content: [{ type: 'text', text: JSON.stringify({ success: true, message: `Team '${team_name}' mapping updated` }, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_github_delete_team',
    'Delete a GitHub team mapping.',
    {
      mount_path: z.string().default('github').describe('Mount path of the GitHub auth method'),
      team_name: z.string().describe('GitHub team name'),
    },
    async ({ mount_path, team_name }) => {
      try {
        await (client as any).request(`/auth/${mount_path}/map/teams/${team_name}`, { method: 'DELETE' });
        return {
          content: [{ type: 'text', text: JSON.stringify({ success: true, message: `Team '${team_name}' mapping deleted` }, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_github_list_users',
    'List all GitHub user mappings.',
    {
      mount_path: z.string().default('github').describe('Mount path of the GitHub auth method'),
    },
    async ({ mount_path }) => {
      try {
        const response = await (client as any).list(`/auth/${mount_path}/map/users`);
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
    'vault_github_read_user',
    'Read a GitHub user mapping.',
    {
      mount_path: z.string().default('github').describe('Mount path of the GitHub auth method'),
      username: z.string().describe('GitHub username'),
    },
    async ({ mount_path, username }) => {
      try {
        const response = await (client as any).request(`/auth/${mount_path}/map/users/${username}`);
        return {
          content: [{ type: 'text', text: JSON.stringify(response.data || response, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_github_write_user',
    'Create or update a GitHub user mapping.',
    {
      mount_path: z.string().default('github').describe('Mount path of the GitHub auth method'),
      username: z.string().describe('GitHub username'),
      policies: z.array(z.string()).optional().describe('Policies to attach'),
    },
    async ({ mount_path, username, policies }) => {
      try {
        await (client as any).request(`/auth/${mount_path}/map/users/${username}`, {
          method: 'POST',
          body: JSON.stringify({ value: policies?.join(',') }),
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
    'vault_github_delete_user',
    'Delete a GitHub user mapping.',
    {
      mount_path: z.string().default('github').describe('Mount path of the GitHub auth method'),
      username: z.string().describe('GitHub username'),
    },
    async ({ mount_path, username }) => {
      try {
        await (client as any).request(`/auth/${mount_path}/map/users/${username}`, { method: 'DELETE' });
        return {
          content: [{ type: 'text', text: JSON.stringify({ success: true, message: `User '${username}' mapping deleted` }, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_github_login',
    'Login using a GitHub personal access token.',
    {
      mount_path: z.string().default('github').describe('Mount path of the GitHub auth method'),
      token: z.string().describe('GitHub personal access token'),
    },
    async ({ mount_path, token }) => {
      try {
        const response = await (client as any).request(`/auth/${mount_path}/login`, {
          method: 'POST',
          body: JSON.stringify({ token }),
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
