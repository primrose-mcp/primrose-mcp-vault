/**
 * Cubbyhole Secrets Engine Tools
 *
 * MCP tools for Cubbyhole operations. Cubbyhole provides per-token
 * isolated secret storage that is automatically destroyed when the
 * token expires.
 */

import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import type { VaultClient } from '../client.js';
import { formatError } from '../utils/formatters.js';

export function registerCubbyholeTools(server: McpServer, client: VaultClient): void {
  server.tool(
    'vault_cubbyhole_read',
    'Read a secret from cubbyhole storage (token-isolated).',
    {
      path: z.string().describe('Path to the secret'),
    },
    async ({ path }) => {
      try {
        const data = await client.cubbyholeRead(path);
        return {
          content: [{ type: 'text', text: JSON.stringify(data, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_cubbyhole_write',
    'Write a secret to cubbyhole storage (token-isolated).',
    {
      path: z.string().describe('Path to the secret'),
      data: z.record(z.string(), z.unknown()).describe('Secret data as key-value pairs'),
    },
    async ({ path, data }) => {
      try {
        await client.cubbyholeWrite(path, data);
        return {
          content: [{ type: 'text', text: JSON.stringify({ success: true, message: `Secret written to cubbyhole/${path}` }, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_cubbyhole_delete',
    'Delete a secret from cubbyhole storage.',
    {
      path: z.string().describe('Path to the secret'),
    },
    async ({ path }) => {
      try {
        await client.cubbyholeDelete(path);
        return {
          content: [{ type: 'text', text: JSON.stringify({ success: true, message: `Secret deleted from cubbyhole/${path}` }, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_cubbyhole_list',
    'List secrets in cubbyhole storage.',
    {
      path: z.string().optional().describe('Path to list (empty for root)'),
    },
    async ({ path }) => {
      try {
        const keys = await client.cubbyholeList(path);
        return {
          content: [{ type: 'text', text: JSON.stringify({ keys, count: keys.length }, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );
}
