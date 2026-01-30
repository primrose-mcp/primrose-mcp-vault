/**
 * System Wrapping Tools
 *
 * MCP tools for Vault response wrapping operations including wrap,
 * unwrap, rewrap, and lookup.
 */

import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import type { VaultClient } from '../client.js';
import { formatError } from '../utils/formatters.js';

export function registerWrappingTools(server: McpServer, client: VaultClient): void {
  server.tool(
    'vault_wrap',
    'Wrap arbitrary data in a single-use wrapping token.',
    {
      data: z.record(z.string(), z.unknown()).describe('Data to wrap'),
      ttl: z.string().optional().describe('Wrapping token TTL (default: 5m)'),
    },
    async ({ data, ttl }) => {
      try {
        const wrapInfo = await client.wrap(data, ttl);
        return {
          content: [{ type: 'text', text: JSON.stringify(wrapInfo, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_unwrap',
    'Unwrap a wrapping token to retrieve the wrapped data.',
    {
      token: z.string().optional().describe('Wrapping token (uses current token if not provided)'),
    },
    async ({ token }) => {
      try {
        const data = await client.unwrap(token);
        return {
          content: [{ type: 'text', text: JSON.stringify(data, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_rewrap',
    'Rewrap a wrapping token with a new token.',
    {
      token: z.string().describe('Wrapping token to rewrap'),
    },
    async ({ token }) => {
      try {
        const wrapInfo = await client.rewrap(token);
        return {
          content: [{ type: 'text', text: JSON.stringify(wrapInfo, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_lookup_wrapping',
    'Look up information about a wrapping token without unwrapping it.',
    {
      token: z.string().describe('Wrapping token to look up'),
    },
    async ({ token }) => {
      try {
        const info = await client.lookupWrapping(token);
        return {
          content: [{ type: 'text', text: JSON.stringify(info, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // System Tools
  // ===========================================================================

  server.tool(
    'vault_sys_generate_random',
    'Generate cryptographically secure random bytes.',
    {
      bytes: z.number().int().default(32).describe('Number of bytes to generate'),
      format: z.enum(['base64', 'hex']).default('base64').describe('Output format'),
    },
    async ({ bytes, format }) => {
      try {
        const randomBytes = await client.sysGenerateRandom(bytes, format);
        return {
          content: [{ type: 'text', text: JSON.stringify({ random_bytes: randomBytes }, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_sys_hash',
    'Hash data using a cryptographic hash function.',
    {
      input: z.string().describe('Data to hash (base64 encoded)'),
      algorithm: z.enum(['sha2-224', 'sha2-256', 'sha2-384', 'sha2-512']).default('sha2-256').describe('Hash algorithm'),
      format: z.enum(['hex', 'base64']).default('hex').describe('Output format'),
    },
    async ({ input, algorithm, format }) => {
      try {
        const hash = await client.sysHash(input, algorithm, format);
        return {
          content: [{ type: 'text', text: JSON.stringify({ sum: hash }, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );
}
