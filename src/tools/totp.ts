/**
 * TOTP Secrets Engine Tools
 *
 * MCP tools for TOTP (Time-based One-Time Password) operations including
 * key management, code generation, and validation.
 */

import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import type { VaultClient } from '../client.js';
import { formatError } from '../utils/formatters.js';

export function registerTotpTools(server: McpServer, client: VaultClient): void {
  // ===========================================================================
  // Key Management
  // ===========================================================================

  server.tool(
    'vault_totp_list_keys',
    'List all TOTP keys.',
    {
      mount_path: z.string().default('totp').describe('Mount path of the TOTP engine'),
    },
    async ({ mount_path }) => {
      try {
        const keys = await client.totpListKeys(mount_path);
        return {
          content: [{ type: 'text', text: JSON.stringify({ keys, count: keys.length }, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_totp_read_key',
    'Read a TOTP key configuration.',
    {
      mount_path: z.string().default('totp').describe('Mount path of the TOTP engine'),
      name: z.string().describe('Key name'),
    },
    async ({ mount_path, name }) => {
      try {
        const key = await client.totpReadKey(mount_path, name);
        return {
          content: [{ type: 'text', text: JSON.stringify(key, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_totp_create_key',
    'Create or update a TOTP key.',
    {
      mount_path: z.string().default('totp').describe('Mount path of the TOTP engine'),
      name: z.string().describe('Key name'),
      generate: z.boolean().optional().describe('Generate a new key (default: false)'),
      exported: z.boolean().optional().describe('Allow key to be exported'),
      key_size: z.number().int().optional().describe('Key size in bytes (default: 20)'),
      url: z.string().optional().describe('TOTP URL to import (otpauth://...)'),
      key: z.string().optional().describe('Base32 encoded key to import'),
      issuer: z.string().optional().describe('Issuer name for the key'),
      account_name: z.string().optional().describe('Account name'),
      period: z.number().int().optional().describe('Time period in seconds (default: 30)'),
      algorithm: z.enum(['SHA1', 'SHA256', 'SHA512']).optional().describe('Hash algorithm'),
      digits: z.number().int().optional().describe('Number of digits (6 or 8)'),
      skew: z.number().int().optional().describe('Number of delay periods allowed'),
      qr_size: z.number().int().optional().describe('QR code size in pixels'),
    },
    async ({ mount_path, name, generate, exported, key_size, url, key, issuer, account_name, period, algorithm, digits, skew, qr_size }) => {
      try {
        const result = await client.totpCreateKey(mount_path, name, {
          generate,
          exported,
          key_size,
          url,
          key,
          issuer,
          account_name,
          period,
          algorithm,
          digits,
          skew,
          qr_size,
        });
        return {
          content: [{ type: 'text', text: JSON.stringify({ success: true, message: `TOTP key '${name}' created/updated`, ...result }, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_totp_delete_key',
    'Delete a TOTP key.',
    {
      mount_path: z.string().default('totp').describe('Mount path of the TOTP engine'),
      name: z.string().describe('Key name to delete'),
    },
    async ({ mount_path, name }) => {
      try {
        await client.totpDeleteKey(mount_path, name);
        return {
          content: [{ type: 'text', text: JSON.stringify({ success: true, message: `TOTP key '${name}' deleted` }, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Code Operations
  // ===========================================================================

  server.tool(
    'vault_totp_generate_code',
    'Generate a TOTP code for a key.',
    {
      mount_path: z.string().default('totp').describe('Mount path of the TOTP engine'),
      name: z.string().describe('Key name'),
    },
    async ({ mount_path, name }) => {
      try {
        const code = await client.totpGenerateCode(mount_path, name);
        return {
          content: [{ type: 'text', text: JSON.stringify(code, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_totp_validate_code',
    'Validate a TOTP code.',
    {
      mount_path: z.string().default('totp').describe('Mount path of the TOTP engine'),
      name: z.string().describe('Key name'),
      code: z.string().describe('TOTP code to validate'),
    },
    async ({ mount_path, name, code }) => {
      try {
        const result = await client.totpValidateCode(mount_path, name, code);
        return {
          content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );
}
