/**
 * KV Secrets Engine Tools
 *
 * MCP tools for KV v1 and v2 secrets engines including read, write,
 * delete, list, and metadata operations.
 */

import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import type { VaultClient } from '../client.js';
import { formatError } from '../utils/formatters.js';

export function registerKvTools(server: McpServer, client: VaultClient): void {
  // ===========================================================================
  // KV v2 - Read/Write
  // ===========================================================================

  server.tool(
    'vault_kv_read',
    'Read a secret from KV v2 secrets engine.',
    {
      mount_path: z.string().default('secret').describe('Mount path of the KV v2 engine'),
      path: z.string().describe('Path to the secret'),
      version: z.number().int().optional().describe('Specific version to read (default: latest)'),
    },
    async ({ mount_path, path, version }) => {
      try {
        const secret = await client.kvRead(mount_path, path, version);
        return {
          content: [{ type: 'text', text: JSON.stringify(secret, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_kv_write',
    'Write a secret to KV v2 secrets engine.',
    {
      mount_path: z.string().default('secret').describe('Mount path of the KV v2 engine'),
      path: z.string().describe('Path to the secret'),
      data: z.record(z.string(), z.unknown()).describe('Secret data as key-value pairs'),
      cas: z.number().int().optional().describe('Check-and-set version (for optimistic locking)'),
    },
    async ({ mount_path, path, data, cas }) => {
      try {
        const result = await client.kvWrite(mount_path, path, data, cas !== undefined ? { cas } : undefined);
        return {
          content: [{ type: 'text', text: JSON.stringify({ success: true, ...result }, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_kv_delete',
    'Delete the latest version of a secret (soft delete in KV v2).',
    {
      mount_path: z.string().default('secret').describe('Mount path of the KV v2 engine'),
      path: z.string().describe('Path to the secret'),
    },
    async ({ mount_path, path }) => {
      try {
        await client.kvDelete(mount_path, path);
        return {
          content: [{ type: 'text', text: JSON.stringify({ success: true, message: `Secret '${path}' deleted` }, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_kv_delete_versions',
    'Delete specific versions of a secret (soft delete).',
    {
      mount_path: z.string().default('secret').describe('Mount path of the KV v2 engine'),
      path: z.string().describe('Path to the secret'),
      versions: z.array(z.number().int()).describe('Version numbers to delete'),
    },
    async ({ mount_path, path, versions }) => {
      try {
        await client.kvDeleteVersions(mount_path, path, versions);
        return {
          content: [{ type: 'text', text: JSON.stringify({ success: true, message: `Versions ${versions.join(', ')} deleted` }, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_kv_undelete',
    'Undelete (restore) soft-deleted versions of a secret.',
    {
      mount_path: z.string().default('secret').describe('Mount path of the KV v2 engine'),
      path: z.string().describe('Path to the secret'),
      versions: z.array(z.number().int()).describe('Version numbers to restore'),
    },
    async ({ mount_path, path, versions }) => {
      try {
        await client.kvUndelete(mount_path, path, versions);
        return {
          content: [{ type: 'text', text: JSON.stringify({ success: true, message: `Versions ${versions.join(', ')} restored` }, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_kv_destroy',
    'Permanently destroy versions of a secret (cannot be recovered).',
    {
      mount_path: z.string().default('secret').describe('Mount path of the KV v2 engine'),
      path: z.string().describe('Path to the secret'),
      versions: z.array(z.number().int()).describe('Version numbers to permanently destroy'),
    },
    async ({ mount_path, path, versions }) => {
      try {
        await client.kvDestroy(mount_path, path, versions);
        return {
          content: [{ type: 'text', text: JSON.stringify({ success: true, message: `Versions ${versions.join(', ')} permanently destroyed` }, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_kv_list',
    'List secrets at a path in KV v2 engine.',
    {
      mount_path: z.string().default('secret').describe('Mount path of the KV v2 engine'),
      path: z.string().optional().describe('Path to list (default: root)'),
    },
    async ({ mount_path, path }) => {
      try {
        const keys = await client.kvList(mount_path, path);
        return {
          content: [{ type: 'text', text: JSON.stringify({ keys, count: keys.length }, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // KV v2 - Metadata
  // ===========================================================================

  server.tool(
    'vault_kv_read_metadata',
    'Read metadata for a secret including version history.',
    {
      mount_path: z.string().default('secret').describe('Mount path of the KV v2 engine'),
      path: z.string().describe('Path to the secret'),
    },
    async ({ mount_path, path }) => {
      try {
        const metadata = await client.kvReadMetadata(mount_path, path);
        return {
          content: [{ type: 'text', text: JSON.stringify(metadata, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_kv_write_metadata',
    'Update metadata for a secret.',
    {
      mount_path: z.string().default('secret').describe('Mount path of the KV v2 engine'),
      path: z.string().describe('Path to the secret'),
      max_versions: z.number().int().optional().describe('Maximum number of versions to keep'),
      cas_required: z.boolean().optional().describe('Require check-and-set for writes'),
      delete_version_after: z.string().optional().describe('Auto-delete versions after duration (e.g., "30d")'),
      custom_metadata: z.record(z.string(), z.string()).optional().describe('Custom metadata key-value pairs'),
    },
    async ({ mount_path, path, max_versions, cas_required, delete_version_after, custom_metadata }) => {
      try {
        await client.kvWriteMetadata(mount_path, path, {
          max_versions,
          cas_required,
          delete_version_after,
          custom_metadata,
        } as any);
        return {
          content: [{ type: 'text', text: JSON.stringify({ success: true, message: `Metadata for '${path}' updated` }, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_kv_delete_metadata',
    'Delete all versions and metadata for a secret permanently.',
    {
      mount_path: z.string().default('secret').describe('Mount path of the KV v2 engine'),
      path: z.string().describe('Path to the secret'),
    },
    async ({ mount_path, path }) => {
      try {
        await client.kvDeleteMetadata(mount_path, path);
        return {
          content: [{ type: 'text', text: JSON.stringify({ success: true, message: `All versions and metadata for '${path}' deleted` }, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // KV v2 - Configuration
  // ===========================================================================

  server.tool(
    'vault_kv_read_config',
    'Read the configuration of a KV v2 secrets engine.',
    {
      mount_path: z.string().default('secret').describe('Mount path of the KV v2 engine'),
    },
    async ({ mount_path }) => {
      try {
        const config = await client.kvReadConfig(mount_path);
        return {
          content: [{ type: 'text', text: JSON.stringify(config, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_kv_write_config',
    'Configure a KV v2 secrets engine.',
    {
      mount_path: z.string().default('secret').describe('Mount path of the KV v2 engine'),
      max_versions: z.number().int().optional().describe('Default maximum versions to keep'),
      cas_required: z.boolean().optional().describe('Require check-and-set by default'),
      delete_version_after: z.string().optional().describe('Default auto-delete duration'),
    },
    async ({ mount_path, max_versions, cas_required, delete_version_after }) => {
      try {
        await client.kvWriteConfig(mount_path, { max_versions, cas_required, delete_version_after });
        return {
          content: [{ type: 'text', text: JSON.stringify({ success: true, message: `KV engine '${mount_path}' configured` }, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // KV v1
  // ===========================================================================

  server.tool(
    'vault_kv_v1_read',
    'Read a secret from KV v1 secrets engine.',
    {
      mount_path: z.string().describe('Mount path of the KV v1 engine'),
      path: z.string().describe('Path to the secret'),
    },
    async ({ mount_path, path }) => {
      try {
        const secret = await client.kvV1Read(mount_path, path);
        return {
          content: [{ type: 'text', text: JSON.stringify(secret, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_kv_v1_write',
    'Write a secret to KV v1 secrets engine.',
    {
      mount_path: z.string().describe('Mount path of the KV v1 engine'),
      path: z.string().describe('Path to the secret'),
      data: z.record(z.string(), z.unknown()).describe('Secret data as key-value pairs'),
    },
    async ({ mount_path, path, data }) => {
      try {
        await client.kvV1Write(mount_path, path, data);
        return {
          content: [{ type: 'text', text: JSON.stringify({ success: true, message: `Secret '${path}' written` }, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_kv_v1_delete',
    'Delete a secret from KV v1 secrets engine.',
    {
      mount_path: z.string().describe('Mount path of the KV v1 engine'),
      path: z.string().describe('Path to the secret'),
    },
    async ({ mount_path, path }) => {
      try {
        await client.kvV1Delete(mount_path, path);
        return {
          content: [{ type: 'text', text: JSON.stringify({ success: true, message: `Secret '${path}' deleted` }, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_kv_v1_list',
    'List secrets at a path in KV v1 engine.',
    {
      mount_path: z.string().describe('Mount path of the KV v1 engine'),
      path: z.string().optional().describe('Path to list (default: root)'),
    },
    async ({ mount_path, path }) => {
      try {
        const keys = await client.kvV1List(mount_path, path);
        return {
          content: [{ type: 'text', text: JSON.stringify({ keys, count: keys.length }, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );
}
