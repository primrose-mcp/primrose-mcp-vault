/**
 * Lease Management Tools
 *
 * MCP tools for managing Vault leases including lookup, renewal,
 * and revocation operations.
 */

import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import type { VaultClient } from '../client.js';
import { formatError } from '../utils/formatters.js';

export function registerLeaseTools(server: McpServer, client: VaultClient): void {
  // ===========================================================================
  // Lease Lookup
  // ===========================================================================

  server.tool(
    'vault_lookup_lease',
    'Look up information about a lease.',
    {
      lease_id: z.string().describe('Lease ID to look up'),
    },
    async ({ lease_id }) => {
      try {
        const lease = await client.lookupLease(lease_id);
        return {
          content: [{ type: 'text', text: JSON.stringify(lease, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Lease Renewal
  // ===========================================================================

  server.tool(
    'vault_renew_lease',
    'Renew a lease to extend its validity.',
    {
      lease_id: z.string().describe('Lease ID to renew'),
      increment: z.number().int().optional().describe('Requested increment in seconds'),
    },
    async ({ lease_id, increment }) => {
      try {
        const lease = await client.renewLease(lease_id, increment);
        return {
          content: [{ type: 'text', text: JSON.stringify(lease, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Lease Revocation
  // ===========================================================================

  server.tool(
    'vault_revoke_lease',
    'Revoke a lease immediately.',
    {
      lease_id: z.string().describe('Lease ID to revoke'),
      sync: z.boolean().optional().describe('Wait for revocation to complete (default: false)'),
    },
    async ({ lease_id, sync }) => {
      try {
        await client.revokeLease(lease_id, sync);
        return {
          content: [{ type: 'text', text: JSON.stringify({ success: true, message: `Lease '${lease_id}' revoked` }, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_revoke_lease_prefix',
    'Revoke all leases under a prefix. Requires sudo capability.',
    {
      prefix: z.string().describe('Lease prefix to revoke (e.g., "database/creds/readonly")'),
      sync: z.boolean().optional().describe('Wait for revocation to complete (default: false)'),
    },
    async ({ prefix, sync }) => {
      try {
        await client.revokeLeasePrefix(prefix, sync);
        return {
          content: [{ type: 'text', text: JSON.stringify({ success: true, message: `Leases under prefix '${prefix}' revoked` }, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );
}
