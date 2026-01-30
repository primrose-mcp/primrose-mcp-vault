/**
 * System Backend Tools
 *
 * MCP tools for Vault system operations including health, seal status,
 * mounts, auth methods, and policies.
 */

import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import type { VaultClient } from '../client.js';
import { formatError } from '../utils/formatters.js';

export function registerSystemTools(server: McpServer, client: VaultClient): void {
  // ===========================================================================
  // Health & Status
  // ===========================================================================

  server.tool(
    'vault_health',
    'Get Vault health status including initialization, seal state, and version.',
    {},
    async () => {
      try {
        const health = await client.getHealth();
        return {
          content: [{ type: 'text', text: JSON.stringify(health, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_seal_status',
    'Get Vault seal status including key shares and threshold.',
    {},
    async () => {
      try {
        const status = await client.getSealStatus();
        return {
          content: [{ type: 'text', text: JSON.stringify(status, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_leader',
    'Get Vault cluster leader information for HA deployments.',
    {},
    async () => {
      try {
        const leader = await client.getLeader();
        return {
          content: [{ type: 'text', text: JSON.stringify(leader, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Seal/Unseal Operations
  // ===========================================================================

  server.tool(
    'vault_seal',
    'Seal the Vault. WARNING: This will make Vault unavailable until unsealed.',
    {},
    async () => {
      try {
        await client.seal();
        return {
          content: [{ type: 'text', text: JSON.stringify({ success: true, message: 'Vault sealed successfully' }, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_unseal',
    'Provide an unseal key to unseal Vault. Multiple keys may be required based on threshold.',
    {
      key: z.string().describe('Unseal key (one of the key shares)'),
      reset: z.boolean().optional().describe('Reset the unseal progress'),
    },
    async ({ key, reset }) => {
      try {
        const status = await client.unseal(key, reset);
        return {
          content: [{ type: 'text', text: JSON.stringify(status, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_init',
    'Initialize a new Vault instance. Only works on uninitialized Vault.',
    {
      secret_shares: z.number().int().min(1).describe('Number of key shares to generate'),
      secret_threshold: z.number().int().min(1).describe('Number of key shares required to unseal'),
    },
    async ({ secret_shares, secret_threshold }) => {
      try {
        const result = await client.init({ secret_shares, secret_threshold });
        return {
          content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Mounts (Secrets Engines)
  // ===========================================================================

  server.tool(
    'vault_list_mounts',
    'List all mounted secrets engines.',
    {},
    async () => {
      try {
        const mounts = await client.listMounts();
        return {
          content: [{ type: 'text', text: JSON.stringify(mounts, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_enable_secrets_engine',
    'Enable a new secrets engine at the specified path.',
    {
      path: z.string().describe('Mount path for the secrets engine'),
      type: z.string().describe('Type of secrets engine (kv, transit, pki, database, etc.)'),
      description: z.string().optional().describe('Human-friendly description'),
      options: z.record(z.string(), z.string()).optional().describe('Engine-specific options (e.g., {"version": "2"} for KV)'),
    },
    async ({ path, type, description, options }) => {
      try {
        await client.enableSecretsEngine(path, { type, description, options });
        return {
          content: [{ type: 'text', text: JSON.stringify({ success: true, message: `Secrets engine '${type}' enabled at '${path}'` }, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_disable_secrets_engine',
    'Disable a secrets engine. WARNING: This will revoke all secrets from this engine.',
    {
      path: z.string().describe('Mount path of the secrets engine to disable'),
    },
    async ({ path }) => {
      try {
        await client.disableSecretsEngine(path);
        return {
          content: [{ type: 'text', text: JSON.stringify({ success: true, message: `Secrets engine at '${path}' disabled` }, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_tune_mount',
    'Tune configuration of a mounted secrets engine.',
    {
      path: z.string().describe('Mount path'),
      default_lease_ttl: z.string().optional().describe('Default lease TTL (e.g., "1h", "24h")'),
      max_lease_ttl: z.string().optional().describe('Maximum lease TTL'),
      description: z.string().optional().describe('Updated description'),
    },
    async ({ path, default_lease_ttl, max_lease_ttl, description }) => {
      try {
        await client.tuneMount(path, { default_lease_ttl, max_lease_ttl, description });
        return {
          content: [{ type: 'text', text: JSON.stringify({ success: true, message: `Mount '${path}' tuned successfully` }, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Auth Methods
  // ===========================================================================

  server.tool(
    'vault_list_auth_methods',
    'List all enabled authentication methods.',
    {},
    async () => {
      try {
        const methods = await client.listAuthMethods();
        return {
          content: [{ type: 'text', text: JSON.stringify(methods, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_enable_auth_method',
    'Enable a new authentication method at the specified path.',
    {
      path: z.string().describe('Mount path for the auth method'),
      type: z.string().describe('Type of auth method (approle, ldap, userpass, etc.)'),
      description: z.string().optional().describe('Human-friendly description'),
    },
    async ({ path, type, description }) => {
      try {
        await client.enableAuthMethod(path, { type, description });
        return {
          content: [{ type: 'text', text: JSON.stringify({ success: true, message: `Auth method '${type}' enabled at '${path}'` }, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_disable_auth_method',
    'Disable an authentication method.',
    {
      path: z.string().describe('Mount path of the auth method to disable'),
    },
    async ({ path }) => {
      try {
        await client.disableAuthMethod(path);
        return {
          content: [{ type: 'text', text: JSON.stringify({ success: true, message: `Auth method at '${path}' disabled` }, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Policies
  // ===========================================================================

  server.tool(
    'vault_list_policies',
    'List all ACL policies.',
    {},
    async () => {
      try {
        const policies = await client.listPolicies();
        return {
          content: [{ type: 'text', text: JSON.stringify({ policies }, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_get_policy',
    'Get the rules for a specific policy.',
    {
      name: z.string().describe('Policy name'),
    },
    async ({ name }) => {
      try {
        const policy = await client.getPolicy(name);
        return {
          content: [{ type: 'text', text: JSON.stringify({ name, policy }, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_create_policy',
    'Create or update an ACL policy.',
    {
      name: z.string().describe('Policy name'),
      policy: z.string().describe('Policy rules in HCL format'),
    },
    async ({ name, policy }) => {
      try {
        await client.createPolicy(name, policy);
        return {
          content: [{ type: 'text', text: JSON.stringify({ success: true, message: `Policy '${name}' created/updated` }, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_delete_policy',
    'Delete an ACL policy.',
    {
      name: z.string().describe('Policy name to delete'),
    },
    async ({ name }) => {
      try {
        await client.deletePolicy(name);
        return {
          content: [{ type: 'text', text: JSON.stringify({ success: true, message: `Policy '${name}' deleted` }, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Audit Devices
  // ===========================================================================

  server.tool(
    'vault_list_audit_devices',
    'List all enabled audit devices.',
    {},
    async () => {
      try {
        const devices = await client.listAuditDevices();
        return {
          content: [{ type: 'text', text: JSON.stringify(devices, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_enable_audit_device',
    'Enable a new audit device.',
    {
      path: z.string().describe('Path for the audit device'),
      type: z.string().describe('Type of audit device (file, socket, syslog)'),
      description: z.string().optional().describe('Human-friendly description'),
      options: z.record(z.string(), z.string()).optional().describe('Device-specific options (e.g., {"file_path": "/var/log/vault.log"})'),
    },
    async ({ path, type, description, options }) => {
      try {
        await client.enableAuditDevice(path, { type, description, options });
        return {
          content: [{ type: 'text', text: JSON.stringify({ success: true, message: `Audit device '${type}' enabled at '${path}'` }, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_disable_audit_device',
    'Disable an audit device.',
    {
      path: z.string().describe('Path of the audit device to disable'),
    },
    async ({ path }) => {
      try {
        await client.disableAuditDevice(path);
        return {
          content: [{ type: 'text', text: JSON.stringify({ success: true, message: `Audit device at '${path}' disabled` }, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Capabilities
  // ===========================================================================

  server.tool(
    'vault_check_capabilities',
    'Check what capabilities a token has on given paths.',
    {
      paths: z.array(z.string()).describe('Paths to check capabilities for'),
      token: z.string().optional().describe('Token to check (defaults to current token)'),
    },
    async ({ paths, token }) => {
      try {
        const capabilities = await client.checkCapabilities(paths, token);
        return {
          content: [{ type: 'text', text: JSON.stringify(capabilities, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );
}
