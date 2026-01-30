/**
 * SSH Secrets Engine Tools
 *
 * MCP tools for SSH secrets engine operations including role management,
 * credential generation, key signing, and CA configuration.
 */

import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import type { VaultClient } from '../client.js';
import { formatError } from '../utils/formatters.js';

export function registerSshTools(server: McpServer, client: VaultClient): void {
  // ===========================================================================
  // Role Management
  // ===========================================================================

  server.tool(
    'vault_ssh_list_roles',
    'List all SSH roles.',
    {
      mount_path: z.string().default('ssh').describe('Mount path of the SSH engine'),
    },
    async ({ mount_path }) => {
      try {
        const roles = await client.sshListRoles(mount_path);
        return {
          content: [{ type: 'text', text: JSON.stringify({ roles, count: roles.length }, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_ssh_read_role',
    'Read configuration of an SSH role.',
    {
      mount_path: z.string().default('ssh').describe('Mount path of the SSH engine'),
      name: z.string().describe('Role name'),
    },
    async ({ mount_path, name }) => {
      try {
        const role = await client.sshReadRole(mount_path, name);
        return {
          content: [{ type: 'text', text: JSON.stringify(role, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_ssh_create_role',
    'Create or update an SSH role.',
    {
      mount_path: z.string().default('ssh').describe('Mount path of the SSH engine'),
      name: z.string().describe('Role name'),
      key_type: z.enum(['otp', 'ca', 'dynamic']).describe('SSH key type'),
      default_user: z.string().optional().describe('Default username'),
      allowed_users: z.string().optional().describe('Comma-separated allowed usernames or "*" for any'),
      cidr_list: z.string().optional().describe('Comma-separated CIDR blocks for OTP roles'),
      ttl: z.string().optional().describe('Certificate TTL for CA roles'),
      max_ttl: z.string().optional().describe('Maximum certificate TTL'),
      allowed_extensions: z.string().optional().describe('Allowed certificate extensions'),
      allow_user_certificates: z.boolean().optional().describe('Allow user certificates'),
      allow_host_certificates: z.boolean().optional().describe('Allow host certificates'),
      algorithm_signer: z.string().optional().describe('Signing algorithm (rsa-sha2-256, rsa-sha2-512, etc.)'),
    },
    async ({ mount_path, name, key_type, default_user, allowed_users, cidr_list, ttl, max_ttl, allowed_extensions, allow_user_certificates, allow_host_certificates, algorithm_signer }) => {
      try {
        await client.sshCreateRole(mount_path, name, {
          key_type,
          default_user,
          allowed_users,
          cidr_list,
          ttl,
          max_ttl,
          allowed_extensions,
          allow_user_certificates,
          allow_host_certificates,
          algorithm_signer,
        });
        return {
          content: [{ type: 'text', text: JSON.stringify({ success: true, message: `SSH role '${name}' created/updated` }, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_ssh_delete_role',
    'Delete an SSH role.',
    {
      mount_path: z.string().default('ssh').describe('Mount path of the SSH engine'),
      name: z.string().describe('Role name to delete'),
    },
    async ({ mount_path, name }) => {
      try {
        await client.sshDeleteRole(mount_path, name);
        return {
          content: [{ type: 'text', text: JSON.stringify({ success: true, message: `SSH role '${name}' deleted` }, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Credential Generation
  // ===========================================================================

  server.tool(
    'vault_ssh_generate_credentials',
    'Generate SSH credentials (OTP or dynamic key) for a role.',
    {
      mount_path: z.string().default('ssh').describe('Mount path of the SSH engine'),
      role_name: z.string().describe('Role name'),
      ip: z.string().describe('Target IP address'),
      username: z.string().optional().describe('Username (uses role default if not specified)'),
    },
    async ({ mount_path, role_name, ip, username }) => {
      try {
        const creds = await client.sshGenerateCredentials(mount_path, role_name, ip, username);
        return {
          content: [{ type: 'text', text: JSON.stringify(creds, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_ssh_sign_key',
    'Sign an SSH public key using a CA role.',
    {
      mount_path: z.string().default('ssh').describe('Mount path of the SSH engine'),
      role_name: z.string().describe('CA role name'),
      public_key: z.string().describe('SSH public key to sign'),
      ttl: z.string().optional().describe('Certificate TTL'),
      valid_principals: z.string().optional().describe('Comma-separated list of principals'),
      cert_type: z.enum(['user', 'host']).optional().describe('Certificate type'),
      key_id: z.string().optional().describe('Key identifier'),
    },
    async ({ mount_path, role_name, public_key, ttl, valid_principals, cert_type, key_id }) => {
      try {
        const signed = await client.sshSignKey(mount_path, role_name, {
          public_key,
          ttl,
          valid_principals,
          cert_type,
          key_id,
        });
        return {
          content: [{ type: 'text', text: JSON.stringify(signed, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_ssh_verify_otp',
    'Verify an SSH OTP.',
    {
      mount_path: z.string().default('ssh').describe('Mount path of the SSH engine'),
      otp: z.string().describe('One-time password to verify'),
    },
    async ({ mount_path, otp }) => {
      try {
        const result = await client.sshVerifyOtp(mount_path, otp);
        return {
          content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // CA Configuration
  // ===========================================================================

  server.tool(
    'vault_ssh_read_ca_config',
    'Read the SSH CA public key.',
    {
      mount_path: z.string().default('ssh').describe('Mount path of the SSH engine'),
    },
    async ({ mount_path }) => {
      try {
        const config = await client.sshReadCaConfig(mount_path);
        return {
          content: [{ type: 'text', text: JSON.stringify(config, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_ssh_write_ca_config',
    'Configure the SSH CA.',
    {
      mount_path: z.string().default('ssh').describe('Mount path of the SSH engine'),
      generate_signing_key: z.boolean().optional().describe('Generate a new signing key'),
      public_key: z.string().optional().describe('Public key for CA (if not generating)'),
      private_key: z.string().optional().describe('Private key for CA (if not generating)'),
      key_type: z.string().optional().describe('Key type (rsa, ecdsa, ed25519)'),
      key_bits: z.number().int().optional().describe('Key size in bits'),
    },
    async ({ mount_path, generate_signing_key, public_key, private_key, key_type, key_bits }) => {
      try {
        await client.sshWriteCaConfig(mount_path, {
          generate_signing_key,
          public_key,
          private_key,
          key_type,
          key_bits,
        });
        return {
          content: [{ type: 'text', text: JSON.stringify({ success: true, message: 'SSH CA configured' }, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_ssh_delete_ca_config',
    'Delete the SSH CA configuration.',
    {
      mount_path: z.string().default('ssh').describe('Mount path of the SSH engine'),
    },
    async ({ mount_path }) => {
      try {
        await client.sshDeleteCaConfig(mount_path);
        return {
          content: [{ type: 'text', text: JSON.stringify({ success: true, message: 'SSH CA configuration deleted' }, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );
}
