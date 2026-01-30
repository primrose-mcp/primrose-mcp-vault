/**
 * Transit Secrets Engine Tools
 *
 * MCP tools for Transit encryption-as-a-service including key management,
 * encryption, decryption, signing, verification, and cryptographic operations.
 */

import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import type { VaultClient } from '../client.js';
import { formatError } from '../utils/formatters.js';

export function registerTransitTools(server: McpServer, client: VaultClient): void {
  // ===========================================================================
  // Key Management
  // ===========================================================================

  server.tool(
    'vault_transit_create_key',
    'Create a new encryption key in the Transit secrets engine.',
    {
      mount_path: z.string().default('transit').describe('Mount path of the Transit engine'),
      name: z.string().describe('Name of the encryption key'),
      type: z.enum([
        'aes128-gcm96', 'aes256-gcm96', 'chacha20-poly1305',
        'ed25519', 'ecdsa-p256', 'ecdsa-p384', 'ecdsa-p521',
        'rsa-2048', 'rsa-3072', 'rsa-4096'
      ]).optional().describe('Key type (default: aes256-gcm96)'),
      exportable: z.boolean().optional().describe('Allow key to be exported'),
      allow_plaintext_backup: z.boolean().optional().describe('Allow plaintext backup'),
      derived: z.boolean().optional().describe('Use key derivation'),
      convergent_encryption: z.boolean().optional().describe('Enable convergent encryption (requires derived)'),
    },
    async ({ mount_path, name, type, exportable, allow_plaintext_backup, derived, convergent_encryption }) => {
      try {
        await client.transitCreateKey(mount_path, name, {
          type,
          exportable,
          allow_plaintext_backup,
          derived,
          convergent_encryption,
        });
        return {
          content: [{ type: 'text', text: JSON.stringify({ success: true, message: `Transit key '${name}' created` }, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_transit_read_key',
    'Read information about a Transit encryption key.',
    {
      mount_path: z.string().default('transit').describe('Mount path of the Transit engine'),
      name: z.string().describe('Name of the encryption key'),
    },
    async ({ mount_path, name }) => {
      try {
        const key = await client.transitReadKey(mount_path, name);
        return {
          content: [{ type: 'text', text: JSON.stringify(key, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_transit_list_keys',
    'List all keys in the Transit secrets engine.',
    {
      mount_path: z.string().default('transit').describe('Mount path of the Transit engine'),
    },
    async ({ mount_path }) => {
      try {
        const keys = await client.transitListKeys(mount_path);
        return {
          content: [{ type: 'text', text: JSON.stringify({ keys, count: keys.length }, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_transit_delete_key',
    'Delete a Transit encryption key. Key must have deletion_allowed=true.',
    {
      mount_path: z.string().default('transit').describe('Mount path of the Transit engine'),
      name: z.string().describe('Name of the encryption key to delete'),
    },
    async ({ mount_path, name }) => {
      try {
        await client.transitDeleteKey(mount_path, name);
        return {
          content: [{ type: 'text', text: JSON.stringify({ success: true, message: `Transit key '${name}' deleted` }, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_transit_update_key_config',
    'Update configuration of a Transit encryption key.',
    {
      mount_path: z.string().default('transit').describe('Mount path of the Transit engine'),
      name: z.string().describe('Name of the encryption key'),
      deletion_allowed: z.boolean().optional().describe('Allow key deletion'),
      exportable: z.boolean().optional().describe('Allow key export (can only enable, not disable)'),
      allow_plaintext_backup: z.boolean().optional().describe('Allow plaintext backup'),
      min_decryption_version: z.number().int().optional().describe('Minimum version for decryption'),
      min_encryption_version: z.number().int().optional().describe('Minimum version for encryption'),
      auto_rotate_period: z.string().optional().describe('Auto-rotate period (e.g., "720h")'),
    },
    async ({ mount_path, name, deletion_allowed, exportable, allow_plaintext_backup, min_decryption_version, min_encryption_version, auto_rotate_period }) => {
      try {
        await client.transitUpdateKeyConfig(mount_path, name, {
          deletion_allowed,
          exportable,
          allow_plaintext_backup,
          min_decryption_version,
          min_encryption_version,
          auto_rotate_period,
        } as any);
        return {
          content: [{ type: 'text', text: JSON.stringify({ success: true, message: `Transit key '${name}' configuration updated` }, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_transit_rotate_key',
    'Rotate a Transit encryption key to a new version.',
    {
      mount_path: z.string().default('transit').describe('Mount path of the Transit engine'),
      name: z.string().describe('Name of the encryption key to rotate'),
    },
    async ({ mount_path, name }) => {
      try {
        await client.transitRotateKey(mount_path, name);
        return {
          content: [{ type: 'text', text: JSON.stringify({ success: true, message: `Transit key '${name}' rotated` }, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Encryption/Decryption
  // ===========================================================================

  server.tool(
    'vault_transit_encrypt',
    'Encrypt plaintext using a Transit encryption key.',
    {
      mount_path: z.string().default('transit').describe('Mount path of the Transit engine'),
      key_name: z.string().describe('Name of the encryption key'),
      plaintext: z.string().describe('Plaintext to encrypt'),
      context: z.string().optional().describe('Context for derived keys (base64 encoded)'),
      key_version: z.number().int().optional().describe('Specific key version to use'),
    },
    async ({ mount_path, key_name, plaintext, context, key_version }) => {
      try {
        const result = await client.transitEncrypt(mount_path, key_name, plaintext, { context, keyVersion: key_version });
        return {
          content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_transit_decrypt',
    'Decrypt ciphertext using a Transit encryption key.',
    {
      mount_path: z.string().default('transit').describe('Mount path of the Transit engine'),
      key_name: z.string().describe('Name of the encryption key'),
      ciphertext: z.string().describe('Ciphertext to decrypt (vault:v1:... format)'),
      context: z.string().optional().describe('Context for derived keys (base64 encoded)'),
    },
    async ({ mount_path, key_name, ciphertext, context }) => {
      try {
        const result = await client.transitDecrypt(mount_path, key_name, ciphertext, { context });
        return {
          content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_transit_rewrap',
    'Rewrap ciphertext with the latest key version.',
    {
      mount_path: z.string().default('transit').describe('Mount path of the Transit engine'),
      key_name: z.string().describe('Name of the encryption key'),
      ciphertext: z.string().describe('Ciphertext to rewrap'),
      context: z.string().optional().describe('Context for derived keys'),
      key_version: z.number().int().optional().describe('Target key version'),
    },
    async ({ mount_path, key_name, ciphertext, context, key_version }) => {
      try {
        const result = await client.transitRewrap(mount_path, key_name, ciphertext, { context, keyVersion: key_version });
        return {
          content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Data Key Generation
  // ===========================================================================

  server.tool(
    'vault_transit_generate_data_key',
    'Generate a data encryption key wrapped by a Transit key.',
    {
      mount_path: z.string().default('transit').describe('Mount path of the Transit engine'),
      key_name: z.string().describe('Name of the wrapping key'),
      type: z.enum(['plaintext', 'wrapped']).describe('Return plaintext key along with wrapped, or only wrapped'),
      context: z.string().optional().describe('Context for derived keys'),
      bits: z.number().int().optional().describe('Number of bits (128, 256, 512)'),
    },
    async ({ mount_path, key_name, type, context, bits }) => {
      try {
        const result = await client.transitGenerateDataKey(mount_path, key_name, type, { context, bits });
        return {
          content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_transit_generate_random',
    'Generate cryptographically secure random bytes.',
    {
      mount_path: z.string().default('transit').describe('Mount path of the Transit engine'),
      bytes: z.number().int().default(32).describe('Number of bytes to generate'),
      format: z.enum(['base64', 'hex']).default('base64').describe('Output format'),
    },
    async ({ mount_path, bytes, format }) => {
      try {
        const result = await client.transitGenerateRandom(mount_path, bytes, format);
        return {
          content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Hashing
  // ===========================================================================

  server.tool(
    'vault_transit_hash',
    'Hash data using a cryptographic hash function.',
    {
      mount_path: z.string().default('transit').describe('Mount path of the Transit engine'),
      input: z.string().describe('Data to hash'),
      algorithm: z.enum(['sha2-224', 'sha2-256', 'sha2-384', 'sha2-512', 'sha3-224', 'sha3-256', 'sha3-384', 'sha3-512']).default('sha2-256').describe('Hash algorithm'),
      format: z.enum(['hex', 'base64']).default('hex').describe('Output format'),
    },
    async ({ mount_path, input, algorithm, format }) => {
      try {
        const result = await client.transitHash(mount_path, input, algorithm, format);
        return {
          content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_transit_hmac',
    'Generate HMAC for data using a Transit key.',
    {
      mount_path: z.string().default('transit').describe('Mount path of the Transit engine'),
      key_name: z.string().describe('Name of the key for HMAC'),
      input: z.string().describe('Data to HMAC'),
      algorithm: z.enum(['sha2-224', 'sha2-256', 'sha2-384', 'sha2-512', 'sha3-224', 'sha3-256', 'sha3-384', 'sha3-512']).default('sha2-256').describe('Hash algorithm'),
    },
    async ({ mount_path, key_name, input, algorithm }) => {
      try {
        const result = await client.transitHmac(mount_path, key_name, input, algorithm);
        return {
          content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Signing/Verification
  // ===========================================================================

  server.tool(
    'vault_transit_sign',
    'Sign data using a Transit signing key.',
    {
      mount_path: z.string().default('transit').describe('Mount path of the Transit engine'),
      key_name: z.string().describe('Name of the signing key'),
      input: z.string().describe('Data to sign'),
      hash_algorithm: z.enum(['sha1', 'sha2-224', 'sha2-256', 'sha2-384', 'sha2-512', 'sha3-224', 'sha3-256', 'sha3-384', 'sha3-512']).optional().describe('Hash algorithm'),
      signature_algorithm: z.enum(['pss', 'pkcs1v15']).optional().describe('Signature algorithm (RSA keys only)'),
    },
    async ({ mount_path, key_name, input, hash_algorithm, signature_algorithm }) => {
      try {
        const result = await client.transitSign(mount_path, key_name, input, {
          hashAlgorithm: hash_algorithm,
          signatureAlgorithm: signature_algorithm,
        });
        return {
          content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_transit_verify',
    'Verify a signature using a Transit signing key.',
    {
      mount_path: z.string().default('transit').describe('Mount path of the Transit engine'),
      key_name: z.string().describe('Name of the signing key'),
      input: z.string().describe('Original data that was signed'),
      signature: z.string().describe('Signature to verify (vault:v1:... format)'),
      hash_algorithm: z.enum(['sha1', 'sha2-224', 'sha2-256', 'sha2-384', 'sha2-512', 'sha3-224', 'sha3-256', 'sha3-384', 'sha3-512']).optional().describe('Hash algorithm'),
    },
    async ({ mount_path, key_name, input, signature, hash_algorithm }) => {
      try {
        const result = await client.transitVerify(mount_path, key_name, input, signature, {
          hashAlgorithm: hash_algorithm,
        });
        return {
          content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );
}
