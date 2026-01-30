/**
 * TLS Certificate Auth Method Tools
 *
 * MCP tools for TLS Certificate authentication including certificate
 * role management, CRL management, and login operations.
 */

import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import type { VaultClient } from '../client.js';
import { formatError } from '../utils/formatters.js';

export function registerCertTools(server: McpServer, client: VaultClient): void {
  // ===========================================================================
  // Configuration
  // ===========================================================================

  server.tool(
    'vault_cert_read_config',
    'Read the TLS Certificate auth method configuration.',
    {
      mount_path: z.string().default('cert').describe('Mount path of the Cert auth method'),
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
    'vault_cert_write_config',
    'Configure the TLS Certificate auth method.',
    {
      mount_path: z.string().default('cert').describe('Mount path of the Cert auth method'),
      disable_binding: z.boolean().optional().describe('Disable certificate binding'),
      enable_identity_alias_metadata: z.boolean().optional().describe('Enable identity alias metadata'),
      ocsp_cache_size: z.number().int().optional().describe('OCSP cache size'),
      role_cache_size: z.number().int().optional().describe('Role cache size'),
    },
    async ({ mount_path, disable_binding, enable_identity_alias_metadata, ocsp_cache_size, role_cache_size }) => {
      try {
        await (client as any).request(`/auth/${mount_path}/config`, {
          method: 'POST',
          body: JSON.stringify({ disable_binding, enable_identity_alias_metadata, ocsp_cache_size, role_cache_size }),
        });
        return {
          content: [{ type: 'text', text: JSON.stringify({ success: true, message: 'Certificate auth configuration updated' }, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Certificate Role Management
  // ===========================================================================

  server.tool(
    'vault_cert_list_certs',
    'List all certificate roles.',
    {
      mount_path: z.string().default('cert').describe('Mount path of the Cert auth method'),
    },
    async ({ mount_path }) => {
      try {
        const response = await (client as any).list(`/auth/${mount_path}/certs`);
        const certs = response.data?.keys || [];
        return {
          content: [{ type: 'text', text: JSON.stringify({ certs, count: certs.length }, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_cert_read_cert',
    'Read a certificate role.',
    {
      mount_path: z.string().default('cert').describe('Mount path of the Cert auth method'),
      name: z.string().describe('Certificate role name'),
    },
    async ({ mount_path, name }) => {
      try {
        const response = await (client as any).request(`/auth/${mount_path}/certs/${name}`);
        return {
          content: [{ type: 'text', text: JSON.stringify(response.data || response, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_cert_create_cert',
    'Create or update a certificate role.',
    {
      mount_path: z.string().default('cert').describe('Mount path of the Cert auth method'),
      name: z.string().describe('Certificate role name'),
      certificate: z.string().describe('CA certificate (PEM format)'),
      allowed_common_names: z.array(z.string()).optional().describe('Allowed common names'),
      allowed_dns_sans: z.array(z.string()).optional().describe('Allowed DNS SANs'),
      allowed_email_sans: z.array(z.string()).optional().describe('Allowed email SANs'),
      allowed_uri_sans: z.array(z.string()).optional().describe('Allowed URI SANs'),
      allowed_organizational_units: z.array(z.string()).optional().describe('Allowed OUs'),
      required_extensions: z.array(z.string()).optional().describe('Required certificate extensions'),
      display_name: z.string().optional().describe('Display name for the role'),
      token_ttl: z.string().optional().describe('Token TTL'),
      token_max_ttl: z.string().optional().describe('Maximum token TTL'),
      token_policies: z.array(z.string()).optional().describe('Policies to attach'),
      token_bound_cidrs: z.array(z.string()).optional().describe('CIDRs that can use the token'),
    },
    async ({ mount_path, name, certificate, allowed_common_names, allowed_dns_sans, allowed_email_sans, allowed_uri_sans, allowed_organizational_units, required_extensions, display_name, token_ttl, token_max_ttl, token_policies, token_bound_cidrs }) => {
      try {
        await (client as any).request(`/auth/${mount_path}/certs/${name}`, {
          method: 'POST',
          body: JSON.stringify({
            certificate, allowed_common_names, allowed_dns_sans,
            allowed_email_sans, allowed_uri_sans, allowed_organizational_units,
            required_extensions, display_name, token_ttl, token_max_ttl,
            token_policies, token_bound_cidrs,
          }),
        });
        return {
          content: [{ type: 'text', text: JSON.stringify({ success: true, message: `Certificate role '${name}' created/updated` }, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_cert_delete_cert',
    'Delete a certificate role.',
    {
      mount_path: z.string().default('cert').describe('Mount path of the Cert auth method'),
      name: z.string().describe('Certificate role name'),
    },
    async ({ mount_path, name }) => {
      try {
        await (client as any).request(`/auth/${mount_path}/certs/${name}`, { method: 'DELETE' });
        return {
          content: [{ type: 'text', text: JSON.stringify({ success: true, message: `Certificate role '${name}' deleted` }, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // CRL Management
  // ===========================================================================

  server.tool(
    'vault_cert_list_crls',
    'List all CRLs.',
    {
      mount_path: z.string().default('cert').describe('Mount path of the Cert auth method'),
    },
    async ({ mount_path }) => {
      try {
        const response = await (client as any).list(`/auth/${mount_path}/crls`);
        const crls = response.data?.keys || [];
        return {
          content: [{ type: 'text', text: JSON.stringify({ crls, count: crls.length }, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_cert_read_crl',
    'Read a CRL.',
    {
      mount_path: z.string().default('cert').describe('Mount path of the Cert auth method'),
      name: z.string().describe('CRL name'),
    },
    async ({ mount_path, name }) => {
      try {
        const response = await (client as any).request(`/auth/${mount_path}/crls/${name}`);
        return {
          content: [{ type: 'text', text: JSON.stringify(response.data || response, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_cert_write_crl',
    'Create or update a CRL.',
    {
      mount_path: z.string().default('cert').describe('Mount path of the Cert auth method'),
      name: z.string().describe('CRL name'),
      crl: z.string().describe('CRL in PEM format'),
      url: z.string().optional().describe('URL to fetch CRL from'),
    },
    async ({ mount_path, name, crl, url }) => {
      try {
        await (client as any).request(`/auth/${mount_path}/crls/${name}`, {
          method: 'POST',
          body: JSON.stringify({ crl, url }),
        });
        return {
          content: [{ type: 'text', text: JSON.stringify({ success: true, message: `CRL '${name}' created/updated` }, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_cert_delete_crl',
    'Delete a CRL.',
    {
      mount_path: z.string().default('cert').describe('Mount path of the Cert auth method'),
      name: z.string().describe('CRL name'),
    },
    async ({ mount_path, name }) => {
      try {
        await (client as any).request(`/auth/${mount_path}/crls/${name}`, { method: 'DELETE' });
        return {
          content: [{ type: 'text', text: JSON.stringify({ success: true, message: `CRL '${name}' deleted` }, null, 2) }],
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
    'vault_cert_login',
    'Login using a TLS client certificate. Note: The client certificate must be provided at the TLS layer.',
    {
      mount_path: z.string().default('cert').describe('Mount path of the Cert auth method'),
      name: z.string().optional().describe('Certificate role name to authenticate against'),
    },
    async ({ mount_path, name }) => {
      try {
        const body = name ? JSON.stringify({ name }) : '{}';
        const response = await (client as any).request(`/auth/${mount_path}/login`, {
          method: 'POST',
          body,
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
