/**
 * PKI Secrets Engine Tools
 *
 * MCP tools for PKI (Public Key Infrastructure) operations including
 * certificate issuance, revocation, roles, and CA management.
 */

import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import type { VaultClient } from '../client.js';
import { formatError } from '../utils/formatters.js';

export function registerPkiTools(server: McpServer, client: VaultClient): void {
  // ===========================================================================
  // Certificate Issuance
  // ===========================================================================

  server.tool(
    'vault_pki_issue_certificate',
    'Issue a new certificate using a PKI role.',
    {
      mount_path: z.string().default('pki').describe('Mount path of the PKI engine'),
      role_name: z.string().describe('PKI role to use for issuance'),
      common_name: z.string().describe('Common name for the certificate'),
      alt_names: z.string().optional().describe('Comma-separated SANs (Subject Alternative Names)'),
      ip_sans: z.string().optional().describe('Comma-separated IP SANs'),
      uri_sans: z.string().optional().describe('Comma-separated URI SANs'),
      ttl: z.string().optional().describe('Certificate TTL (e.g., "24h", "30d")'),
      format: z.enum(['pem', 'der', 'pem_bundle']).optional().describe('Output format'),
      private_key_format: z.enum(['der', 'pem', 'pkcs8']).optional().describe('Private key format'),
      exclude_cn_from_sans: z.boolean().optional().describe('Exclude CN from SANs'),
    },
    async ({ mount_path, role_name, common_name, alt_names, ip_sans, uri_sans, ttl, format, private_key_format, exclude_cn_from_sans }) => {
      try {
        const cert = await client.pkiIssueCertificate(mount_path, role_name, {
          common_name,
          alt_names,
          ip_sans,
          uri_sans,
          ttl,
          format,
          private_key_format,
          exclude_cn_from_sans,
        });
        return {
          content: [{ type: 'text', text: JSON.stringify(cert, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_pki_sign_certificate',
    'Sign a CSR using a PKI role.',
    {
      mount_path: z.string().default('pki').describe('Mount path of the PKI engine'),
      role_name: z.string().describe('PKI role to use for signing'),
      csr: z.string().describe('PEM-encoded Certificate Signing Request'),
      common_name: z.string().optional().describe('Override the CN from CSR'),
      alt_names: z.string().optional().describe('Comma-separated SANs'),
      ip_sans: z.string().optional().describe('Comma-separated IP SANs'),
      uri_sans: z.string().optional().describe('Comma-separated URI SANs'),
      ttl: z.string().optional().describe('Certificate TTL'),
      format: z.enum(['pem', 'der', 'pem_bundle']).optional().describe('Output format'),
    },
    async ({ mount_path, role_name, csr, common_name, alt_names, ip_sans, uri_sans, ttl, format }) => {
      try {
        const cert = await client.pkiSignCertificate(mount_path, role_name, {
          csr,
          common_name,
          alt_names,
          ip_sans,
          uri_sans,
          ttl,
          format,
        });
        return {
          content: [{ type: 'text', text: JSON.stringify(cert, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Certificate Revocation
  // ===========================================================================

  server.tool(
    'vault_pki_revoke_certificate',
    'Revoke a certificate by serial number.',
    {
      mount_path: z.string().default('pki').describe('Mount path of the PKI engine'),
      serial_number: z.string().describe('Serial number of the certificate to revoke'),
    },
    async ({ mount_path, serial_number }) => {
      try {
        await client.pkiRevokeCertificate(mount_path, { serial_number });
        return {
          content: [{ type: 'text', text: JSON.stringify({ success: true, message: `Certificate ${serial_number} revoked` }, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Certificate Listing/Reading
  // ===========================================================================

  server.tool(
    'vault_pki_list_certificates',
    'List all issued certificate serial numbers.',
    {
      mount_path: z.string().default('pki').describe('Mount path of the PKI engine'),
    },
    async ({ mount_path }) => {
      try {
        const serials = await client.pkiListCertificates(mount_path);
        return {
          content: [{ type: 'text', text: JSON.stringify({ certificates: serials, count: serials.length }, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_pki_read_certificate',
    'Read a certificate by serial number.',
    {
      mount_path: z.string().default('pki').describe('Mount path of the PKI engine'),
      serial: z.string().describe('Serial number of the certificate'),
    },
    async ({ mount_path, serial }) => {
      try {
        const cert = await client.pkiReadCertificate(mount_path, serial);
        return {
          content: [{ type: 'text', text: JSON.stringify(cert, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // CA Operations
  // ===========================================================================

  server.tool(
    'vault_pki_get_ca',
    'Get the CA certificate.',
    {
      mount_path: z.string().default('pki').describe('Mount path of the PKI engine'),
    },
    async ({ mount_path }) => {
      try {
        const ca = await client.pkiGetCa(mount_path);
        return {
          content: [{ type: 'text', text: JSON.stringify(ca, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_pki_get_ca_chain',
    'Get the CA certificate chain.',
    {
      mount_path: z.string().default('pki').describe('Mount path of the PKI engine'),
    },
    async ({ mount_path }) => {
      try {
        const chain = await client.pkiGetCaChain(mount_path);
        return {
          content: [{ type: 'text', text: JSON.stringify(chain, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Issuer Management
  // ===========================================================================

  server.tool(
    'vault_pki_list_issuers',
    'List all issuers in the PKI engine.',
    {
      mount_path: z.string().default('pki').describe('Mount path of the PKI engine'),
    },
    async ({ mount_path }) => {
      try {
        const issuers = await client.pkiListIssuers(mount_path);
        return {
          content: [{ type: 'text', text: JSON.stringify({ issuers, count: issuers.length }, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_pki_read_issuer',
    'Read details of a specific issuer.',
    {
      mount_path: z.string().default('pki').describe('Mount path of the PKI engine'),
      issuer_id: z.string().describe('Issuer ID or name'),
    },
    async ({ mount_path, issuer_id }) => {
      try {
        const issuer = await client.pkiReadIssuer(mount_path, issuer_id);
        return {
          content: [{ type: 'text', text: JSON.stringify(issuer, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Role Management
  // ===========================================================================

  server.tool(
    'vault_pki_list_roles',
    'List all PKI roles.',
    {
      mount_path: z.string().default('pki').describe('Mount path of the PKI engine'),
    },
    async ({ mount_path }) => {
      try {
        const roles = await client.pkiListRoles(mount_path);
        return {
          content: [{ type: 'text', text: JSON.stringify({ roles, count: roles.length }, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_pki_read_role',
    'Read configuration of a PKI role.',
    {
      mount_path: z.string().default('pki').describe('Mount path of the PKI engine'),
      name: z.string().describe('Role name'),
    },
    async ({ mount_path, name }) => {
      try {
        const role = await client.pkiReadRole(mount_path, name);
        return {
          content: [{ type: 'text', text: JSON.stringify(role, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_pki_create_role',
    'Create or update a PKI role.',
    {
      mount_path: z.string().default('pki').describe('Mount path of the PKI engine'),
      name: z.string().describe('Role name'),
      ttl: z.string().optional().describe('Default TTL for certificates'),
      max_ttl: z.string().optional().describe('Maximum TTL for certificates'),
      allow_localhost: z.boolean().optional().describe('Allow localhost in SANs'),
      allowed_domains: z.array(z.string()).optional().describe('Allowed domains for certificates'),
      allow_bare_domains: z.boolean().optional().describe('Allow bare domains'),
      allow_subdomains: z.boolean().optional().describe('Allow subdomains'),
      allow_glob_domains: z.boolean().optional().describe('Allow glob patterns in domains'),
      allow_any_name: z.boolean().optional().describe('Allow any common name'),
      enforce_hostnames: z.boolean().optional().describe('Enforce hostnames in certificates'),
      allow_ip_sans: z.boolean().optional().describe('Allow IP SANs'),
      server_flag: z.boolean().optional().describe('Set server flag in certificates'),
      client_flag: z.boolean().optional().describe('Set client flag in certificates'),
      key_type: z.enum(['rsa', 'ec', 'ed25519']).optional().describe('Key type for generated certificates'),
      key_bits: z.number().int().optional().describe('Key size in bits'),
    },
    async ({ mount_path, name, ttl, max_ttl, allow_localhost, allowed_domains, allow_bare_domains, allow_subdomains, allow_glob_domains, allow_any_name, enforce_hostnames, allow_ip_sans, server_flag, client_flag, key_type, key_bits }) => {
      try {
        await client.pkiCreateRole(mount_path, name, {
          ttl: ttl ? parseInt(ttl) : undefined,
          max_ttl: max_ttl ? parseInt(max_ttl) : undefined,
          allow_localhost,
          allowed_domains,
          allow_bare_domains,
          allow_subdomains,
          allow_glob_domains,
          allow_any_name,
          enforce_hostnames,
          allow_ip_sans,
          server_flag,
          client_flag,
          key_type,
          key_bits,
        } as any);
        return {
          content: [{ type: 'text', text: JSON.stringify({ success: true, message: `PKI role '${name}' created/updated` }, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_pki_delete_role',
    'Delete a PKI role.',
    {
      mount_path: z.string().default('pki').describe('Mount path of the PKI engine'),
      name: z.string().describe('Role name to delete'),
    },
    async ({ mount_path, name }) => {
      try {
        await client.pkiDeleteRole(mount_path, name);
        return {
          content: [{ type: 'text', text: JSON.stringify({ success: true, message: `PKI role '${name}' deleted` }, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // URLs Configuration
  // ===========================================================================

  server.tool(
    'vault_pki_read_urls_config',
    'Read the URLs configuration for the PKI engine.',
    {
      mount_path: z.string().default('pki').describe('Mount path of the PKI engine'),
    },
    async ({ mount_path }) => {
      try {
        const config = await client.pkiReadUrlsConfig(mount_path);
        return {
          content: [{ type: 'text', text: JSON.stringify(config, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_pki_write_urls_config',
    'Configure URLs for the PKI engine.',
    {
      mount_path: z.string().default('pki').describe('Mount path of the PKI engine'),
      issuing_certificates: z.array(z.string()).optional().describe('URLs for issuing certificates'),
      crl_distribution_points: z.array(z.string()).optional().describe('CRL distribution point URLs'),
      ocsp_servers: z.array(z.string()).optional().describe('OCSP server URLs'),
    },
    async ({ mount_path, issuing_certificates, crl_distribution_points, ocsp_servers }) => {
      try {
        await client.pkiWriteUrlsConfig(mount_path, {
          issuing_certificates,
          crl_distribution_points,
          ocsp_servers,
        });
        return {
          content: [{ type: 'text', text: JSON.stringify({ success: true, message: 'PKI URLs configured' }, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // CRL & Tidy
  // ===========================================================================

  server.tool(
    'vault_pki_rotate_crl',
    'Rotate the Certificate Revocation List.',
    {
      mount_path: z.string().default('pki').describe('Mount path of the PKI engine'),
    },
    async ({ mount_path }) => {
      try {
        const result = await client.pkiRotateCrl(mount_path);
        return {
          content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_pki_tidy',
    'Tidy up the PKI backend by removing expired certificates.',
    {
      mount_path: z.string().default('pki').describe('Mount path of the PKI engine'),
      tidy_cert_store: z.boolean().optional().describe('Tidy the certificate store'),
      tidy_revoked_certs: z.boolean().optional().describe('Tidy revoked certificates'),
      tidy_revoked_cert_issuer_associations: z.boolean().optional().describe('Tidy revoked cert issuer associations'),
      safety_buffer: z.string().optional().describe('Safety buffer duration (e.g., "72h")'),
    },
    async ({ mount_path, tidy_cert_store, tidy_revoked_certs, tidy_revoked_cert_issuer_associations, safety_buffer }) => {
      try {
        await client.pkiTidy(mount_path, {
          tidy_cert_store,
          tidy_revoked_certs,
          tidy_revoked_cert_issuer_associations,
          safety_buffer,
        });
        return {
          content: [{ type: 'text', text: JSON.stringify({ success: true, message: 'PKI tidy operation started' }, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );
}
