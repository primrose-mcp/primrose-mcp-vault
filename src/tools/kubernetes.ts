/**
 * Kubernetes Auth Method Tools
 *
 * MCP tools for Kubernetes authentication including configuration,
 * role management, and login operations.
 */

import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import type { VaultClient } from '../client.js';
import { formatError } from '../utils/formatters.js';

export function registerKubernetesTools(server: McpServer, client: VaultClient): void {
  // ===========================================================================
  // Configuration
  // ===========================================================================

  server.tool(
    'vault_kubernetes_read_config',
    'Read the Kubernetes auth method configuration.',
    {
      mount_path: z.string().default('kubernetes').describe('Mount path of the Kubernetes auth method'),
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
    'vault_kubernetes_write_config',
    'Configure the Kubernetes auth method.',
    {
      mount_path: z.string().default('kubernetes').describe('Mount path of the Kubernetes auth method'),
      kubernetes_host: z.string().describe('Kubernetes API server URL'),
      kubernetes_ca_cert: z.string().optional().describe('Kubernetes CA certificate (PEM)'),
      token_reviewer_jwt: z.string().optional().describe('JWT for token review API'),
      pem_keys: z.array(z.string()).optional().describe('PEM keys for JWT verification'),
      issuer: z.string().optional().describe('JWT issuer'),
      disable_iss_validation: z.boolean().optional().describe('Disable issuer validation'),
      disable_local_ca_jwt: z.boolean().optional().describe('Disable local CA JWT'),
    },
    async ({ mount_path, kubernetes_host, kubernetes_ca_cert, token_reviewer_jwt, pem_keys, issuer, disable_iss_validation, disable_local_ca_jwt }) => {
      try {
        await (client as any).request(`/auth/${mount_path}/config`, {
          method: 'POST',
          body: JSON.stringify({
            kubernetes_host, kubernetes_ca_cert, token_reviewer_jwt,
            pem_keys, issuer, disable_iss_validation, disable_local_ca_jwt,
          }),
        });
        return {
          content: [{ type: 'text', text: JSON.stringify({ success: true, message: 'Kubernetes configuration updated' }, null, 2) }],
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
    'vault_kubernetes_list_roles',
    'List all Kubernetes auth roles.',
    {
      mount_path: z.string().default('kubernetes').describe('Mount path of the Kubernetes auth method'),
    },
    async ({ mount_path }) => {
      try {
        const response = await (client as any).list(`/auth/${mount_path}/role`);
        const roles = response.data?.keys || [];
        return {
          content: [{ type: 'text', text: JSON.stringify({ roles, count: roles.length }, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_kubernetes_read_role',
    'Read a Kubernetes auth role.',
    {
      mount_path: z.string().default('kubernetes').describe('Mount path of the Kubernetes auth method'),
      name: z.string().describe('Role name'),
    },
    async ({ mount_path, name }) => {
      try {
        const response = await (client as any).request(`/auth/${mount_path}/role/${name}`);
        return {
          content: [{ type: 'text', text: JSON.stringify(response.data || response, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_kubernetes_create_role',
    'Create or update a Kubernetes auth role.',
    {
      mount_path: z.string().default('kubernetes').describe('Mount path of the Kubernetes auth method'),
      name: z.string().describe('Role name'),
      bound_service_account_names: z.array(z.string()).describe('Allowed service account names ("*" for any)'),
      bound_service_account_namespaces: z.array(z.string()).describe('Allowed namespaces ("*" for any)'),
      audience: z.string().optional().describe('Expected JWT audience'),
      alias_name_source: z.enum(['serviceaccount_uid', 'serviceaccount_name']).optional().describe('Source for entity alias'),
      token_ttl: z.string().optional().describe('Token TTL'),
      token_max_ttl: z.string().optional().describe('Maximum token TTL'),
      token_policies: z.array(z.string()).optional().describe('Policies to attach'),
      token_bound_cidrs: z.array(z.string()).optional().describe('CIDRs that can use the token'),
      token_num_uses: z.number().int().optional().describe('Number of times token can be used'),
      token_period: z.string().optional().describe('Token period'),
      token_type: z.string().optional().describe('Token type'),
    },
    async ({ mount_path, name, bound_service_account_names, bound_service_account_namespaces, audience, alias_name_source, token_ttl, token_max_ttl, token_policies, token_bound_cidrs, token_num_uses, token_period, token_type }) => {
      try {
        await (client as any).request(`/auth/${mount_path}/role/${name}`, {
          method: 'POST',
          body: JSON.stringify({
            bound_service_account_names, bound_service_account_namespaces,
            audience, alias_name_source, token_ttl, token_max_ttl,
            token_policies, token_bound_cidrs, token_num_uses,
            token_period, token_type,
          }),
        });
        return {
          content: [{ type: 'text', text: JSON.stringify({ success: true, message: `Kubernetes role '${name}' created/updated` }, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_kubernetes_delete_role',
    'Delete a Kubernetes auth role.',
    {
      mount_path: z.string().default('kubernetes').describe('Mount path of the Kubernetes auth method'),
      name: z.string().describe('Role name'),
    },
    async ({ mount_path, name }) => {
      try {
        await (client as any).request(`/auth/${mount_path}/role/${name}`, { method: 'DELETE' });
        return {
          content: [{ type: 'text', text: JSON.stringify({ success: true, message: `Kubernetes role '${name}' deleted` }, null, 2) }],
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
    'vault_kubernetes_login',
    'Login using a Kubernetes service account JWT.',
    {
      mount_path: z.string().default('kubernetes').describe('Mount path of the Kubernetes auth method'),
      role: z.string().describe('Role to authenticate against'),
      jwt: z.string().describe('Kubernetes service account JWT'),
    },
    async ({ mount_path, role, jwt }) => {
      try {
        const response = await (client as any).request(`/auth/${mount_path}/login`, {
          method: 'POST',
          body: JSON.stringify({ role, jwt }),
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
