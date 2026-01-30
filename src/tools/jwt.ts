/**
 * JWT/OIDC Auth Method Tools
 *
 * MCP tools for JWT and OIDC authentication including configuration,
 * role management, and login operations.
 */

import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import type { VaultClient } from '../client.js';
import { formatError } from '../utils/formatters.js';

export function registerJwtTools(server: McpServer, client: VaultClient): void {
  // ===========================================================================
  // Configuration
  // ===========================================================================

  server.tool(
    'vault_jwt_read_config',
    'Read the JWT/OIDC auth method configuration.',
    {
      mount_path: z.string().default('jwt').describe('Mount path of the JWT auth method'),
    },
    async ({ mount_path }) => {
      try {
        const config = await client.jwtReadConfig(mount_path);
        return {
          content: [{ type: 'text', text: JSON.stringify(config, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_jwt_write_config',
    'Configure the JWT/OIDC auth method.',
    {
      mount_path: z.string().default('jwt').describe('Mount path of the JWT auth method'),
      oidc_discovery_url: z.string().optional().describe('OIDC discovery URL'),
      oidc_discovery_ca_pem: z.string().optional().describe('CA certificate for OIDC discovery'),
      oidc_client_id: z.string().optional().describe('OIDC client ID'),
      oidc_client_secret: z.string().optional().describe('OIDC client secret'),
      oidc_response_mode: z.string().optional().describe('OIDC response mode'),
      oidc_response_types: z.array(z.string()).optional().describe('OIDC response types'),
      jwks_url: z.string().optional().describe('JWKS URL for JWT validation'),
      jwks_ca_pem: z.string().optional().describe('CA certificate for JWKS'),
      jwt_validation_pubkeys: z.array(z.string()).optional().describe('Public keys for JWT validation'),
      jwt_supported_algs: z.array(z.string()).optional().describe('Supported JWT algorithms'),
      bound_issuer: z.string().optional().describe('Required JWT issuer'),
      default_role: z.string().optional().describe('Default role for login'),
      namespace_in_state: z.boolean().optional().describe('Include namespace in OIDC state'),
    },
    async ({ mount_path, oidc_discovery_url, oidc_discovery_ca_pem, oidc_client_id, oidc_client_secret, oidc_response_mode, oidc_response_types, jwks_url, jwks_ca_pem, jwt_validation_pubkeys, jwt_supported_algs, bound_issuer, default_role, namespace_in_state }) => {
      try {
        await client.jwtWriteConfig(mount_path, {
          oidc_discovery_url,
          oidc_discovery_ca_pem,
          oidc_client_id,
          oidc_client_secret,
          oidc_response_mode,
          oidc_response_types,
          jwks_url,
          jwks_ca_pem,
          jwt_validation_pubkeys,
          jwt_supported_algs,
          bound_issuer,
          default_role,
          namespace_in_state,
        });
        return {
          content: [{ type: 'text', text: JSON.stringify({ success: true, message: 'JWT/OIDC configuration updated' }, null, 2) }],
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
    'vault_jwt_list_roles',
    'List all JWT/OIDC roles.',
    {
      mount_path: z.string().default('jwt').describe('Mount path of the JWT auth method'),
    },
    async ({ mount_path }) => {
      try {
        const roles = await client.jwtListRoles(mount_path);
        return {
          content: [{ type: 'text', text: JSON.stringify({ roles, count: roles.length }, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_jwt_read_role',
    'Read a JWT/OIDC role configuration.',
    {
      mount_path: z.string().default('jwt').describe('Mount path of the JWT auth method'),
      name: z.string().describe('Role name'),
    },
    async ({ mount_path, name }) => {
      try {
        const role = await client.jwtReadRole(mount_path, name);
        return {
          content: [{ type: 'text', text: JSON.stringify(role, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_jwt_create_role',
    'Create or update a JWT/OIDC role.',
    {
      mount_path: z.string().default('jwt').describe('Mount path of the JWT auth method'),
      name: z.string().describe('Role name'),
      role_type: z.enum(['jwt', 'oidc']).optional().describe('Role type'),
      bound_audiences: z.array(z.string()).optional().describe('Required JWT audiences'),
      user_claim: z.string().describe('Claim to use as user identity'),
      user_claim_json_pointer: z.boolean().optional().describe('User claim is a JSON pointer'),
      bound_subject: z.string().optional().describe('Required JWT subject'),
      bound_claims: z.record(z.string(), z.string()).optional().describe('Required claim values'),
      bound_claims_type: z.enum(['string', 'glob']).optional().describe('How to match bound claims'),
      groups_claim: z.string().optional().describe('Claim containing group membership'),
      claim_mappings: z.record(z.string(), z.string()).optional().describe('Claim to metadata mappings'),
      oidc_scopes: z.array(z.string()).optional().describe('OIDC scopes to request'),
      allowed_redirect_uris: z.array(z.string()).optional().describe('Allowed OIDC redirect URIs'),
      token_ttl: z.string().optional().describe('Token TTL'),
      token_max_ttl: z.string().optional().describe('Maximum token TTL'),
      token_policies: z.array(z.string()).optional().describe('Policies to attach'),
      token_bound_cidrs: z.array(z.string()).optional().describe('CIDRs that can use the token'),
      token_no_default_policy: z.boolean().optional().describe('Do not attach default policy'),
      token_num_uses: z.number().int().optional().describe('Number of times token can be used'),
      token_period: z.string().optional().describe('Token period for periodic tokens'),
      token_type: z.string().optional().describe('Token type'),
    },
    async ({ mount_path, name, role_type, bound_audiences, user_claim, user_claim_json_pointer, bound_subject, bound_claims, bound_claims_type, groups_claim, claim_mappings, oidc_scopes, allowed_redirect_uris, token_ttl, token_max_ttl, token_policies, token_bound_cidrs, token_no_default_policy, token_num_uses, token_period, token_type }) => {
      try {
        await client.jwtCreateRole(mount_path, name, {
          role_type,
          bound_audiences,
          user_claim,
          user_claim_json_pointer,
          bound_subject,
          bound_claims,
          bound_claims_type,
          groups_claim,
          claim_mappings,
          oidc_scopes,
          allowed_redirect_uris,
          token_ttl,
          token_max_ttl,
          token_policies,
          token_bound_cidrs,
          token_no_default_policy,
          token_num_uses,
          token_period,
          token_type,
        });
        return {
          content: [{ type: 'text', text: JSON.stringify({ success: true, message: `JWT role '${name}' created/updated` }, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_jwt_delete_role',
    'Delete a JWT/OIDC role.',
    {
      mount_path: z.string().default('jwt').describe('Mount path of the JWT auth method'),
      name: z.string().describe('Role name to delete'),
    },
    async ({ mount_path, name }) => {
      try {
        await client.jwtDeleteRole(mount_path, name);
        return {
          content: [{ type: 'text', text: JSON.stringify({ success: true, message: `JWT role '${name}' deleted` }, null, 2) }],
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
    'vault_jwt_login',
    'Login using a JWT to obtain a Vault token.',
    {
      mount_path: z.string().default('jwt').describe('Mount path of the JWT auth method'),
      role: z.string().describe('Role to authenticate against'),
      jwt: z.string().describe('Signed JWT'),
    },
    async ({ mount_path, role, jwt }) => {
      try {
        const auth = await client.jwtLogin(mount_path, role, jwt);
        return {
          content: [{ type: 'text', text: JSON.stringify(auth, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_oidc_get_auth_url',
    'Get the OIDC authorization URL for browser-based login.',
    {
      mount_path: z.string().default('oidc').describe('Mount path of the OIDC auth method'),
      role: z.string().describe('Role to authenticate against'),
      redirect_uri: z.string().describe('Redirect URI after authentication'),
    },
    async ({ mount_path, role, redirect_uri }) => {
      try {
        const result = await client.oidcGetAuthUrl(mount_path, role, redirect_uri);
        return {
          content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );
}
