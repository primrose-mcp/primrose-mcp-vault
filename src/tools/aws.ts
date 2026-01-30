/**
 * AWS Secrets Engine Tools
 *
 * MCP tools for AWS secrets engine operations including dynamic IAM
 * credentials, STS credentials, and static role management.
 */

import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import type { VaultClient } from '../client.js';
import { formatError } from '../utils/formatters.js';

export function registerAwsTools(server: McpServer, client: VaultClient): void {
  // ===========================================================================
  // Configuration
  // ===========================================================================

  server.tool(
    'vault_aws_read_root_config',
    'Read the AWS root configuration (credentials are not returned).',
    {
      mount_path: z.string().default('aws').describe('Mount path of the AWS engine'),
    },
    async ({ mount_path }) => {
      try {
        const config = await client.awsReadRootConfig(mount_path);
        return {
          content: [{ type: 'text', text: JSON.stringify(config, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_aws_write_root_config',
    'Configure the root credentials for AWS.',
    {
      mount_path: z.string().default('aws').describe('Mount path of the AWS engine'),
      access_key: z.string().optional().describe('AWS access key ID'),
      secret_key: z.string().optional().describe('AWS secret access key'),
      region: z.string().optional().describe('AWS region'),
      iam_endpoint: z.string().optional().describe('Custom IAM endpoint'),
      sts_endpoint: z.string().optional().describe('Custom STS endpoint'),
      max_retries: z.number().int().optional().describe('Max retries for API calls'),
    },
    async ({ mount_path, access_key, secret_key, region, iam_endpoint, sts_endpoint, max_retries }) => {
      try {
        await client.awsWriteRootConfig(mount_path, {
          access_key,
          secret_key,
          region,
          iam_endpoint,
          sts_endpoint,
          max_retries,
        });
        return {
          content: [{ type: 'text', text: JSON.stringify({ success: true, message: 'AWS root configuration updated' }, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_aws_rotate_root',
    'Rotate the root credentials for AWS.',
    {
      mount_path: z.string().default('aws').describe('Mount path of the AWS engine'),
    },
    async ({ mount_path }) => {
      try {
        await client.awsRotateRoot(mount_path);
        return {
          content: [{ type: 'text', text: JSON.stringify({ success: true, message: 'AWS root credentials rotated' }, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_aws_read_lease_config',
    'Read the lease configuration for AWS credentials.',
    {
      mount_path: z.string().default('aws').describe('Mount path of the AWS engine'),
    },
    async ({ mount_path }) => {
      try {
        const config = await client.awsReadLeaseConfig(mount_path);
        return {
          content: [{ type: 'text', text: JSON.stringify(config, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_aws_write_lease_config',
    'Configure the lease settings for AWS credentials.',
    {
      mount_path: z.string().default('aws').describe('Mount path of the AWS engine'),
      lease: z.string().describe('Default lease duration (e.g., "1h")'),
      lease_max: z.string().describe('Maximum lease duration'),
    },
    async ({ mount_path, lease, lease_max }) => {
      try {
        await client.awsWriteLeaseConfig(mount_path, { lease, lease_max });
        return {
          content: [{ type: 'text', text: JSON.stringify({ success: true, message: 'AWS lease configuration updated' }, null, 2) }],
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
    'vault_aws_list_roles',
    'List all AWS roles.',
    {
      mount_path: z.string().default('aws').describe('Mount path of the AWS engine'),
    },
    async ({ mount_path }) => {
      try {
        const roles = await client.awsListRoles(mount_path);
        return {
          content: [{ type: 'text', text: JSON.stringify({ roles, count: roles.length }, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_aws_read_role',
    'Read an AWS role configuration.',
    {
      mount_path: z.string().default('aws').describe('Mount path of the AWS engine'),
      name: z.string().describe('Role name'),
    },
    async ({ mount_path, name }) => {
      try {
        const role = await client.awsReadRole(mount_path, name);
        return {
          content: [{ type: 'text', text: JSON.stringify(role, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_aws_create_role',
    'Create or update an AWS role.',
    {
      mount_path: z.string().default('aws').describe('Mount path of the AWS engine'),
      name: z.string().describe('Role name'),
      credential_type: z.enum(['iam_user', 'assumed_role', 'federation_token', 'session_token']).describe('Credential type'),
      role_arns: z.array(z.string()).optional().describe('ARNs of AWS roles to assume'),
      policy_arns: z.array(z.string()).optional().describe('ARNs of AWS managed policies'),
      policy_document: z.string().optional().describe('Inline IAM policy document (JSON)'),
      iam_groups: z.array(z.string()).optional().describe('IAM groups for iam_user type'),
      default_sts_ttl: z.string().optional().describe('Default STS credential TTL'),
      max_sts_ttl: z.string().optional().describe('Maximum STS credential TTL'),
      user_path: z.string().optional().describe('IAM user path for iam_user type'),
      permissions_boundary_arn: z.string().optional().describe('Permissions boundary ARN'),
    },
    async ({ mount_path, name, credential_type, role_arns, policy_arns, policy_document, iam_groups, default_sts_ttl, max_sts_ttl, user_path, permissions_boundary_arn }) => {
      try {
        await client.awsCreateRole(mount_path, name, {
          credential_type,
          role_arns,
          policy_arns,
          policy_document,
          iam_groups,
          default_sts_ttl,
          max_sts_ttl,
          user_path,
          permissions_boundary_arn,
        });
        return {
          content: [{ type: 'text', text: JSON.stringify({ success: true, message: `AWS role '${name}' created/updated` }, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_aws_delete_role',
    'Delete an AWS role.',
    {
      mount_path: z.string().default('aws').describe('Mount path of the AWS engine'),
      name: z.string().describe('Role name to delete'),
    },
    async ({ mount_path, name }) => {
      try {
        await client.awsDeleteRole(mount_path, name);
        return {
          content: [{ type: 'text', text: JSON.stringify({ success: true, message: `AWS role '${name}' deleted` }, null, 2) }],
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
    'vault_aws_generate_credentials',
    'Generate AWS credentials for a role.',
    {
      mount_path: z.string().default('aws').describe('Mount path of the AWS engine'),
      role_name: z.string().describe('Role name'),
      ttl: z.string().optional().describe('Credential TTL'),
    },
    async ({ mount_path, role_name, ttl }) => {
      try {
        const creds = await client.awsGenerateCredentials(mount_path, role_name, ttl);
        return {
          content: [{ type: 'text', text: JSON.stringify(creds, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_aws_generate_sts_credentials',
    'Generate AWS STS credentials for a role.',
    {
      mount_path: z.string().default('aws').describe('Mount path of the AWS engine'),
      role_name: z.string().describe('Role name'),
      ttl: z.string().optional().describe('Credential TTL'),
      role_arn: z.string().optional().describe('Specific role ARN to assume'),
    },
    async ({ mount_path, role_name, ttl, role_arn }) => {
      try {
        const creds = await client.awsGenerateStsCredentials(mount_path, role_name, ttl, role_arn);
        return {
          content: [{ type: 'text', text: JSON.stringify(creds, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Static Roles
  // ===========================================================================

  server.tool(
    'vault_aws_list_static_roles',
    'List all AWS static roles.',
    {
      mount_path: z.string().default('aws').describe('Mount path of the AWS engine'),
    },
    async ({ mount_path }) => {
      try {
        const roles = await client.awsListStaticRoles(mount_path);
        return {
          content: [{ type: 'text', text: JSON.stringify({ roles, count: roles.length }, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_aws_read_static_role',
    'Read an AWS static role configuration.',
    {
      mount_path: z.string().default('aws').describe('Mount path of the AWS engine'),
      name: z.string().describe('Static role name'),
    },
    async ({ mount_path, name }) => {
      try {
        const role = await client.awsReadStaticRole(mount_path, name);
        return {
          content: [{ type: 'text', text: JSON.stringify(role, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_aws_create_static_role',
    'Create or update an AWS static role.',
    {
      mount_path: z.string().default('aws').describe('Mount path of the AWS engine'),
      name: z.string().describe('Static role name'),
      username: z.string().describe('AWS IAM username to manage'),
      rotation_period: z.string().describe('Rotation period (e.g., "24h")'),
    },
    async ({ mount_path, name, username, rotation_period }) => {
      try {
        await client.awsCreateStaticRole(mount_path, name, { username, rotation_period });
        return {
          content: [{ type: 'text', text: JSON.stringify({ success: true, message: `AWS static role '${name}' created/updated` }, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_aws_delete_static_role',
    'Delete an AWS static role.',
    {
      mount_path: z.string().default('aws').describe('Mount path of the AWS engine'),
      name: z.string().describe('Static role name to delete'),
    },
    async ({ mount_path, name }) => {
      try {
        await client.awsDeleteStaticRole(mount_path, name);
        return {
          content: [{ type: 'text', text: JSON.stringify({ success: true, message: `AWS static role '${name}' deleted` }, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_aws_get_static_credentials',
    'Get current credentials for an AWS static role.',
    {
      mount_path: z.string().default('aws').describe('Mount path of the AWS engine'),
      name: z.string().describe('Static role name'),
    },
    async ({ mount_path, name }) => {
      try {
        const creds = await client.awsGetStaticCredentials(mount_path, name);
        return {
          content: [{ type: 'text', text: JSON.stringify(creds, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );
}
