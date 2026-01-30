/**
 * Identity Secrets Engine Tools
 *
 * MCP tools for Identity management including entities, entity aliases,
 * groups, and group aliases.
 */

import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import type { VaultClient } from '../client.js';
import { formatError } from '../utils/formatters.js';

export function registerIdentityTools(server: McpServer, client: VaultClient): void {
  // ===========================================================================
  // Entity Management
  // ===========================================================================

  server.tool(
    'vault_identity_list_entities',
    'List all identity entities by ID.',
    {},
    async () => {
      try {
        const entities = await client.identityListEntities();
        return {
          content: [{ type: 'text', text: JSON.stringify({ entities, count: entities.length }, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_identity_list_entities_by_name',
    'List all identity entities by name.',
    {},
    async () => {
      try {
        const entities = await client.identityListEntitiesByName();
        return {
          content: [{ type: 'text', text: JSON.stringify({ entities, count: entities.length }, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_identity_create_entity',
    'Create a new identity entity.',
    {
      name: z.string().optional().describe('Entity name'),
      metadata: z.record(z.string(), z.string()).optional().describe('Entity metadata'),
      policies: z.array(z.string()).optional().describe('Policies to attach'),
      disabled: z.boolean().optional().describe('Whether entity is disabled'),
    },
    async ({ name, metadata, policies, disabled }) => {
      try {
        const entity = await client.identityCreateEntity({ name, metadata, policies, disabled });
        return {
          content: [{ type: 'text', text: JSON.stringify(entity, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_identity_read_entity',
    'Read an identity entity by ID.',
    {
      id: z.string().describe('Entity ID'),
    },
    async ({ id }) => {
      try {
        const entity = await client.identityReadEntity(id);
        return {
          content: [{ type: 'text', text: JSON.stringify(entity, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_identity_read_entity_by_name',
    'Read an identity entity by name.',
    {
      name: z.string().describe('Entity name'),
    },
    async ({ name }) => {
      try {
        const entity = await client.identityReadEntityByName(name);
        return {
          content: [{ type: 'text', text: JSON.stringify(entity, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_identity_update_entity',
    'Update an identity entity.',
    {
      id: z.string().describe('Entity ID'),
      name: z.string().optional().describe('New entity name'),
      metadata: z.record(z.string(), z.string()).optional().describe('Entity metadata'),
      policies: z.array(z.string()).optional().describe('Policies to attach'),
      disabled: z.boolean().optional().describe('Whether entity is disabled'),
    },
    async ({ id, name, metadata, policies, disabled }) => {
      try {
        await client.identityUpdateEntity(id, { name, metadata, policies, disabled });
        return {
          content: [{ type: 'text', text: JSON.stringify({ success: true, message: `Entity '${id}' updated` }, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_identity_delete_entity',
    'Delete an identity entity and all its aliases.',
    {
      id: z.string().describe('Entity ID'),
    },
    async ({ id }) => {
      try {
        await client.identityDeleteEntity(id);
        return {
          content: [{ type: 'text', text: JSON.stringify({ success: true, message: `Entity '${id}' deleted` }, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_identity_merge_entities',
    'Merge multiple entities into one.',
    {
      from_entity_ids: z.array(z.string()).describe('Entity IDs to merge from'),
      to_entity_id: z.string().describe('Entity ID to merge into'),
      force: z.boolean().optional().describe('Force merge even with conflicts'),
      conflicting_alias_ids_to_keep: z.array(z.string()).optional().describe('Alias IDs to keep on conflict'),
    },
    async ({ from_entity_ids, to_entity_id, force, conflicting_alias_ids_to_keep }) => {
      try {
        await client.identityMergeEntities({
          from_entity_ids,
          to_entity_id,
          force,
          conflicting_alias_ids_to_keep,
        });
        return {
          content: [{ type: 'text', text: JSON.stringify({ success: true, message: 'Entities merged' }, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Entity Alias Management
  // ===========================================================================

  server.tool(
    'vault_identity_list_entity_aliases',
    'List all entity aliases.',
    {},
    async () => {
      try {
        const aliases = await client.identityListEntityAliases();
        return {
          content: [{ type: 'text', text: JSON.stringify({ aliases, count: aliases.length }, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_identity_create_entity_alias',
    'Create an entity alias.',
    {
      name: z.string().describe('Alias name (usually username from auth method)'),
      canonical_id: z.string().describe('Entity ID to link to'),
      mount_accessor: z.string().describe('Auth method mount accessor'),
      metadata: z.record(z.string(), z.string()).optional().describe('Alias metadata'),
    },
    async ({ name, canonical_id, mount_accessor, metadata }) => {
      try {
        const alias = await client.identityCreateEntityAlias({
          name,
          canonical_id,
          mount_accessor,
          metadata,
        });
        return {
          content: [{ type: 'text', text: JSON.stringify(alias, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_identity_read_entity_alias',
    'Read an entity alias.',
    {
      id: z.string().describe('Alias ID'),
    },
    async ({ id }) => {
      try {
        const alias = await client.identityReadEntityAlias(id);
        return {
          content: [{ type: 'text', text: JSON.stringify(alias, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_identity_update_entity_alias',
    'Update an entity alias.',
    {
      id: z.string().describe('Alias ID'),
      name: z.string().optional().describe('New alias name'),
      canonical_id: z.string().optional().describe('New entity ID'),
      mount_accessor: z.string().optional().describe('New mount accessor'),
      metadata: z.record(z.string(), z.string()).optional().describe('Alias metadata'),
    },
    async ({ id, name, canonical_id, mount_accessor, metadata }) => {
      try {
        await client.identityUpdateEntityAlias(id, { name, canonical_id, mount_accessor, metadata } as any);
        return {
          content: [{ type: 'text', text: JSON.stringify({ success: true, message: `Entity alias '${id}' updated` }, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_identity_delete_entity_alias',
    'Delete an entity alias.',
    {
      id: z.string().describe('Alias ID'),
    },
    async ({ id }) => {
      try {
        await client.identityDeleteEntityAlias(id);
        return {
          content: [{ type: 'text', text: JSON.stringify({ success: true, message: `Entity alias '${id}' deleted` }, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Group Management
  // ===========================================================================

  server.tool(
    'vault_identity_list_groups',
    'List all identity groups by ID.',
    {},
    async () => {
      try {
        const groups = await client.identityListGroups();
        return {
          content: [{ type: 'text', text: JSON.stringify({ groups, count: groups.length }, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_identity_list_groups_by_name',
    'List all identity groups by name.',
    {},
    async () => {
      try {
        const groups = await client.identityListGroupsByName();
        return {
          content: [{ type: 'text', text: JSON.stringify({ groups, count: groups.length }, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_identity_create_group',
    'Create an identity group.',
    {
      name: z.string().optional().describe('Group name'),
      type: z.enum(['internal', 'external']).optional().describe('Group type'),
      policies: z.array(z.string()).optional().describe('Policies to attach'),
      metadata: z.record(z.string(), z.string()).optional().describe('Group metadata'),
      member_entity_ids: z.array(z.string()).optional().describe('Member entity IDs'),
      member_group_ids: z.array(z.string()).optional().describe('Member group IDs (nested groups)'),
    },
    async ({ name, type, policies, metadata, member_entity_ids, member_group_ids }) => {
      try {
        const group = await client.identityCreateGroup({
          name,
          type,
          policies,
          metadata,
          member_entity_ids,
          member_group_ids,
        });
        return {
          content: [{ type: 'text', text: JSON.stringify(group, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_identity_read_group',
    'Read an identity group by ID.',
    {
      id: z.string().describe('Group ID'),
    },
    async ({ id }) => {
      try {
        const group = await client.identityReadGroup(id);
        return {
          content: [{ type: 'text', text: JSON.stringify(group, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_identity_read_group_by_name',
    'Read an identity group by name.',
    {
      name: z.string().describe('Group name'),
    },
    async ({ name }) => {
      try {
        const group = await client.identityReadGroupByName(name);
        return {
          content: [{ type: 'text', text: JSON.stringify(group, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_identity_update_group',
    'Update an identity group.',
    {
      id: z.string().describe('Group ID'),
      name: z.string().optional().describe('New group name'),
      policies: z.array(z.string()).optional().describe('Policies to attach'),
      metadata: z.record(z.string(), z.string()).optional().describe('Group metadata'),
      member_entity_ids: z.array(z.string()).optional().describe('Member entity IDs'),
      member_group_ids: z.array(z.string()).optional().describe('Member group IDs'),
    },
    async ({ id, name, policies, metadata, member_entity_ids, member_group_ids }) => {
      try {
        await client.identityUpdateGroup(id, { name, policies, metadata, member_entity_ids, member_group_ids });
        return {
          content: [{ type: 'text', text: JSON.stringify({ success: true, message: `Group '${id}' updated` }, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_identity_delete_group',
    'Delete an identity group.',
    {
      id: z.string().describe('Group ID'),
    },
    async ({ id }) => {
      try {
        await client.identityDeleteGroup(id);
        return {
          content: [{ type: 'text', text: JSON.stringify({ success: true, message: `Group '${id}' deleted` }, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Group Alias Management
  // ===========================================================================

  server.tool(
    'vault_identity_list_group_aliases',
    'List all group aliases.',
    {},
    async () => {
      try {
        const aliases = await client.identityListGroupAliases();
        return {
          content: [{ type: 'text', text: JSON.stringify({ aliases, count: aliases.length }, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_identity_create_group_alias',
    'Create a group alias (for external groups).',
    {
      name: z.string().describe('Alias name'),
      mount_accessor: z.string().describe('Auth method mount accessor'),
      canonical_id: z.string().describe('Group ID to link to'),
    },
    async ({ name, mount_accessor, canonical_id }) => {
      try {
        const alias = await client.identityCreateGroupAlias({ name, mount_accessor, canonical_id });
        return {
          content: [{ type: 'text', text: JSON.stringify(alias, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_identity_read_group_alias',
    'Read a group alias.',
    {
      id: z.string().describe('Alias ID'),
    },
    async ({ id }) => {
      try {
        const alias = await client.identityReadGroupAlias(id);
        return {
          content: [{ type: 'text', text: JSON.stringify(alias, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_identity_update_group_alias',
    'Update a group alias.',
    {
      id: z.string().describe('Alias ID'),
      name: z.string().optional().describe('New alias name'),
      mount_accessor: z.string().optional().describe('New mount accessor'),
      canonical_id: z.string().optional().describe('New group ID'),
    },
    async ({ id, name, mount_accessor, canonical_id }) => {
      try {
        await client.identityUpdateGroupAlias(id, { name, mount_accessor, canonical_id } as any);
        return {
          content: [{ type: 'text', text: JSON.stringify({ success: true, message: `Group alias '${id}' updated` }, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  server.tool(
    'vault_identity_delete_group_alias',
    'Delete a group alias.',
    {
      id: z.string().describe('Alias ID'),
    },
    async ({ id }) => {
      try {
        await client.identityDeleteGroupAlias(id);
        return {
          content: [{ type: 'text', text: JSON.stringify({ success: true, message: `Group alias '${id}' deleted` }, null, 2) }],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );
}
