# HashiCorp Vault MCP Server

[![Primrose MCP](https://img.shields.io/badge/Primrose-MCP-blue)](https://primrose.dev/mcp/vault)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A Model Context Protocol (MCP) server for HashiCorp Vault, enabling AI assistants to securely manage secrets, encryption, PKI, and authentication across multiple secrets engines.

## Features

### System and Core
- **System** - Health checks, seal status, and system information
- **Tokens** - Create, renew, and revoke authentication tokens
- **Leases** - Manage secret leases and TTLs
- **Wrapping** - Response wrapping for secure secret distribution

### Secrets Engines
- **KV** - Key-value secrets storage (v1 and v2)
- **Transit** - Encryption as a service
- **PKI** - Public key infrastructure and certificate management
- **Database** - Dynamic database credentials
- **SSH** - SSH key signing and OTP
- **TOTP** - Time-based one-time passwords
- **Cubbyhole** - Private token-scoped secrets
- **AWS** - Dynamic AWS credentials
- **Identity** - Identity management and entities
- **RabbitMQ** - Dynamic RabbitMQ credentials
- **Consul** - Dynamic Consul tokens

### Auth Methods
- **AppRole** - Machine authentication
- **Userpass** - Username/password authentication
- **JWT** - JWT/OIDC authentication
- **GitHub** - GitHub-based authentication
- **LDAP** - LDAP/Active Directory authentication
- **Kubernetes** - Kubernetes service account authentication
- **Cert** - TLS certificate authentication

## Quick Start

### Recommended: Use Primrose SDK

The easiest way to use this MCP server is with the Primrose SDK:

```bash
npm install primrose-mcp
```

```typescript
import { PrimroseMCP } from 'primrose-mcp';

const primrose = new PrimroseMCP({
  apiKey: process.env.PRIMROSE_API_KEY,
});

const vaultClient = primrose.getClient('vault', {
  address: process.env.VAULT_ADDR,
  token: process.env.VAULT_TOKEN,
});
```

## Manual Installation

### Prerequisites

- Node.js 18+
- Wrangler CLI (`npm install -g wrangler`)
- HashiCorp Vault server with API access

### Setup

1. Clone and install dependencies:

```bash
git clone <repository-url>
cd primrose-mcp-vault
npm install
```

2. Deploy to Cloudflare Workers:

```bash
npx wrangler deploy
```

## Configuration

### Required Headers

| Header | Description |
|--------|-------------|
| `X-Vault-Token` | Vault authentication token |
| `X-Vault-Address` | Vault server address (e.g., https://vault.example.com) |

### Optional Headers

| Header | Description |
|--------|-------------|
| `X-Vault-Namespace` | Vault namespace (Enterprise feature) |

### Example Request

```bash
curl -X POST https://your-worker.workers.dev/mcp \
  -H "Content-Type: application/json" \
  -H "X-Vault-Token: your-vault-token" \
  -H "X-Vault-Address: https://vault.example.com" \
  -d '{"jsonrpc":"2.0","method":"tools/list","id":1}'
```

## Available Tools

### System Tools
- `vault_health` - Check Vault health status
- `vault_seal_status` - Get seal status
- `vault_list_mounts` - List mounted secrets engines
- `vault_list_auth_methods` - List enabled auth methods

### Token Tools
- `vault_create_token` - Create a new token
- `vault_lookup_token` - Look up token information
- `vault_renew_token` - Renew a token
- `vault_revoke_token` - Revoke a token

### Lease Tools
- `vault_list_leases` - List leases
- `vault_renew_lease` - Renew a lease
- `vault_revoke_lease` - Revoke a lease

### KV Tools
- `vault_kv_read` - Read a secret
- `vault_kv_write` - Write a secret
- `vault_kv_delete` - Delete a secret
- `vault_kv_list` - List secrets

### Transit Tools
- `vault_transit_encrypt` - Encrypt data
- `vault_transit_decrypt` - Decrypt data
- `vault_transit_create_key` - Create encryption key
- `vault_transit_rotate_key` - Rotate encryption key

### PKI Tools
- `vault_pki_generate_root` - Generate root CA
- `vault_pki_issue_certificate` - Issue a certificate
- `vault_pki_revoke_certificate` - Revoke a certificate
- `vault_pki_list_certificates` - List certificates

### Database Tools
- `vault_db_generate_credentials` - Generate database credentials
- `vault_db_configure_connection` - Configure database connection
- `vault_db_create_role` - Create a database role

### Auth Method Tools
- `vault_approle_login` - Login with AppRole
- `vault_userpass_login` - Login with username/password
- `vault_jwt_login` - Login with JWT
- `vault_github_login` - Login with GitHub
- `vault_ldap_login` - Login with LDAP
- `vault_kubernetes_login` - Login with Kubernetes

## Development

```bash
# Install dependencies
npm install

# Run locally
npm run dev

# Type check
npm run typecheck

# Deploy
npm run deploy
```

## Related Resources

- [Primrose SDK Documentation](https://primrose.dev/docs)
- [HashiCorp Vault Documentation](https://developer.hashicorp.com/vault/docs)
- [Vault API Reference](https://developer.hashicorp.com/vault/api-docs)
- [Model Context Protocol](https://modelcontextprotocol.io)
