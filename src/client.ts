/**
 * HashiCorp Vault API Client
 *
 * This file handles all HTTP communication with the Vault API.
 *
 * MULTI-TENANT: This client receives credentials per-request via TenantCredentials,
 * allowing a single server to serve multiple tenants with different Vault instances.
 */

import type {
  AppRole,
  AppRoleInput,
  AuditDevice,
  AuditDeviceInput,
  AuthInfo,
  AuthMethod,
  AuthMethodInput,
  AwsCredentials,
  AwsLeaseConfig,
  AwsRole,
  AwsRoleInput,
  AwsRootConfig,
  AwsStaticRole,
  AwsStaticRoleInput,
  DatabaseConnection,
  DatabaseConnectionInput,
  DatabaseCredentials,
  DatabaseRole,
  DatabaseRoleInput,
  DatabaseStaticRole,
  DatabaseStaticRoleInput,
  EntityMergeRequest,
  HealthStatus,
  IdentityAlias,
  IdentityAliasInput,
  IdentityEntity,
  IdentityEntityInput,
  IdentityGroup,
  IdentityGroupAliasInput,
  IdentityGroupInput,
  InitRequest,
  InitResponse,
  JwtConfig,
  JwtRole,
  JwtRoleInput,
  KvConfig,
  KvSecret,
  KvSecretMetadata,
  KvV1Secret,
  KvWriteOptions,
  LeaderStatus,
  LeaseInfo,
  Mount,
  MountInput,
  MountTuneInput,
  OidcAuthUrlResponse,
  PkiCertificate,
  PkiIssueRequest,
  PkiIssuer,
  PkiRole,
  PkiRevokeRequest,
  PkiSignRequest,
  PkiUrlsConfig,
  SealStatus,
  SecretId,
  SecretIdInput,
  SshCaConfig,
  SshCredentials,
  SshRole,
  SshRoleInput,
  SshSignedKey,
  SshSignRequest,
  TokenCreateRequest,
  TokenInfo,
  TokenRole,
  TotpCode,
  TotpKey,
  TotpKeyInput,
  TotpValidateResponse,
  TransitDataKeyResponse,
  TransitDecryptResponse,
  TransitEncryptResponse,
  TransitHashResponse,
  TransitHmacResponse,
  TransitKey,
  TransitKeyConfig,
  TransitRandomResponse,
  TransitRewrapResponse,
  TransitSignResponse,
  TransitVerifyResponse,
  UserpassUser,
  UserpassUserInput,
  VaultResponse,
  WrapInfo,
  WrapLookupResponse,
} from './types/entities.js';
import type { TenantCredentials } from './types/env.js';
import { AuthenticationError, VaultApiError, RateLimitError } from './utils/errors.js';

// =============================================================================
// Vault Client Interface
// =============================================================================

export interface VaultClient {
  // Connection
  testConnection(): Promise<{ connected: boolean; message: string }>;

  // System Backend
  getHealth(): Promise<HealthStatus>;
  getSealStatus(): Promise<SealStatus>;
  seal(): Promise<void>;
  unseal(key: string, reset?: boolean): Promise<SealStatus>;
  init(options: InitRequest): Promise<InitResponse>;
  getLeader(): Promise<LeaderStatus>;

  // Mounts (Secrets Engines)
  listMounts(): Promise<Record<string, Mount>>;
  getMount(path: string): Promise<Mount>;
  enableSecretsEngine(path: string, input: MountInput): Promise<void>;
  disableSecretsEngine(path: string): Promise<void>;
  tuneMount(path: string, input: MountTuneInput): Promise<void>;

  // Auth Methods
  listAuthMethods(): Promise<Record<string, AuthMethod>>;
  enableAuthMethod(path: string, input: AuthMethodInput): Promise<void>;
  disableAuthMethod(path: string): Promise<void>;

  // Policies
  listPolicies(): Promise<string[]>;
  getPolicy(name: string): Promise<string>;
  createPolicy(name: string, policy: string): Promise<void>;
  deletePolicy(name: string): Promise<void>;

  // Tokens
  lookupSelf(): Promise<TokenInfo>;
  lookupToken(token: string): Promise<TokenInfo>;
  createToken(options?: TokenCreateRequest): Promise<AuthInfo>;
  renewSelf(increment?: string): Promise<AuthInfo>;
  renewToken(token: string, increment?: string): Promise<AuthInfo>;
  revokeSelf(): Promise<void>;
  revokeToken(token: string): Promise<void>;
  revokeAccessor(accessor: string): Promise<void>;
  listAccessors(): Promise<string[]>;
  listTokenRoles(): Promise<string[]>;
  getTokenRole(name: string): Promise<TokenRole>;
  createTokenRole(name: string, role: Partial<TokenRole>): Promise<void>;
  deleteTokenRole(name: string): Promise<void>;

  // Leases
  lookupLease(leaseId: string): Promise<LeaseInfo>;
  renewLease(leaseId: string, increment?: number): Promise<LeaseInfo>;
  revokeLease(leaseId: string, sync?: boolean): Promise<void>;
  revokeLeasePrefix(prefix: string, sync?: boolean): Promise<void>;

  // Audit Devices
  listAuditDevices(): Promise<Record<string, AuditDevice>>;
  enableAuditDevice(path: string, input: AuditDeviceInput): Promise<void>;
  disableAuditDevice(path: string): Promise<void>;

  // KV v2
  kvRead(mountPath: string, secretPath: string, version?: number): Promise<KvSecret>;
  kvWrite(
    mountPath: string,
    secretPath: string,
    data: Record<string, unknown>,
    options?: KvWriteOptions
  ): Promise<{ version: number }>;
  kvDelete(mountPath: string, secretPath: string): Promise<void>;
  kvDeleteVersions(mountPath: string, secretPath: string, versions: number[]): Promise<void>;
  kvUndelete(mountPath: string, secretPath: string, versions: number[]): Promise<void>;
  kvDestroy(mountPath: string, secretPath: string, versions: number[]): Promise<void>;
  kvList(mountPath: string, path?: string): Promise<string[]>;
  kvReadMetadata(mountPath: string, secretPath: string): Promise<KvSecretMetadata>;
  kvWriteMetadata(
    mountPath: string,
    secretPath: string,
    metadata: Partial<KvSecretMetadata>
  ): Promise<void>;
  kvDeleteMetadata(mountPath: string, secretPath: string): Promise<void>;
  kvReadConfig(mountPath: string): Promise<KvConfig>;
  kvWriteConfig(mountPath: string, config: Partial<KvConfig>): Promise<void>;

  // KV v1
  kvV1Read(mountPath: string, secretPath: string): Promise<KvV1Secret>;
  kvV1Write(mountPath: string, secretPath: string, data: Record<string, unknown>): Promise<void>;
  kvV1Delete(mountPath: string, secretPath: string): Promise<void>;
  kvV1List(mountPath: string, path?: string): Promise<string[]>;

  // Transit
  transitCreateKey(mountPath: string, name: string, config?: TransitKeyConfig): Promise<void>;
  transitReadKey(mountPath: string, name: string): Promise<TransitKey>;
  transitListKeys(mountPath: string): Promise<string[]>;
  transitDeleteKey(mountPath: string, name: string): Promise<void>;
  transitUpdateKeyConfig(
    mountPath: string,
    name: string,
    config: Partial<TransitKeyConfig>
  ): Promise<void>;
  transitRotateKey(mountPath: string, name: string): Promise<void>;
  transitEncrypt(
    mountPath: string,
    keyName: string,
    plaintext: string,
    options?: { context?: string; keyVersion?: number }
  ): Promise<TransitEncryptResponse>;
  transitDecrypt(
    mountPath: string,
    keyName: string,
    ciphertext: string,
    options?: { context?: string }
  ): Promise<TransitDecryptResponse>;
  transitRewrap(
    mountPath: string,
    keyName: string,
    ciphertext: string,
    options?: { context?: string; keyVersion?: number }
  ): Promise<TransitRewrapResponse>;
  transitGenerateDataKey(
    mountPath: string,
    keyName: string,
    type: 'plaintext' | 'wrapped',
    options?: { context?: string; bits?: number }
  ): Promise<TransitDataKeyResponse>;
  transitGenerateRandom(
    mountPath: string,
    bytes?: number,
    format?: string
  ): Promise<TransitRandomResponse>;
  transitHash(
    mountPath: string,
    input: string,
    algorithm?: string,
    format?: string
  ): Promise<TransitHashResponse>;
  transitHmac(
    mountPath: string,
    keyName: string,
    input: string,
    algorithm?: string
  ): Promise<TransitHmacResponse>;
  transitSign(
    mountPath: string,
    keyName: string,
    input: string,
    options?: { hashAlgorithm?: string; signatureAlgorithm?: string }
  ): Promise<TransitSignResponse>;
  transitVerify(
    mountPath: string,
    keyName: string,
    input: string,
    signature: string,
    options?: { hashAlgorithm?: string }
  ): Promise<TransitVerifyResponse>;

  // PKI
  pkiListRoles(mountPath: string): Promise<string[]>;
  pkiReadRole(mountPath: string, name: string): Promise<PkiRole>;
  pkiCreateRole(mountPath: string, name: string, role: Partial<PkiRole>): Promise<void>;
  pkiDeleteRole(mountPath: string, name: string): Promise<void>;
  pkiIssueCertificate(
    mountPath: string,
    roleName: string,
    request: PkiIssueRequest
  ): Promise<PkiCertificate>;
  pkiSignCertificate(
    mountPath: string,
    roleName: string,
    request: PkiSignRequest
  ): Promise<PkiCertificate>;
  pkiRevokeCertificate(mountPath: string, request: PkiRevokeRequest): Promise<void>;
  pkiListCertificates(mountPath: string): Promise<string[]>;
  pkiReadCertificate(mountPath: string, serial: string): Promise<{ certificate: string }>;
  pkiGetCa(mountPath: string): Promise<{ certificate: string }>;
  pkiGetCaChain(mountPath: string): Promise<{ ca_chain: string }>;
  pkiListIssuers(mountPath: string): Promise<string[]>;
  pkiReadIssuer(mountPath: string, issuerId: string): Promise<PkiIssuer>;
  pkiReadUrlsConfig(mountPath: string): Promise<PkiUrlsConfig>;
  pkiWriteUrlsConfig(mountPath: string, config: Partial<PkiUrlsConfig>): Promise<void>;
  pkiRotateCrl(mountPath: string): Promise<{ success: boolean }>;
  pkiTidy(mountPath: string, options?: Record<string, unknown>): Promise<void>;

  // Database
  dbListConnections(mountPath: string): Promise<string[]>;
  dbReadConnection(mountPath: string, name: string): Promise<DatabaseConnection>;
  dbCreateConnection(mountPath: string, name: string, config: DatabaseConnectionInput): Promise<void>;
  dbDeleteConnection(mountPath: string, name: string): Promise<void>;
  dbResetConnection(mountPath: string, name: string): Promise<void>;
  dbRotateRoot(mountPath: string, name: string): Promise<void>;
  dbListRoles(mountPath: string): Promise<string[]>;
  dbReadRole(mountPath: string, name: string): Promise<DatabaseRole>;
  dbCreateRole(mountPath: string, name: string, role: DatabaseRoleInput): Promise<void>;
  dbDeleteRole(mountPath: string, name: string): Promise<void>;
  dbGenerateCredentials(mountPath: string, roleName: string): Promise<DatabaseCredentials>;
  dbListStaticRoles(mountPath: string): Promise<string[]>;
  dbReadStaticRole(mountPath: string, name: string): Promise<DatabaseStaticRole>;
  dbCreateStaticRole(mountPath: string, name: string, role: DatabaseStaticRoleInput): Promise<void>;
  dbDeleteStaticRole(mountPath: string, name: string): Promise<void>;
  dbGetStaticCredentials(mountPath: string, roleName: string): Promise<DatabaseCredentials>;
  dbRotateStaticRole(mountPath: string, roleName: string): Promise<void>;

  // AppRole
  approleListRoles(mountPath: string): Promise<string[]>;
  approleReadRole(mountPath: string, roleName: string): Promise<AppRole>;
  approleCreateRole(mountPath: string, roleName: string, role: AppRoleInput): Promise<void>;
  approleDeleteRole(mountPath: string, roleName: string): Promise<void>;
  approleGetRoleId(mountPath: string, roleName: string): Promise<string>;
  approleSetRoleId(mountPath: string, roleName: string, roleId: string): Promise<void>;
  approleGenerateSecretId(mountPath: string, roleName: string, options?: SecretIdInput): Promise<SecretId>;
  approleListSecretIds(mountPath: string, roleName: string): Promise<string[]>;
  approleLookupSecretId(mountPath: string, roleName: string, secretId: string): Promise<SecretId>;
  approleDestroySecretId(mountPath: string, roleName: string, secretId: string): Promise<void>;
  approleLogin(mountPath: string, roleId: string, secretId: string): Promise<AuthInfo>;

  // Capabilities
  checkCapabilities(paths: string[], token?: string): Promise<Record<string, string[]>>;
  checkCapabilitiesSelf(paths: string[]): Promise<Record<string, string[]>>;

  // SSH Secrets Engine
  sshListRoles(mountPath: string): Promise<string[]>;
  sshReadRole(mountPath: string, name: string): Promise<SshRole>;
  sshCreateRole(mountPath: string, name: string, role: SshRoleInput): Promise<void>;
  sshDeleteRole(mountPath: string, name: string): Promise<void>;
  sshGenerateCredentials(mountPath: string, roleName: string, ip: string, username?: string): Promise<SshCredentials>;
  sshSignKey(mountPath: string, roleName: string, request: SshSignRequest): Promise<SshSignedKey>;
  sshVerifyOtp(mountPath: string, otp: string): Promise<{ valid: boolean }>;
  sshReadCaConfig(mountPath: string): Promise<{ public_key: string }>;
  sshWriteCaConfig(mountPath: string, config: SshCaConfig): Promise<void>;
  sshDeleteCaConfig(mountPath: string): Promise<void>;

  // TOTP Secrets Engine
  totpListKeys(mountPath: string): Promise<string[]>;
  totpReadKey(mountPath: string, name: string): Promise<TotpKey>;
  totpCreateKey(mountPath: string, name: string, config: TotpKeyInput): Promise<TotpKey>;
  totpDeleteKey(mountPath: string, name: string): Promise<void>;
  totpGenerateCode(mountPath: string, name: string): Promise<TotpCode>;
  totpValidateCode(mountPath: string, name: string, code: string): Promise<TotpValidateResponse>;

  // Cubbyhole
  cubbyholeRead(path: string): Promise<Record<string, unknown>>;
  cubbyholeWrite(path: string, data: Record<string, unknown>): Promise<void>;
  cubbyholeDelete(path: string): Promise<void>;
  cubbyholeList(path?: string): Promise<string[]>;

  // Identity - Entities
  identityCreateEntity(entity: IdentityEntityInput): Promise<IdentityEntity>;
  identityReadEntity(id: string): Promise<IdentityEntity>;
  identityReadEntityByName(name: string): Promise<IdentityEntity>;
  identityUpdateEntity(id: string, entity: IdentityEntityInput): Promise<void>;
  identityDeleteEntity(id: string): Promise<void>;
  identityListEntities(): Promise<string[]>;
  identityListEntitiesByName(): Promise<string[]>;
  identityMergeEntities(request: EntityMergeRequest): Promise<void>;

  // Identity - Entity Aliases
  identityCreateEntityAlias(alias: IdentityAliasInput): Promise<IdentityAlias>;
  identityReadEntityAlias(id: string): Promise<IdentityAlias>;
  identityUpdateEntityAlias(id: string, alias: Partial<IdentityAliasInput>): Promise<void>;
  identityDeleteEntityAlias(id: string): Promise<void>;
  identityListEntityAliases(): Promise<string[]>;

  // Identity - Groups
  identityCreateGroup(group: IdentityGroupInput): Promise<IdentityGroup>;
  identityReadGroup(id: string): Promise<IdentityGroup>;
  identityReadGroupByName(name: string): Promise<IdentityGroup>;
  identityUpdateGroup(id: string, group: IdentityGroupInput): Promise<void>;
  identityDeleteGroup(id: string): Promise<void>;
  identityListGroups(): Promise<string[]>;
  identityListGroupsByName(): Promise<string[]>;

  // Identity - Group Aliases
  identityCreateGroupAlias(alias: IdentityGroupAliasInput): Promise<IdentityAlias>;
  identityReadGroupAlias(id: string): Promise<IdentityAlias>;
  identityUpdateGroupAlias(id: string, alias: Partial<IdentityGroupAliasInput>): Promise<void>;
  identityDeleteGroupAlias(id: string): Promise<void>;
  identityListGroupAliases(): Promise<string[]>;

  // AWS Secrets Engine
  awsReadRootConfig(mountPath: string): Promise<AwsRootConfig>;
  awsWriteRootConfig(mountPath: string, config: AwsRootConfig): Promise<void>;
  awsRotateRoot(mountPath: string): Promise<void>;
  awsReadLeaseConfig(mountPath: string): Promise<AwsLeaseConfig>;
  awsWriteLeaseConfig(mountPath: string, config: AwsLeaseConfig): Promise<void>;
  awsListRoles(mountPath: string): Promise<string[]>;
  awsReadRole(mountPath: string, name: string): Promise<AwsRole>;
  awsCreateRole(mountPath: string, name: string, role: AwsRoleInput): Promise<void>;
  awsDeleteRole(mountPath: string, name: string): Promise<void>;
  awsGenerateCredentials(mountPath: string, roleName: string, ttl?: string): Promise<AwsCredentials>;
  awsGenerateStsCredentials(mountPath: string, roleName: string, ttl?: string, roleArn?: string): Promise<AwsCredentials>;
  awsListStaticRoles(mountPath: string): Promise<string[]>;
  awsReadStaticRole(mountPath: string, name: string): Promise<AwsStaticRole>;
  awsCreateStaticRole(mountPath: string, name: string, role: AwsStaticRoleInput): Promise<void>;
  awsDeleteStaticRole(mountPath: string, name: string): Promise<void>;
  awsGetStaticCredentials(mountPath: string, name: string): Promise<AwsCredentials>;

  // Userpass Auth Method
  userpassListUsers(mountPath: string): Promise<string[]>;
  userpassReadUser(mountPath: string, username: string): Promise<UserpassUser>;
  userpassCreateUser(mountPath: string, username: string, config: UserpassUserInput): Promise<void>;
  userpassUpdateUser(mountPath: string, username: string, config: Partial<UserpassUserInput>): Promise<void>;
  userpassDeleteUser(mountPath: string, username: string): Promise<void>;
  userpassUpdatePassword(mountPath: string, username: string, password: string): Promise<void>;
  userpassUpdatePolicies(mountPath: string, username: string, policies: string[]): Promise<void>;
  userpassLogin(mountPath: string, username: string, password: string): Promise<AuthInfo>;

  // JWT/OIDC Auth Method
  jwtReadConfig(mountPath: string): Promise<JwtConfig>;
  jwtWriteConfig(mountPath: string, config: JwtConfig): Promise<void>;
  jwtListRoles(mountPath: string): Promise<string[]>;
  jwtReadRole(mountPath: string, name: string): Promise<JwtRole>;
  jwtCreateRole(mountPath: string, name: string, role: JwtRoleInput): Promise<void>;
  jwtDeleteRole(mountPath: string, name: string): Promise<void>;
  jwtLogin(mountPath: string, role: string, jwt: string): Promise<AuthInfo>;
  oidcGetAuthUrl(mountPath: string, role: string, redirectUri: string): Promise<OidcAuthUrlResponse>;

  // System Wrapping
  wrap(data: Record<string, unknown>, ttl?: string): Promise<WrapInfo>;
  unwrap(token?: string): Promise<Record<string, unknown>>;
  rewrap(token: string): Promise<WrapInfo>;
  lookupWrapping(token: string): Promise<WrapLookupResponse>;

  // System Tools
  sysGenerateRandom(bytes?: number, format?: string): Promise<string>;
  sysHash(input: string, algorithm?: string, format?: string): Promise<string>;
}

// =============================================================================
// Vault Client Implementation
// =============================================================================

class VaultClientImpl implements VaultClient {
  private credentials: TenantCredentials;
  private baseUrl: string;

  constructor(credentials: TenantCredentials) {
    this.credentials = credentials;
    this.baseUrl = credentials.address.replace(/\/+$/, '') + '/v1';
  }

  // ===========================================================================
  // HTTP Request Helper
  // ===========================================================================

  private getAuthHeaders(): Record<string, string> {
    const headers: Record<string, string> = {
      'X-Vault-Token': this.credentials.token,
      'Content-Type': 'application/json',
    };

    if (this.credentials.namespace) {
      headers['X-Vault-Namespace'] = this.credentials.namespace;
    }

    return headers;
  }

  private async request<T>(
    endpoint: string,
    options: RequestInit = {},
    skipAuth = false
  ): Promise<T> {
    const url = `${this.baseUrl}${endpoint}`;

    const headers = skipAuth
      ? { 'Content-Type': 'application/json' }
      : this.getAuthHeaders();

    const response = await fetch(url, {
      ...options,
      headers: {
        ...headers,
        ...(options.headers || {}),
      },
    });

    // Handle rate limiting
    if (response.status === 429) {
      const retryAfter = response.headers.get('Retry-After');
      throw new RateLimitError('Rate limit exceeded', retryAfter ? parseInt(retryAfter, 10) : 60);
    }

    // Handle authentication errors
    if (response.status === 401 || response.status === 403) {
      throw new AuthenticationError('Authentication failed. Check your Vault token.');
    }

    // Handle other errors
    if (!response.ok) {
      const errorBody = await response.text();
      let message = `Vault API error: ${response.status}`;
      let errors: string[] = [];
      try {
        const errorJson = JSON.parse(errorBody);
        errors = errorJson.errors || [];
        message = errors.join('; ') || message;
      } catch {
        // Use default message
      }
      throw new VaultApiError(message, response.status, undefined, false, errors);
    }

    // Handle 204 No Content
    if (response.status === 204) {
      return undefined as T;
    }

    return response.json() as Promise<T>;
  }

  private async list<T>(endpoint: string): Promise<T> {
    return this.request<T>(endpoint, { method: 'LIST' });
  }

  // ===========================================================================
  // Connection
  // ===========================================================================

  async testConnection(): Promise<{ connected: boolean; message: string }> {
    try {
      const health = await this.getHealth();
      if (health.sealed) {
        return { connected: true, message: 'Connected to Vault (sealed)' };
      }
      return { connected: true, message: `Connected to Vault ${health.version}` };
    } catch (error) {
      return {
        connected: false,
        message: error instanceof Error ? error.message : 'Connection failed',
      };
    }
  }

  // ===========================================================================
  // System Backend
  // ===========================================================================

  async getHealth(): Promise<HealthStatus> {
    return this.request<HealthStatus>('/sys/health', { method: 'GET' }, true);
  }

  async getSealStatus(): Promise<SealStatus> {
    return this.request<SealStatus>('/sys/seal-status', { method: 'GET' }, true);
  }

  async seal(): Promise<void> {
    await this.request<void>('/sys/seal', { method: 'PUT' });
  }

  async unseal(key: string, reset = false): Promise<SealStatus> {
    return this.request<SealStatus>('/sys/unseal', {
      method: 'PUT',
      body: JSON.stringify({ key, reset }),
    });
  }

  async init(options: InitRequest): Promise<InitResponse> {
    return this.request<InitResponse>('/sys/init', {
      method: 'PUT',
      body: JSON.stringify(options),
    }, true);
  }

  async getLeader(): Promise<LeaderStatus> {
    return this.request<LeaderStatus>('/sys/leader', { method: 'GET' });
  }

  // ===========================================================================
  // Mounts (Secrets Engines)
  // ===========================================================================

  async listMounts(): Promise<Record<string, Mount>> {
    const response = await this.request<VaultResponse<Record<string, Mount>>>('/sys/mounts');
    return response.data || {};
  }

  async getMount(path: string): Promise<Mount> {
    const response = await this.request<VaultResponse<Mount>>(`/sys/mounts/${path}`);
    return response.data!;
  }

  async enableSecretsEngine(path: string, input: MountInput): Promise<void> {
    await this.request(`/sys/mounts/${path}`, {
      method: 'POST',
      body: JSON.stringify(input),
    });
  }

  async disableSecretsEngine(path: string): Promise<void> {
    await this.request(`/sys/mounts/${path}`, { method: 'DELETE' });
  }

  async tuneMount(path: string, input: MountTuneInput): Promise<void> {
    await this.request(`/sys/mounts/${path}/tune`, {
      method: 'POST',
      body: JSON.stringify(input),
    });
  }

  // ===========================================================================
  // Auth Methods
  // ===========================================================================

  async listAuthMethods(): Promise<Record<string, AuthMethod>> {
    const response = await this.request<VaultResponse<Record<string, AuthMethod>>>('/sys/auth');
    return response.data || {};
  }

  async enableAuthMethod(path: string, input: AuthMethodInput): Promise<void> {
    await this.request(`/sys/auth/${path}`, {
      method: 'POST',
      body: JSON.stringify(input),
    });
  }

  async disableAuthMethod(path: string): Promise<void> {
    await this.request(`/sys/auth/${path}`, { method: 'DELETE' });
  }

  // ===========================================================================
  // Policies
  // ===========================================================================

  async listPolicies(): Promise<string[]> {
    const response = await this.request<VaultResponse<{ policies: string[] }>>('/sys/policies/acl', {
      method: 'LIST',
    });
    return response.data?.policies || [];
  }

  async getPolicy(name: string): Promise<string> {
    const response = await this.request<VaultResponse<{ policy: string }>>(
      `/sys/policies/acl/${name}`
    );
    return response.data?.policy || '';
  }

  async createPolicy(name: string, policy: string): Promise<void> {
    await this.request(`/sys/policies/acl/${name}`, {
      method: 'PUT',
      body: JSON.stringify({ policy }),
    });
  }

  async deletePolicy(name: string): Promise<void> {
    await this.request(`/sys/policies/acl/${name}`, { method: 'DELETE' });
  }

  // ===========================================================================
  // Tokens
  // ===========================================================================

  async lookupSelf(): Promise<TokenInfo> {
    const response = await this.request<VaultResponse<TokenInfo>>('/auth/token/lookup-self');
    return response.data!;
  }

  async lookupToken(token: string): Promise<TokenInfo> {
    const response = await this.request<VaultResponse<TokenInfo>>('/auth/token/lookup', {
      method: 'POST',
      body: JSON.stringify({ token }),
    });
    return response.data!;
  }

  async createToken(options?: TokenCreateRequest): Promise<AuthInfo> {
    const response = await this.request<VaultResponse<never>>('/auth/token/create', {
      method: 'POST',
      body: JSON.stringify(options || {}),
    });
    return response.auth!;
  }

  async renewSelf(increment?: string): Promise<AuthInfo> {
    const response = await this.request<VaultResponse<never>>('/auth/token/renew-self', {
      method: 'POST',
      body: JSON.stringify({ increment }),
    });
    return response.auth!;
  }

  async renewToken(token: string, increment?: string): Promise<AuthInfo> {
    const response = await this.request<VaultResponse<never>>('/auth/token/renew', {
      method: 'POST',
      body: JSON.stringify({ token, increment }),
    });
    return response.auth!;
  }

  async revokeSelf(): Promise<void> {
    await this.request('/auth/token/revoke-self', { method: 'POST' });
  }

  async revokeToken(token: string): Promise<void> {
    await this.request('/auth/token/revoke', {
      method: 'POST',
      body: JSON.stringify({ token }),
    });
  }

  async revokeAccessor(accessor: string): Promise<void> {
    await this.request('/auth/token/revoke-accessor', {
      method: 'POST',
      body: JSON.stringify({ accessor }),
    });
  }

  async listAccessors(): Promise<string[]> {
    const response = await this.request<VaultResponse<{ keys: string[] }>>(
      '/auth/token/accessors',
      { method: 'LIST' }
    );
    return response.data?.keys || [];
  }

  async listTokenRoles(): Promise<string[]> {
    const response = await this.request<VaultResponse<{ keys: string[] }>>(
      '/auth/token/roles',
      { method: 'LIST' }
    );
    return response.data?.keys || [];
  }

  async getTokenRole(name: string): Promise<TokenRole> {
    const response = await this.request<VaultResponse<TokenRole>>(`/auth/token/roles/${name}`);
    return response.data!;
  }

  async createTokenRole(name: string, role: Partial<TokenRole>): Promise<void> {
    await this.request(`/auth/token/roles/${name}`, {
      method: 'POST',
      body: JSON.stringify(role),
    });
  }

  async deleteTokenRole(name: string): Promise<void> {
    await this.request(`/auth/token/roles/${name}`, { method: 'DELETE' });
  }

  // ===========================================================================
  // Leases
  // ===========================================================================

  async lookupLease(leaseId: string): Promise<LeaseInfo> {
    const response = await this.request<VaultResponse<LeaseInfo>>('/sys/leases/lookup', {
      method: 'POST',
      body: JSON.stringify({ lease_id: leaseId }),
    });
    return response.data!;
  }

  async renewLease(leaseId: string, increment?: number): Promise<LeaseInfo> {
    const response = await this.request<VaultResponse<LeaseInfo>>('/sys/leases/renew', {
      method: 'POST',
      body: JSON.stringify({ lease_id: leaseId, increment }),
    });
    return response.data!;
  }

  async revokeLease(leaseId: string, sync = false): Promise<void> {
    await this.request('/sys/leases/revoke', {
      method: 'POST',
      body: JSON.stringify({ lease_id: leaseId, sync }),
    });
  }

  async revokeLeasePrefix(prefix: string, sync = false): Promise<void> {
    await this.request(`/sys/leases/revoke-prefix/${prefix}`, {
      method: 'POST',
      body: JSON.stringify({ sync }),
    });
  }

  // ===========================================================================
  // Audit Devices
  // ===========================================================================

  async listAuditDevices(): Promise<Record<string, AuditDevice>> {
    const response = await this.request<VaultResponse<Record<string, AuditDevice>>>('/sys/audit');
    return response.data || {};
  }

  async enableAuditDevice(path: string, input: AuditDeviceInput): Promise<void> {
    await this.request(`/sys/audit/${path}`, {
      method: 'PUT',
      body: JSON.stringify(input),
    });
  }

  async disableAuditDevice(path: string): Promise<void> {
    await this.request(`/sys/audit/${path}`, { method: 'DELETE' });
  }

  // ===========================================================================
  // KV v2
  // ===========================================================================

  async kvRead(mountPath: string, secretPath: string, version?: number): Promise<KvSecret> {
    let endpoint = `/${mountPath}/data/${secretPath}`;
    if (version !== undefined) {
      endpoint += `?version=${version}`;
    }
    const response = await this.request<VaultResponse<KvSecret>>(endpoint);
    return response.data!;
  }

  async kvWrite(
    mountPath: string,
    secretPath: string,
    data: Record<string, unknown>,
    options?: KvWriteOptions
  ): Promise<{ version: number }> {
    const body: Record<string, unknown> = { data };
    if (options?.cas !== undefined) {
      body.options = { cas: options.cas };
    }
    const response = await this.request<VaultResponse<{ version: number }>>(
      `/${mountPath}/data/${secretPath}`,
      {
        method: 'POST',
        body: JSON.stringify(body),
      }
    );
    return response.data!;
  }

  async kvDelete(mountPath: string, secretPath: string): Promise<void> {
    await this.request(`/${mountPath}/data/${secretPath}`, { method: 'DELETE' });
  }

  async kvDeleteVersions(mountPath: string, secretPath: string, versions: number[]): Promise<void> {
    await this.request(`/${mountPath}/delete/${secretPath}`, {
      method: 'POST',
      body: JSON.stringify({ versions }),
    });
  }

  async kvUndelete(mountPath: string, secretPath: string, versions: number[]): Promise<void> {
    await this.request(`/${mountPath}/undelete/${secretPath}`, {
      method: 'POST',
      body: JSON.stringify({ versions }),
    });
  }

  async kvDestroy(mountPath: string, secretPath: string, versions: number[]): Promise<void> {
    await this.request(`/${mountPath}/destroy/${secretPath}`, {
      method: 'PUT',
      body: JSON.stringify({ versions }),
    });
  }

  async kvList(mountPath: string, path = ''): Promise<string[]> {
    const endpoint = path ? `/${mountPath}/metadata/${path}` : `/${mountPath}/metadata`;
    const response = await this.list<VaultResponse<{ keys: string[] }>>(endpoint);
    return response.data?.keys || [];
  }

  async kvReadMetadata(mountPath: string, secretPath: string): Promise<KvSecretMetadata> {
    const response = await this.request<VaultResponse<KvSecretMetadata>>(
      `/${mountPath}/metadata/${secretPath}`
    );
    return response.data!;
  }

  async kvWriteMetadata(
    mountPath: string,
    secretPath: string,
    metadata: Partial<KvSecretMetadata>
  ): Promise<void> {
    await this.request(`/${mountPath}/metadata/${secretPath}`, {
      method: 'POST',
      body: JSON.stringify(metadata),
    });
  }

  async kvDeleteMetadata(mountPath: string, secretPath: string): Promise<void> {
    await this.request(`/${mountPath}/metadata/${secretPath}`, { method: 'DELETE' });
  }

  async kvReadConfig(mountPath: string): Promise<KvConfig> {
    const response = await this.request<VaultResponse<KvConfig>>(`/${mountPath}/config`);
    return response.data!;
  }

  async kvWriteConfig(mountPath: string, config: Partial<KvConfig>): Promise<void> {
    await this.request(`/${mountPath}/config`, {
      method: 'POST',
      body: JSON.stringify(config),
    });
  }

  // ===========================================================================
  // KV v1
  // ===========================================================================

  async kvV1Read(mountPath: string, secretPath: string): Promise<KvV1Secret> {
    const response = await this.request<VaultResponse<KvV1Secret>>(`/${mountPath}/${secretPath}`);
    return response.data!;
  }

  async kvV1Write(
    mountPath: string,
    secretPath: string,
    data: Record<string, unknown>
  ): Promise<void> {
    await this.request(`/${mountPath}/${secretPath}`, {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  async kvV1Delete(mountPath: string, secretPath: string): Promise<void> {
    await this.request(`/${mountPath}/${secretPath}`, { method: 'DELETE' });
  }

  async kvV1List(mountPath: string, path = ''): Promise<string[]> {
    const endpoint = path ? `/${mountPath}/${path}` : `/${mountPath}`;
    const response = await this.list<VaultResponse<{ keys: string[] }>>(endpoint);
    return response.data?.keys || [];
  }

  // ===========================================================================
  // Transit
  // ===========================================================================

  async transitCreateKey(mountPath: string, name: string, config?: TransitKeyConfig): Promise<void> {
    await this.request(`/${mountPath}/keys/${name}`, {
      method: 'POST',
      body: JSON.stringify(config || {}),
    });
  }

  async transitReadKey(mountPath: string, name: string): Promise<TransitKey> {
    const response = await this.request<VaultResponse<TransitKey>>(`/${mountPath}/keys/${name}`);
    return response.data!;
  }

  async transitListKeys(mountPath: string): Promise<string[]> {
    const response = await this.list<VaultResponse<{ keys: string[] }>>(`/${mountPath}/keys`);
    return response.data?.keys || [];
  }

  async transitDeleteKey(mountPath: string, name: string): Promise<void> {
    await this.request(`/${mountPath}/keys/${name}`, { method: 'DELETE' });
  }

  async transitUpdateKeyConfig(
    mountPath: string,
    name: string,
    config: Partial<TransitKeyConfig>
  ): Promise<void> {
    await this.request(`/${mountPath}/keys/${name}/config`, {
      method: 'POST',
      body: JSON.stringify(config),
    });
  }

  async transitRotateKey(mountPath: string, name: string): Promise<void> {
    await this.request(`/${mountPath}/keys/${name}/rotate`, { method: 'POST' });
  }

  async transitEncrypt(
    mountPath: string,
    keyName: string,
    plaintext: string,
    options?: { context?: string; keyVersion?: number }
  ): Promise<TransitEncryptResponse> {
    const response = await this.request<VaultResponse<TransitEncryptResponse>>(
      `/${mountPath}/encrypt/${keyName}`,
      {
        method: 'POST',
        body: JSON.stringify({
          plaintext: btoa(plaintext),
          context: options?.context,
          key_version: options?.keyVersion,
        }),
      }
    );
    return response.data!;
  }

  async transitDecrypt(
    mountPath: string,
    keyName: string,
    ciphertext: string,
    options?: { context?: string }
  ): Promise<TransitDecryptResponse> {
    const response = await this.request<VaultResponse<TransitDecryptResponse>>(
      `/${mountPath}/decrypt/${keyName}`,
      {
        method: 'POST',
        body: JSON.stringify({
          ciphertext,
          context: options?.context,
        }),
      }
    );
    return {
      plaintext: atob(response.data!.plaintext),
    };
  }

  async transitRewrap(
    mountPath: string,
    keyName: string,
    ciphertext: string,
    options?: { context?: string; keyVersion?: number }
  ): Promise<TransitRewrapResponse> {
    const response = await this.request<VaultResponse<TransitRewrapResponse>>(
      `/${mountPath}/rewrap/${keyName}`,
      {
        method: 'POST',
        body: JSON.stringify({
          ciphertext,
          context: options?.context,
          key_version: options?.keyVersion,
        }),
      }
    );
    return response.data!;
  }

  async transitGenerateDataKey(
    mountPath: string,
    keyName: string,
    type: 'plaintext' | 'wrapped',
    options?: { context?: string; bits?: number }
  ): Promise<TransitDataKeyResponse> {
    const response = await this.request<VaultResponse<TransitDataKeyResponse>>(
      `/${mountPath}/datakey/${type}/${keyName}`,
      {
        method: 'POST',
        body: JSON.stringify({
          context: options?.context,
          bits: options?.bits,
        }),
      }
    );
    return response.data!;
  }

  async transitGenerateRandom(
    mountPath: string,
    bytes = 32,
    format = 'base64'
  ): Promise<TransitRandomResponse> {
    const response = await this.request<VaultResponse<TransitRandomResponse>>(
      `/${mountPath}/random/${bytes}`,
      {
        method: 'POST',
        body: JSON.stringify({ format }),
      }
    );
    return response.data!;
  }

  async transitHash(
    mountPath: string,
    input: string,
    algorithm = 'sha2-256',
    format = 'hex'
  ): Promise<TransitHashResponse> {
    const response = await this.request<VaultResponse<TransitHashResponse>>(
      `/${mountPath}/hash/${algorithm}`,
      {
        method: 'POST',
        body: JSON.stringify({ input: btoa(input), format }),
      }
    );
    return response.data!;
  }

  async transitHmac(
    mountPath: string,
    keyName: string,
    input: string,
    algorithm = 'sha2-256'
  ): Promise<TransitHmacResponse> {
    const response = await this.request<VaultResponse<TransitHmacResponse>>(
      `/${mountPath}/hmac/${keyName}/${algorithm}`,
      {
        method: 'POST',
        body: JSON.stringify({ input: btoa(input) }),
      }
    );
    return response.data!;
  }

  async transitSign(
    mountPath: string,
    keyName: string,
    input: string,
    options?: { hashAlgorithm?: string; signatureAlgorithm?: string }
  ): Promise<TransitSignResponse> {
    const endpoint = options?.hashAlgorithm
      ? `/${mountPath}/sign/${keyName}/${options.hashAlgorithm}`
      : `/${mountPath}/sign/${keyName}`;
    const response = await this.request<VaultResponse<TransitSignResponse>>(endpoint, {
      method: 'POST',
      body: JSON.stringify({
        input: btoa(input),
        signature_algorithm: options?.signatureAlgorithm,
      }),
    });
    return response.data!;
  }

  async transitVerify(
    mountPath: string,
    keyName: string,
    input: string,
    signature: string,
    options?: { hashAlgorithm?: string }
  ): Promise<TransitVerifyResponse> {
    const endpoint = options?.hashAlgorithm
      ? `/${mountPath}/verify/${keyName}/${options.hashAlgorithm}`
      : `/${mountPath}/verify/${keyName}`;
    const response = await this.request<VaultResponse<TransitVerifyResponse>>(endpoint, {
      method: 'POST',
      body: JSON.stringify({
        input: btoa(input),
        signature,
      }),
    });
    return response.data!;
  }

  // ===========================================================================
  // PKI
  // ===========================================================================

  async pkiListRoles(mountPath: string): Promise<string[]> {
    const response = await this.list<VaultResponse<{ keys: string[] }>>(`/${mountPath}/roles`);
    return response.data?.keys || [];
  }

  async pkiReadRole(mountPath: string, name: string): Promise<PkiRole> {
    const response = await this.request<VaultResponse<PkiRole>>(`/${mountPath}/roles/${name}`);
    return response.data!;
  }

  async pkiCreateRole(mountPath: string, name: string, role: Partial<PkiRole>): Promise<void> {
    await this.request(`/${mountPath}/roles/${name}`, {
      method: 'POST',
      body: JSON.stringify(role),
    });
  }

  async pkiDeleteRole(mountPath: string, name: string): Promise<void> {
    await this.request(`/${mountPath}/roles/${name}`, { method: 'DELETE' });
  }

  async pkiIssueCertificate(
    mountPath: string,
    roleName: string,
    request: PkiIssueRequest
  ): Promise<PkiCertificate> {
    const response = await this.request<VaultResponse<PkiCertificate>>(
      `/${mountPath}/issue/${roleName}`,
      {
        method: 'POST',
        body: JSON.stringify(request),
      }
    );
    return response.data!;
  }

  async pkiSignCertificate(
    mountPath: string,
    roleName: string,
    request: PkiSignRequest
  ): Promise<PkiCertificate> {
    const response = await this.request<VaultResponse<PkiCertificate>>(
      `/${mountPath}/sign/${roleName}`,
      {
        method: 'POST',
        body: JSON.stringify(request),
      }
    );
    return response.data!;
  }

  async pkiRevokeCertificate(mountPath: string, request: PkiRevokeRequest): Promise<void> {
    await this.request(`/${mountPath}/revoke`, {
      method: 'POST',
      body: JSON.stringify(request),
    });
  }

  async pkiListCertificates(mountPath: string): Promise<string[]> {
    const response = await this.list<VaultResponse<{ keys: string[] }>>(`/${mountPath}/certs`);
    return response.data?.keys || [];
  }

  async pkiReadCertificate(mountPath: string, serial: string): Promise<{ certificate: string }> {
    const response = await this.request<VaultResponse<{ certificate: string }>>(
      `/${mountPath}/cert/${serial}`
    );
    return response.data!;
  }

  async pkiGetCa(mountPath: string): Promise<{ certificate: string }> {
    const response = await this.request<VaultResponse<{ certificate: string }>>(
      `/${mountPath}/cert/ca`
    );
    return response.data!;
  }

  async pkiGetCaChain(mountPath: string): Promise<{ ca_chain: string }> {
    const response = await this.request<VaultResponse<{ ca_chain: string }>>(
      `/${mountPath}/cert/ca_chain`
    );
    return response.data!;
  }

  async pkiListIssuers(mountPath: string): Promise<string[]> {
    const response = await this.list<VaultResponse<{ keys: string[] }>>(`/${mountPath}/issuers`);
    return response.data?.keys || [];
  }

  async pkiReadIssuer(mountPath: string, issuerId: string): Promise<PkiIssuer> {
    const response = await this.request<VaultResponse<PkiIssuer>>(
      `/${mountPath}/issuer/${issuerId}`
    );
    return response.data!;
  }

  async pkiReadUrlsConfig(mountPath: string): Promise<PkiUrlsConfig> {
    const response = await this.request<VaultResponse<PkiUrlsConfig>>(
      `/${mountPath}/config/urls`
    );
    return response.data!;
  }

  async pkiWriteUrlsConfig(mountPath: string, config: Partial<PkiUrlsConfig>): Promise<void> {
    await this.request(`/${mountPath}/config/urls`, {
      method: 'POST',
      body: JSON.stringify(config),
    });
  }

  async pkiRotateCrl(mountPath: string): Promise<{ success: boolean }> {
    const response = await this.request<VaultResponse<{ success: boolean }>>(
      `/${mountPath}/crl/rotate`,
      { method: 'POST' }
    );
    return response.data!;
  }

  async pkiTidy(mountPath: string, options?: Record<string, unknown>): Promise<void> {
    await this.request(`/${mountPath}/tidy`, {
      method: 'POST',
      body: JSON.stringify(options || {}),
    });
  }

  // ===========================================================================
  // Database
  // ===========================================================================

  async dbListConnections(mountPath: string): Promise<string[]> {
    const response = await this.list<VaultResponse<{ keys: string[] }>>(`/${mountPath}/config`);
    return response.data?.keys || [];
  }

  async dbReadConnection(mountPath: string, name: string): Promise<DatabaseConnection> {
    const response = await this.request<VaultResponse<DatabaseConnection>>(
      `/${mountPath}/config/${name}`
    );
    return response.data!;
  }

  async dbCreateConnection(
    mountPath: string,
    name: string,
    config: DatabaseConnectionInput
  ): Promise<void> {
    await this.request(`/${mountPath}/config/${name}`, {
      method: 'POST',
      body: JSON.stringify(config),
    });
  }

  async dbDeleteConnection(mountPath: string, name: string): Promise<void> {
    await this.request(`/${mountPath}/config/${name}`, { method: 'DELETE' });
  }

  async dbResetConnection(mountPath: string, name: string): Promise<void> {
    await this.request(`/${mountPath}/reset/${name}`, { method: 'POST' });
  }

  async dbRotateRoot(mountPath: string, name: string): Promise<void> {
    await this.request(`/${mountPath}/rotate-root/${name}`, { method: 'POST' });
  }

  async dbListRoles(mountPath: string): Promise<string[]> {
    const response = await this.list<VaultResponse<{ keys: string[] }>>(`/${mountPath}/roles`);
    return response.data?.keys || [];
  }

  async dbReadRole(mountPath: string, name: string): Promise<DatabaseRole> {
    const response = await this.request<VaultResponse<DatabaseRole>>(
      `/${mountPath}/roles/${name}`
    );
    return response.data!;
  }

  async dbCreateRole(mountPath: string, name: string, role: DatabaseRoleInput): Promise<void> {
    await this.request(`/${mountPath}/roles/${name}`, {
      method: 'POST',
      body: JSON.stringify(role),
    });
  }

  async dbDeleteRole(mountPath: string, name: string): Promise<void> {
    await this.request(`/${mountPath}/roles/${name}`, { method: 'DELETE' });
  }

  async dbGenerateCredentials(mountPath: string, roleName: string): Promise<DatabaseCredentials> {
    const response = await this.request<VaultResponse<DatabaseCredentials>>(
      `/${mountPath}/creds/${roleName}`
    );
    return response.data!;
  }

  async dbListStaticRoles(mountPath: string): Promise<string[]> {
    const response = await this.list<VaultResponse<{ keys: string[] }>>(
      `/${mountPath}/static-roles`
    );
    return response.data?.keys || [];
  }

  async dbReadStaticRole(mountPath: string, name: string): Promise<DatabaseStaticRole> {
    const response = await this.request<VaultResponse<DatabaseStaticRole>>(
      `/${mountPath}/static-roles/${name}`
    );
    return response.data!;
  }

  async dbCreateStaticRole(
    mountPath: string,
    name: string,
    role: DatabaseStaticRoleInput
  ): Promise<void> {
    await this.request(`/${mountPath}/static-roles/${name}`, {
      method: 'POST',
      body: JSON.stringify(role),
    });
  }

  async dbDeleteStaticRole(mountPath: string, name: string): Promise<void> {
    await this.request(`/${mountPath}/static-roles/${name}`, { method: 'DELETE' });
  }

  async dbGetStaticCredentials(mountPath: string, roleName: string): Promise<DatabaseCredentials> {
    const response = await this.request<VaultResponse<DatabaseCredentials>>(
      `/${mountPath}/static-creds/${roleName}`
    );
    return response.data!;
  }

  async dbRotateStaticRole(mountPath: string, roleName: string): Promise<void> {
    await this.request(`/${mountPath}/rotate-role/${roleName}`, { method: 'POST' });
  }

  // ===========================================================================
  // AppRole
  // ===========================================================================

  async approleListRoles(mountPath: string): Promise<string[]> {
    const response = await this.list<VaultResponse<{ keys: string[] }>>(`/auth/${mountPath}/role`);
    return response.data?.keys || [];
  }

  async approleReadRole(mountPath: string, roleName: string): Promise<AppRole> {
    const response = await this.request<VaultResponse<AppRole>>(
      `/auth/${mountPath}/role/${roleName}`
    );
    return response.data!;
  }

  async approleCreateRole(mountPath: string, roleName: string, role: AppRoleInput): Promise<void> {
    await this.request(`/auth/${mountPath}/role/${roleName}`, {
      method: 'POST',
      body: JSON.stringify(role),
    });
  }

  async approleDeleteRole(mountPath: string, roleName: string): Promise<void> {
    await this.request(`/auth/${mountPath}/role/${roleName}`, { method: 'DELETE' });
  }

  async approleGetRoleId(mountPath: string, roleName: string): Promise<string> {
    const response = await this.request<VaultResponse<{ role_id: string }>>(
      `/auth/${mountPath}/role/${roleName}/role-id`
    );
    return response.data!.role_id;
  }

  async approleSetRoleId(mountPath: string, roleName: string, roleId: string): Promise<void> {
    await this.request(`/auth/${mountPath}/role/${roleName}/role-id`, {
      method: 'POST',
      body: JSON.stringify({ role_id: roleId }),
    });
  }

  async approleGenerateSecretId(
    mountPath: string,
    roleName: string,
    options?: SecretIdInput
  ): Promise<SecretId> {
    const response = await this.request<VaultResponse<SecretId>>(
      `/auth/${mountPath}/role/${roleName}/secret-id`,
      {
        method: 'POST',
        body: JSON.stringify(options || {}),
      }
    );
    return response.data!;
  }

  async approleListSecretIds(mountPath: string, roleName: string): Promise<string[]> {
    const response = await this.list<VaultResponse<{ keys: string[] }>>(
      `/auth/${mountPath}/role/${roleName}/secret-id`
    );
    return response.data?.keys || [];
  }

  async approleLookupSecretId(
    mountPath: string,
    roleName: string,
    secretId: string
  ): Promise<SecretId> {
    const response = await this.request<VaultResponse<SecretId>>(
      `/auth/${mountPath}/role/${roleName}/secret-id/lookup`,
      {
        method: 'POST',
        body: JSON.stringify({ secret_id: secretId }),
      }
    );
    return response.data!;
  }

  async approleDestroySecretId(
    mountPath: string,
    roleName: string,
    secretId: string
  ): Promise<void> {
    await this.request(`/auth/${mountPath}/role/${roleName}/secret-id/destroy`, {
      method: 'POST',
      body: JSON.stringify({ secret_id: secretId }),
    });
  }

  async approleLogin(mountPath: string, roleId: string, secretId: string): Promise<AuthInfo> {
    const response = await this.request<VaultResponse<never>>(
      `/auth/${mountPath}/login`,
      {
        method: 'POST',
        body: JSON.stringify({ role_id: roleId, secret_id: secretId }),
      },
      true
    );
    return response.auth!;
  }

  // ===========================================================================
  // Capabilities
  // ===========================================================================

  async checkCapabilities(paths: string[], token?: string): Promise<Record<string, string[]>> {
    const endpoint = token ? '/sys/capabilities' : '/sys/capabilities-self';
    const body: Record<string, unknown> = { paths };
    if (token) body.token = token;

    const response = await this.request<VaultResponse<Record<string, string[]>>>(endpoint, {
      method: 'POST',
      body: JSON.stringify(body),
    });
    return response.data || {};
  }

  async checkCapabilitiesSelf(paths: string[]): Promise<Record<string, string[]>> {
    return this.checkCapabilities(paths);
  }

  // ===========================================================================
  // SSH Secrets Engine
  // ===========================================================================

  async sshListRoles(mountPath: string): Promise<string[]> {
    const response = await this.list<VaultResponse<{ keys: string[] }>>(`/${mountPath}/roles`);
    return response.data?.keys || [];
  }

  async sshReadRole(mountPath: string, name: string): Promise<SshRole> {
    const response = await this.request<VaultResponse<SshRole>>(`/${mountPath}/roles/${name}`);
    return response.data!;
  }

  async sshCreateRole(mountPath: string, name: string, role: SshRoleInput): Promise<void> {
    await this.request(`/${mountPath}/roles/${name}`, {
      method: 'POST',
      body: JSON.stringify(role),
    });
  }

  async sshDeleteRole(mountPath: string, name: string): Promise<void> {
    await this.request(`/${mountPath}/roles/${name}`, { method: 'DELETE' });
  }

  async sshGenerateCredentials(
    mountPath: string,
    roleName: string,
    ip: string,
    username?: string
  ): Promise<SshCredentials> {
    const body: Record<string, string> = { ip };
    if (username) body.username = username;
    const response = await this.request<VaultResponse<SshCredentials>>(
      `/${mountPath}/creds/${roleName}`,
      { method: 'POST', body: JSON.stringify(body) }
    );
    return response.data!;
  }

  async sshSignKey(mountPath: string, roleName: string, request: SshSignRequest): Promise<SshSignedKey> {
    const response = await this.request<VaultResponse<SshSignedKey>>(
      `/${mountPath}/sign/${roleName}`,
      { method: 'POST', body: JSON.stringify(request) }
    );
    return response.data!;
  }

  async sshVerifyOtp(mountPath: string, otp: string): Promise<{ valid: boolean }> {
    const response = await this.request<VaultResponse<{ valid: boolean }>>(
      `/${mountPath}/verify`,
      { method: 'POST', body: JSON.stringify({ otp }) }
    );
    return response.data!;
  }

  async sshReadCaConfig(mountPath: string): Promise<{ public_key: string }> {
    const response = await this.request<VaultResponse<{ public_key: string }>>(
      `/${mountPath}/config/ca`
    );
    return response.data!;
  }

  async sshWriteCaConfig(mountPath: string, config: SshCaConfig): Promise<void> {
    await this.request(`/${mountPath}/config/ca`, {
      method: 'POST',
      body: JSON.stringify(config),
    });
  }

  async sshDeleteCaConfig(mountPath: string): Promise<void> {
    await this.request(`/${mountPath}/config/ca`, { method: 'DELETE' });
  }

  // ===========================================================================
  // TOTP Secrets Engine
  // ===========================================================================

  async totpListKeys(mountPath: string): Promise<string[]> {
    const response = await this.list<VaultResponse<{ keys: string[] }>>(`/${mountPath}/keys`);
    return response.data?.keys || [];
  }

  async totpReadKey(mountPath: string, name: string): Promise<TotpKey> {
    const response = await this.request<VaultResponse<TotpKey>>(`/${mountPath}/keys/${name}`);
    return response.data!;
  }

  async totpCreateKey(mountPath: string, name: string, config: TotpKeyInput): Promise<TotpKey> {
    const response = await this.request<VaultResponse<TotpKey>>(`/${mountPath}/keys/${name}`, {
      method: 'POST',
      body: JSON.stringify(config),
    });
    return response.data!;
  }

  async totpDeleteKey(mountPath: string, name: string): Promise<void> {
    await this.request(`/${mountPath}/keys/${name}`, { method: 'DELETE' });
  }

  async totpGenerateCode(mountPath: string, name: string): Promise<TotpCode> {
    const response = await this.request<VaultResponse<TotpCode>>(`/${mountPath}/code/${name}`);
    return response.data!;
  }

  async totpValidateCode(mountPath: string, name: string, code: string): Promise<TotpValidateResponse> {
    const response = await this.request<VaultResponse<TotpValidateResponse>>(
      `/${mountPath}/code/${name}`,
      { method: 'POST', body: JSON.stringify({ code }) }
    );
    return response.data!;
  }

  // ===========================================================================
  // Cubbyhole
  // ===========================================================================

  async cubbyholeRead(path: string): Promise<Record<string, unknown>> {
    const response = await this.request<VaultResponse<Record<string, unknown>>>(
      `/cubbyhole/${path}`
    );
    return response.data || {};
  }

  async cubbyholeWrite(path: string, data: Record<string, unknown>): Promise<void> {
    await this.request(`/cubbyhole/${path}`, {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  async cubbyholeDelete(path: string): Promise<void> {
    await this.request(`/cubbyhole/${path}`, { method: 'DELETE' });
  }

  async cubbyholeList(path?: string): Promise<string[]> {
    const response = await this.list<VaultResponse<{ keys: string[] }>>(
      `/cubbyhole/${path || ''}`
    );
    return response.data?.keys || [];
  }

  // ===========================================================================
  // Identity - Entities
  // ===========================================================================

  async identityCreateEntity(entity: IdentityEntityInput): Promise<IdentityEntity> {
    const response = await this.request<VaultResponse<IdentityEntity>>('/identity/entity', {
      method: 'POST',
      body: JSON.stringify(entity),
    });
    return response.data!;
  }

  async identityReadEntity(id: string): Promise<IdentityEntity> {
    const response = await this.request<VaultResponse<IdentityEntity>>(
      `/identity/entity/id/${id}`
    );
    return response.data!;
  }

  async identityReadEntityByName(name: string): Promise<IdentityEntity> {
    const response = await this.request<VaultResponse<IdentityEntity>>(
      `/identity/entity/name/${name}`
    );
    return response.data!;
  }

  async identityUpdateEntity(id: string, entity: IdentityEntityInput): Promise<void> {
    await this.request(`/identity/entity/id/${id}`, {
      method: 'POST',
      body: JSON.stringify(entity),
    });
  }

  async identityDeleteEntity(id: string): Promise<void> {
    await this.request(`/identity/entity/id/${id}`, { method: 'DELETE' });
  }

  async identityListEntities(): Promise<string[]> {
    const response = await this.list<VaultResponse<{ keys: string[] }>>('/identity/entity/id');
    return response.data?.keys || [];
  }

  async identityListEntitiesByName(): Promise<string[]> {
    const response = await this.list<VaultResponse<{ keys: string[] }>>('/identity/entity/name');
    return response.data?.keys || [];
  }

  async identityMergeEntities(request: EntityMergeRequest): Promise<void> {
    await this.request('/identity/entity/merge', {
      method: 'POST',
      body: JSON.stringify(request),
    });
  }

  // ===========================================================================
  // Identity - Entity Aliases
  // ===========================================================================

  async identityCreateEntityAlias(alias: IdentityAliasInput): Promise<IdentityAlias> {
    const response = await this.request<VaultResponse<IdentityAlias>>('/identity/entity-alias', {
      method: 'POST',
      body: JSON.stringify(alias),
    });
    return response.data!;
  }

  async identityReadEntityAlias(id: string): Promise<IdentityAlias> {
    const response = await this.request<VaultResponse<IdentityAlias>>(
      `/identity/entity-alias/id/${id}`
    );
    return response.data!;
  }

  async identityUpdateEntityAlias(id: string, alias: Partial<IdentityAliasInput>): Promise<void> {
    await this.request(`/identity/entity-alias/id/${id}`, {
      method: 'POST',
      body: JSON.stringify(alias),
    });
  }

  async identityDeleteEntityAlias(id: string): Promise<void> {
    await this.request(`/identity/entity-alias/id/${id}`, { method: 'DELETE' });
  }

  async identityListEntityAliases(): Promise<string[]> {
    const response = await this.list<VaultResponse<{ keys: string[] }>>('/identity/entity-alias/id');
    return response.data?.keys || [];
  }

  // ===========================================================================
  // Identity - Groups
  // ===========================================================================

  async identityCreateGroup(group: IdentityGroupInput): Promise<IdentityGroup> {
    const response = await this.request<VaultResponse<IdentityGroup>>('/identity/group', {
      method: 'POST',
      body: JSON.stringify(group),
    });
    return response.data!;
  }

  async identityReadGroup(id: string): Promise<IdentityGroup> {
    const response = await this.request<VaultResponse<IdentityGroup>>(`/identity/group/id/${id}`);
    return response.data!;
  }

  async identityReadGroupByName(name: string): Promise<IdentityGroup> {
    const response = await this.request<VaultResponse<IdentityGroup>>(
      `/identity/group/name/${name}`
    );
    return response.data!;
  }

  async identityUpdateGroup(id: string, group: IdentityGroupInput): Promise<void> {
    await this.request(`/identity/group/id/${id}`, {
      method: 'POST',
      body: JSON.stringify(group),
    });
  }

  async identityDeleteGroup(id: string): Promise<void> {
    await this.request(`/identity/group/id/${id}`, { method: 'DELETE' });
  }

  async identityListGroups(): Promise<string[]> {
    const response = await this.list<VaultResponse<{ keys: string[] }>>('/identity/group/id');
    return response.data?.keys || [];
  }

  async identityListGroupsByName(): Promise<string[]> {
    const response = await this.list<VaultResponse<{ keys: string[] }>>('/identity/group/name');
    return response.data?.keys || [];
  }

  // ===========================================================================
  // Identity - Group Aliases
  // ===========================================================================

  async identityCreateGroupAlias(alias: IdentityGroupAliasInput): Promise<IdentityAlias> {
    const response = await this.request<VaultResponse<IdentityAlias>>('/identity/group-alias', {
      method: 'POST',
      body: JSON.stringify(alias),
    });
    return response.data!;
  }

  async identityReadGroupAlias(id: string): Promise<IdentityAlias> {
    const response = await this.request<VaultResponse<IdentityAlias>>(
      `/identity/group-alias/id/${id}`
    );
    return response.data!;
  }

  async identityUpdateGroupAlias(id: string, alias: Partial<IdentityGroupAliasInput>): Promise<void> {
    await this.request(`/identity/group-alias/id/${id}`, {
      method: 'POST',
      body: JSON.stringify(alias),
    });
  }

  async identityDeleteGroupAlias(id: string): Promise<void> {
    await this.request(`/identity/group-alias/id/${id}`, { method: 'DELETE' });
  }

  async identityListGroupAliases(): Promise<string[]> {
    const response = await this.list<VaultResponse<{ keys: string[] }>>('/identity/group-alias/id');
    return response.data?.keys || [];
  }

  // ===========================================================================
  // AWS Secrets Engine
  // ===========================================================================

  async awsReadRootConfig(mountPath: string): Promise<AwsRootConfig> {
    const response = await this.request<VaultResponse<AwsRootConfig>>(`/${mountPath}/config/root`);
    return response.data!;
  }

  async awsWriteRootConfig(mountPath: string, config: AwsRootConfig): Promise<void> {
    await this.request(`/${mountPath}/config/root`, {
      method: 'POST',
      body: JSON.stringify(config),
    });
  }

  async awsRotateRoot(mountPath: string): Promise<void> {
    await this.request(`/${mountPath}/config/rotate-root`, { method: 'POST' });
  }

  async awsReadLeaseConfig(mountPath: string): Promise<AwsLeaseConfig> {
    const response = await this.request<VaultResponse<AwsLeaseConfig>>(`/${mountPath}/config/lease`);
    return response.data!;
  }

  async awsWriteLeaseConfig(mountPath: string, config: AwsLeaseConfig): Promise<void> {
    await this.request(`/${mountPath}/config/lease`, {
      method: 'POST',
      body: JSON.stringify(config),
    });
  }

  async awsListRoles(mountPath: string): Promise<string[]> {
    const response = await this.list<VaultResponse<{ keys: string[] }>>(`/${mountPath}/roles`);
    return response.data?.keys || [];
  }

  async awsReadRole(mountPath: string, name: string): Promise<AwsRole> {
    const response = await this.request<VaultResponse<AwsRole>>(`/${mountPath}/roles/${name}`);
    return response.data!;
  }

  async awsCreateRole(mountPath: string, name: string, role: AwsRoleInput): Promise<void> {
    await this.request(`/${mountPath}/roles/${name}`, {
      method: 'POST',
      body: JSON.stringify(role),
    });
  }

  async awsDeleteRole(mountPath: string, name: string): Promise<void> {
    await this.request(`/${mountPath}/roles/${name}`, { method: 'DELETE' });
  }

  async awsGenerateCredentials(
    mountPath: string,
    roleName: string,
    ttl?: string
  ): Promise<AwsCredentials> {
    const params = ttl ? `?ttl=${ttl}` : '';
    const response = await this.request<VaultResponse<AwsCredentials>>(
      `/${mountPath}/creds/${roleName}${params}`
    );
    return response.data!;
  }

  async awsGenerateStsCredentials(
    mountPath: string,
    roleName: string,
    ttl?: string,
    roleArn?: string
  ): Promise<AwsCredentials> {
    const body: Record<string, string> = {};
    if (ttl) body.ttl = ttl;
    if (roleArn) body.role_arn = roleArn;
    const response = await this.request<VaultResponse<AwsCredentials>>(
      `/${mountPath}/sts/${roleName}`,
      { method: 'POST', body: JSON.stringify(body) }
    );
    return response.data!;
  }

  async awsListStaticRoles(mountPath: string): Promise<string[]> {
    const response = await this.list<VaultResponse<{ keys: string[] }>>(
      `/${mountPath}/static-roles`
    );
    return response.data?.keys || [];
  }

  async awsReadStaticRole(mountPath: string, name: string): Promise<AwsStaticRole> {
    const response = await this.request<VaultResponse<AwsStaticRole>>(
      `/${mountPath}/static-roles/${name}`
    );
    return response.data!;
  }

  async awsCreateStaticRole(mountPath: string, name: string, role: AwsStaticRoleInput): Promise<void> {
    await this.request(`/${mountPath}/static-roles/${name}`, {
      method: 'POST',
      body: JSON.stringify(role),
    });
  }

  async awsDeleteStaticRole(mountPath: string, name: string): Promise<void> {
    await this.request(`/${mountPath}/static-roles/${name}`, { method: 'DELETE' });
  }

  async awsGetStaticCredentials(mountPath: string, name: string): Promise<AwsCredentials> {
    const response = await this.request<VaultResponse<AwsCredentials>>(
      `/${mountPath}/static-creds/${name}`
    );
    return response.data!;
  }

  // ===========================================================================
  // Userpass Auth Method
  // ===========================================================================

  async userpassListUsers(mountPath: string): Promise<string[]> {
    const response = await this.list<VaultResponse<{ keys: string[] }>>(
      `/auth/${mountPath}/users`
    );
    return response.data?.keys || [];
  }

  async userpassReadUser(mountPath: string, username: string): Promise<UserpassUser> {
    const response = await this.request<VaultResponse<UserpassUser>>(
      `/auth/${mountPath}/users/${username}`
    );
    return response.data!;
  }

  async userpassCreateUser(
    mountPath: string,
    username: string,
    config: UserpassUserInput
  ): Promise<void> {
    await this.request(`/auth/${mountPath}/users/${username}`, {
      method: 'POST',
      body: JSON.stringify(config),
    });
  }

  async userpassUpdateUser(
    mountPath: string,
    username: string,
    config: Partial<UserpassUserInput>
  ): Promise<void> {
    await this.request(`/auth/${mountPath}/users/${username}`, {
      method: 'POST',
      body: JSON.stringify(config),
    });
  }

  async userpassDeleteUser(mountPath: string, username: string): Promise<void> {
    await this.request(`/auth/${mountPath}/users/${username}`, { method: 'DELETE' });
  }

  async userpassUpdatePassword(mountPath: string, username: string, password: string): Promise<void> {
    await this.request(`/auth/${mountPath}/users/${username}/password`, {
      method: 'POST',
      body: JSON.stringify({ password }),
    });
  }

  async userpassUpdatePolicies(
    mountPath: string,
    username: string,
    policies: string[]
  ): Promise<void> {
    await this.request(`/auth/${mountPath}/users/${username}/policies`, {
      method: 'POST',
      body: JSON.stringify({ token_policies: policies }),
    });
  }

  async userpassLogin(mountPath: string, username: string, password: string): Promise<AuthInfo> {
    const response = await this.request<VaultResponse<never>>(
      `/auth/${mountPath}/login/${username}`,
      { method: 'POST', body: JSON.stringify({ password }) },
      true
    );
    return response.auth!;
  }

  // ===========================================================================
  // JWT/OIDC Auth Method
  // ===========================================================================

  async jwtReadConfig(mountPath: string): Promise<JwtConfig> {
    const response = await this.request<VaultResponse<JwtConfig>>(`/auth/${mountPath}/config`);
    return response.data!;
  }

  async jwtWriteConfig(mountPath: string, config: JwtConfig): Promise<void> {
    await this.request(`/auth/${mountPath}/config`, {
      method: 'POST',
      body: JSON.stringify(config),
    });
  }

  async jwtListRoles(mountPath: string): Promise<string[]> {
    const response = await this.list<VaultResponse<{ keys: string[] }>>(`/auth/${mountPath}/role`);
    return response.data?.keys || [];
  }

  async jwtReadRole(mountPath: string, name: string): Promise<JwtRole> {
    const response = await this.request<VaultResponse<JwtRole>>(`/auth/${mountPath}/role/${name}`);
    return response.data!;
  }

  async jwtCreateRole(mountPath: string, name: string, role: JwtRoleInput): Promise<void> {
    await this.request(`/auth/${mountPath}/role/${name}`, {
      method: 'POST',
      body: JSON.stringify(role),
    });
  }

  async jwtDeleteRole(mountPath: string, name: string): Promise<void> {
    await this.request(`/auth/${mountPath}/role/${name}`, { method: 'DELETE' });
  }

  async jwtLogin(mountPath: string, role: string, jwt: string): Promise<AuthInfo> {
    const response = await this.request<VaultResponse<never>>(
      `/auth/${mountPath}/login`,
      { method: 'POST', body: JSON.stringify({ role, jwt }) },
      true
    );
    return response.auth!;
  }

  async oidcGetAuthUrl(
    mountPath: string,
    role: string,
    redirectUri: string
  ): Promise<OidcAuthUrlResponse> {
    const response = await this.request<VaultResponse<OidcAuthUrlResponse>>(
      `/auth/${mountPath}/oidc/auth_url`,
      { method: 'POST', body: JSON.stringify({ role, redirect_uri: redirectUri }) }
    );
    return response.data!;
  }

  // ===========================================================================
  // System Wrapping
  // ===========================================================================

  async wrap(data: Record<string, unknown>, ttl?: string): Promise<WrapInfo> {
    const headers: Record<string, string> = {};
    if (ttl) headers['X-Vault-Wrap-TTL'] = ttl;
    const response = await this.request<VaultResponse<never>>('/sys/wrapping/wrap', {
      method: 'POST',
      body: JSON.stringify(data),
      headers,
    });
    return response.wrap_info!;
  }

  async unwrap(token?: string): Promise<Record<string, unknown>> {
    const body = token ? JSON.stringify({ token }) : '{}';
    const response = await this.request<VaultResponse<Record<string, unknown>>>(
      '/sys/wrapping/unwrap',
      { method: 'POST', body }
    );
    return response.data || {};
  }

  async rewrap(token: string): Promise<WrapInfo> {
    const response = await this.request<VaultResponse<never>>('/sys/wrapping/rewrap', {
      method: 'POST',
      body: JSON.stringify({ token }),
    });
    return response.wrap_info!;
  }

  async lookupWrapping(token: string): Promise<WrapLookupResponse> {
    const response = await this.request<VaultResponse<WrapLookupResponse>>(
      '/sys/wrapping/lookup',
      { method: 'POST', body: JSON.stringify({ token }) }
    );
    return response.data!;
  }

  // ===========================================================================
  // System Tools
  // ===========================================================================

  async sysGenerateRandom(bytes = 32, format = 'base64'): Promise<string> {
    const response = await this.request<VaultResponse<{ random_bytes: string }>>(
      `/sys/tools/random/${bytes}`,
      { method: 'POST', body: JSON.stringify({ format }) }
    );
    return response.data!.random_bytes;
  }

  async sysHash(input: string, algorithm = 'sha2-256', format = 'hex'): Promise<string> {
    const response = await this.request<VaultResponse<{ sum: string }>>(
      `/sys/tools/hash/${algorithm}`,
      { method: 'POST', body: JSON.stringify({ input, format }) }
    );
    return response.data!.sum;
  }
}

// =============================================================================
// Factory Function
// =============================================================================

/**
 * Create a Vault client instance with tenant-specific credentials.
 *
 * MULTI-TENANT: Each request provides its own credentials via headers,
 * allowing a single server deployment to serve multiple tenants.
 *
 * @param credentials - Tenant credentials parsed from request headers
 */
export function createVaultClient(credentials: TenantCredentials): VaultClient {
  return new VaultClientImpl(credentials);
}
