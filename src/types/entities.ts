/**
 * Vault Entity Types
 *
 * Type definitions for HashiCorp Vault API responses and requests.
 */

// =============================================================================
// Common Response Types
// =============================================================================

export interface VaultResponse<T> {
  request_id: string;
  lease_id?: string;
  renewable?: boolean;
  lease_duration?: number;
  data?: T;
  wrap_info?: WrapInfo;
  warnings?: string[];
  auth?: AuthInfo;
}

export interface WrapInfo {
  token: string;
  accessor: string;
  ttl: number;
  creation_time: string;
  creation_path: string;
  wrapped_accessor?: string;
}

export interface AuthInfo {
  client_token: string;
  accessor: string;
  policies: string[];
  token_policies: string[];
  metadata?: Record<string, string>;
  lease_duration: number;
  renewable: boolean;
  entity_id: string;
  token_type: string;
  orphan: boolean;
  mfa_requirement?: MfaRequirement;
  num_uses?: number;
}

export interface MfaRequirement {
  mfa_request_id: string;
  mfa_constraints: Record<string, MfaConstraint>;
}

export interface MfaConstraint {
  any: MfaMethod[];
}

export interface MfaMethod {
  type: string;
  id: string;
  uses_passcode: boolean;
  name?: string;
}

// =============================================================================
// System Backend Types
// =============================================================================

export interface HealthStatus {
  initialized: boolean;
  sealed: boolean;
  standby: boolean;
  performance_standby: boolean;
  replication_performance_mode: string;
  replication_dr_mode: string;
  server_time_utc: number;
  version: string;
  cluster_name?: string;
  cluster_id?: string;
}

export interface SealStatus {
  type: string;
  initialized: boolean;
  sealed: boolean;
  t: number;
  n: number;
  progress: number;
  nonce: string;
  version: string;
  build_date: string;
  migration: boolean;
  cluster_name?: string;
  cluster_id?: string;
  recovery_seal: boolean;
  storage_type: string;
}

export interface InitStatus {
  initialized: boolean;
}

export interface InitRequest {
  secret_shares: number;
  secret_threshold: number;
  recovery_shares?: number;
  recovery_threshold?: number;
  root_token_pgp_key?: string;
  recovery_pgp_keys?: string[];
  stored_shares?: number;
}

export interface InitResponse {
  keys: string[];
  keys_base64: string[];
  root_token: string;
  recovery_keys?: string[];
  recovery_keys_base64?: string[];
}

export interface UnsealRequest {
  key?: string;
  reset?: boolean;
  migrate?: boolean;
}

export interface LeaderStatus {
  ha_enabled: boolean;
  is_self: boolean;
  active_time?: string;
  leader_address?: string;
  leader_cluster_address?: string;
  performance_standby: boolean;
  performance_standby_last_remote_wal: number;
  last_wal?: number;
  raft_committed_index?: number;
  raft_applied_index?: number;
}

// =============================================================================
// Mounts
// =============================================================================

export interface Mount {
  accessor: string;
  config: MountConfig;
  description: string;
  external_entropy_access: boolean;
  local: boolean;
  options?: Record<string, string>;
  plugin_version?: string;
  running_plugin_version?: string;
  running_sha256?: string;
  seal_wrap: boolean;
  type: string;
  uuid: string;
}

export interface MountConfig {
  default_lease_ttl: number;
  force_no_cache: boolean;
  max_lease_ttl: number;
  token_type?: string;
  audit_non_hmac_request_keys?: string[];
  audit_non_hmac_response_keys?: string[];
  listing_visibility?: string;
  passthrough_request_headers?: string[];
}

export interface MountInput {
  type: string;
  description?: string;
  config?: Partial<MountConfig>;
  options?: Record<string, string>;
  local?: boolean;
  seal_wrap?: boolean;
  external_entropy_access?: boolean;
  plugin_name?: string;
  plugin_version?: string;
}

export interface MountTuneInput {
  default_lease_ttl?: string;
  max_lease_ttl?: string;
  description?: string;
  audit_non_hmac_request_keys?: string[];
  audit_non_hmac_response_keys?: string[];
  listing_visibility?: string;
  passthrough_request_headers?: string[];
  allowed_response_headers?: string[];
  token_type?: string;
  allowed_managed_keys?: string[];
  plugin_version?: string;
}

// =============================================================================
// Auth Methods
// =============================================================================

export interface AuthMethod {
  accessor: string;
  config: AuthMethodConfig;
  description: string;
  external_entropy_access: boolean;
  local: boolean;
  options?: Record<string, string>;
  plugin_version?: string;
  running_plugin_version?: string;
  running_sha256?: string;
  seal_wrap: boolean;
  type: string;
  uuid: string;
}

export interface AuthMethodConfig {
  default_lease_ttl: number;
  force_no_cache: boolean;
  max_lease_ttl: number;
  token_type: string;
}

export interface AuthMethodInput {
  type: string;
  description?: string;
  config?: Partial<AuthMethodConfig>;
  options?: Record<string, string>;
  local?: boolean;
  seal_wrap?: boolean;
  external_entropy_access?: boolean;
  plugin_name?: string;
  plugin_version?: string;
}

// =============================================================================
// Policies
// =============================================================================

export interface Policy {
  name: string;
  rules: string;
}

// =============================================================================
// KV v2 Types
// =============================================================================

export interface KvSecret {
  data: Record<string, unknown>;
  metadata: KvMetadata;
}

export interface KvMetadata {
  created_time: string;
  custom_metadata?: Record<string, string>;
  deletion_time: string;
  destroyed: boolean;
  version: number;
}

export interface KvSecretMetadata {
  cas_required: boolean;
  created_time: string;
  current_version: number;
  custom_metadata?: Record<string, string>;
  delete_version_after: string;
  max_versions: number;
  oldest_version: number;
  updated_time: string;
  versions: Record<string, KvVersionInfo>;
}

export interface KvVersionInfo {
  created_time: string;
  deletion_time: string;
  destroyed: boolean;
}

export interface KvConfig {
  cas_required: boolean;
  delete_version_after: string;
  max_versions: number;
}

export interface KvWriteOptions {
  cas?: number;
}

export interface KvDeleteOptions {
  versions: number[];
}

// =============================================================================
// KV v1 Types
// =============================================================================

export interface KvV1Secret {
  [key: string]: unknown;
}

// =============================================================================
// Transit Types
// =============================================================================

export interface TransitKey {
  allow_plaintext_backup: boolean;
  auto_rotate_period: number;
  deletion_allowed: boolean;
  derived: boolean;
  exportable: boolean;
  imported_key: boolean;
  keys: Record<string, TransitKeyVersion>;
  latest_version: number;
  min_available_version: number;
  min_decryption_version: number;
  min_encryption_version: number;
  name: string;
  supports_decryption: boolean;
  supports_derivation: boolean;
  supports_encryption: boolean;
  supports_signing: boolean;
  type: string;
}

export interface TransitKeyVersion {
  creation_time: string;
  name?: string;
  public_key?: string;
  certificate_chain?: string;
}

export interface TransitKeyConfig {
  type?: string;
  convergent_encryption?: boolean;
  derived?: boolean;
  exportable?: boolean;
  allow_plaintext_backup?: boolean;
  auto_rotate_period?: string;
}

export interface TransitEncryptRequest {
  plaintext: string;
  context?: string;
  key_version?: number;
  nonce?: string;
  type?: string;
  convergent_encryption?: boolean;
  partial_failure_response_code?: number;
}

export interface TransitEncryptResponse {
  ciphertext: string;
  key_version?: number;
}

export interface TransitDecryptRequest {
  ciphertext: string;
  context?: string;
  nonce?: string;
  partial_failure_response_code?: number;
}

export interface TransitDecryptResponse {
  plaintext: string;
}

export interface TransitSignRequest {
  input: string;
  key_version?: number;
  hash_algorithm?: string;
  context?: string;
  prehashed?: boolean;
  signature_algorithm?: string;
  marshaling_algorithm?: string;
  salt_length?: string;
}

export interface TransitSignResponse {
  signature: string;
  key_version?: number;
}

export interface TransitVerifyRequest {
  input: string;
  signature?: string;
  hmac?: string;
  hash_algorithm?: string;
  context?: string;
  prehashed?: boolean;
  signature_algorithm?: string;
  marshaling_algorithm?: string;
  salt_length?: string;
}

export interface TransitVerifyResponse {
  valid: boolean;
}

export interface TransitHashRequest {
  input: string;
  algorithm?: string;
  format?: string;
}

export interface TransitHashResponse {
  sum: string;
}

export interface TransitHmacRequest {
  input: string;
  key_version?: number;
  algorithm?: string;
}

export interface TransitHmacResponse {
  hmac: string;
}

export interface TransitDataKeyRequest {
  context?: string;
  nonce?: string;
  bits?: number;
}

export interface TransitDataKeyResponse {
  ciphertext: string;
  plaintext?: string;
  key_version?: number;
}

export interface TransitRandomRequest {
  bytes?: number;
  format?: string;
}

export interface TransitRandomResponse {
  random_bytes: string;
}

export interface TransitRewrapRequest {
  ciphertext: string;
  context?: string;
  key_version?: number;
  nonce?: string;
}

export interface TransitRewrapResponse {
  ciphertext: string;
  key_version?: number;
}

// =============================================================================
// Token Types
// =============================================================================

export interface TokenInfo {
  accessor: string;
  creation_time: number;
  creation_ttl: number;
  display_name: string;
  entity_id: string;
  expire_time?: string;
  explicit_max_ttl: number;
  id: string;
  issue_time: string;
  meta?: Record<string, string>;
  num_uses: number;
  orphan: boolean;
  path: string;
  policies: string[];
  renewable: boolean;
  ttl: number;
  type: string;
}

export interface TokenCreateRequest {
  id?: string;
  role_name?: string;
  policies?: string[];
  meta?: Record<string, string>;
  no_parent?: boolean;
  no_default_policy?: boolean;
  renewable?: boolean;
  ttl?: string;
  type?: string;
  explicit_max_ttl?: string;
  display_name?: string;
  num_uses?: number;
  period?: string;
  entity_alias?: string;
}

export interface TokenRole {
  allowed_entity_aliases?: string[];
  allowed_policies?: string[];
  allowed_policies_glob?: string[];
  disallowed_policies?: string[];
  disallowed_policies_glob?: string[];
  explicit_max_ttl?: number;
  name: string;
  orphan?: boolean;
  path_suffix?: string;
  period?: number;
  renewable?: boolean;
  token_bound_cidrs?: string[];
  token_explicit_max_ttl?: number;
  token_no_default_policy?: boolean;
  token_num_uses?: number;
  token_period?: number;
  token_type?: string;
}

export interface TokenRenewRequest {
  token?: string;
  increment?: string;
}

// =============================================================================
// Lease Types
// =============================================================================

export interface LeaseInfo {
  id: string;
  issue_time: string;
  expire_time: string;
  last_renewal?: string;
  renewable: boolean;
  ttl: number;
}

export interface LeaseRenewRequest {
  lease_id: string;
  increment?: number;
}

export interface LeaseRevokeRequest {
  lease_id: string;
  sync?: boolean;
}

// =============================================================================
// Audit Types
// =============================================================================

export interface AuditDevice {
  description: string;
  local: boolean;
  options: Record<string, string>;
  path: string;
  type: string;
}

export interface AuditDeviceInput {
  type: string;
  description?: string;
  options?: Record<string, string>;
  local?: boolean;
}

// =============================================================================
// PKI Types
// =============================================================================

export interface PkiRole {
  name: string;
  allow_any_name: boolean;
  allow_bare_domains: boolean;
  allow_glob_domains: boolean;
  allow_ip_sans: boolean;
  allow_localhost: boolean;
  allow_subdomains: boolean;
  allow_wildcard_certificates: boolean;
  allowed_domains: string[];
  allowed_domains_template: boolean;
  allowed_other_sans: string[];
  allowed_serial_numbers: string[];
  allowed_uri_sans: string[];
  allowed_uri_sans_template: boolean;
  basic_constraints_valid_for_non_ca: boolean;
  client_flag: boolean;
  cn_validations: string[];
  code_signing_flag: boolean;
  country: string[];
  email_protection_flag: boolean;
  enforce_hostnames: boolean;
  ext_key_usage: string[];
  ext_key_usage_oids: string[];
  generate_lease: boolean;
  issuer_ref: string;
  key_bits: number;
  key_type: string;
  key_usage: string[];
  locality: string[];
  max_ttl: number;
  no_store: boolean;
  not_after: string;
  not_before_duration: number;
  organization: string[];
  ou: string[];
  policy_identifiers: string[];
  postal_code: string[];
  province: string[];
  require_cn: boolean;
  server_flag: boolean;
  signature_bits: number;
  street_address: string[];
  ttl: number;
  use_csr_common_name: boolean;
  use_csr_sans: boolean;
  use_pss: boolean;
}

export interface PkiCertificate {
  certificate: string;
  issuing_ca: string;
  ca_chain: string[];
  private_key?: string;
  private_key_type?: string;
  serial_number: string;
  expiration: number;
}

export interface PkiIssueRequest {
  common_name: string;
  alt_names?: string;
  ip_sans?: string;
  uri_sans?: string;
  other_sans?: string;
  ttl?: string;
  format?: string;
  private_key_format?: string;
  exclude_cn_from_sans?: boolean;
  not_after?: string;
  remove_roots_from_chain?: boolean;
  user_ids?: string;
}

export interface PkiSignRequest {
  csr: string;
  common_name?: string;
  alt_names?: string;
  ip_sans?: string;
  uri_sans?: string;
  other_sans?: string;
  ttl?: string;
  format?: string;
  exclude_cn_from_sans?: boolean;
  not_after?: string;
  remove_roots_from_chain?: boolean;
  user_ids?: string;
}

export interface PkiRevokeRequest {
  serial_number: string;
}

export interface PkiIssuer {
  ca_chain: string[];
  certificate: string;
  issuer_id: string;
  issuer_name: string;
  key_id: string;
  leaf_not_after_behavior: string;
  manual_chain?: string[];
  usage: string;
}

export interface PkiUrlsConfig {
  crl_distribution_points: string[];
  issuing_certificates: string[];
  ocsp_servers: string[];
  enable_templating: boolean;
}

// =============================================================================
// Database Types
// =============================================================================

export interface DatabaseConnection {
  allowed_roles: string[];
  connection_details: Record<string, unknown>;
  password_policy?: string;
  plugin_name: string;
  plugin_version?: string;
  root_credentials_rotate_statements?: string[];
  verify_connection: boolean;
}

export interface DatabaseConnectionInput {
  plugin_name: string;
  connection_url?: string;
  username?: string;
  password?: string;
  allowed_roles?: string[];
  verify_connection?: boolean;
  password_policy?: string;
  root_rotation_statements?: string[];
}

export interface DatabaseRole {
  db_name: string;
  creation_statements: string[];
  revocation_statements?: string[];
  rollback_statements?: string[];
  renew_statements?: string[];
  default_ttl: number;
  max_ttl: number;
  credential_type: string;
  credential_config?: Record<string, unknown>;
}

export interface DatabaseRoleInput {
  db_name: string;
  creation_statements: string[];
  revocation_statements?: string[];
  rollback_statements?: string[];
  renew_statements?: string[];
  default_ttl?: string;
  max_ttl?: string;
  credential_type?: string;
  credential_config?: Record<string, unknown>;
}

export interface DatabaseStaticRole {
  db_name: string;
  username: string;
  rotation_period?: number;
  rotation_schedule?: string;
  rotation_window?: number;
  rotation_statements?: string[];
  credential_type: string;
  credential_config?: Record<string, unknown>;
}

export interface DatabaseStaticRoleInput {
  db_name: string;
  username: string;
  rotation_period?: string;
  rotation_schedule?: string;
  rotation_window?: string;
  rotation_statements?: string[];
  credential_type?: string;
  credential_config?: Record<string, unknown>;
}

export interface DatabaseCredentials {
  username: string;
  password: string;
}

// =============================================================================
// AppRole Types
// =============================================================================

export interface AppRole {
  bind_secret_id: boolean;
  local_secret_ids: boolean;
  policies: string[];
  secret_id_bound_cidrs?: string[];
  secret_id_num_uses: number;
  secret_id_ttl: number;
  token_bound_cidrs?: string[];
  token_explicit_max_ttl: number;
  token_max_ttl: number;
  token_no_default_policy: boolean;
  token_num_uses: number;
  token_period: number;
  token_policies: string[];
  token_ttl: number;
  token_type: string;
}

export interface AppRoleInput {
  bind_secret_id?: boolean;
  secret_id_bound_cidrs?: string[];
  secret_id_num_uses?: number;
  secret_id_ttl?: string;
  local_secret_ids?: boolean;
  token_ttl?: string;
  token_max_ttl?: string;
  token_policies?: string[];
  policies?: string[];
  token_bound_cidrs?: string[];
  token_explicit_max_ttl?: string;
  token_no_default_policy?: boolean;
  token_num_uses?: number;
  token_period?: string;
  token_type?: string;
}

export interface SecretId {
  secret_id: string;
  secret_id_accessor: string;
  secret_id_num_uses: number;
  secret_id_ttl: number;
}

export interface SecretIdInput {
  metadata?: string;
  cidr_list?: string[];
  token_bound_cidrs?: string[];
  num_uses?: number;
  ttl?: string;
}

export interface AppRoleLoginRequest {
  role_id: string;
  secret_id: string;
}

// =============================================================================
// Capabilities Types
// =============================================================================

export interface CapabilitiesRequest {
  paths: string[];
  token?: string;
}

export interface CapabilitiesResponse {
  capabilities: Record<string, string[]>;
}

// =============================================================================
// SSH Secrets Engine Types
// =============================================================================

export interface SshRole {
  key_type: 'otp' | 'ca' | 'dynamic';
  default_user?: string;
  allowed_users?: string;
  allowed_users_template?: boolean;
  allowed_domains?: string;
  cidr_list?: string;
  exclude_cidr_list?: string;
  port?: number;
  ttl?: string;
  max_ttl?: string;
  allowed_critical_options?: string;
  allowed_extensions?: string;
  default_critical_options?: Record<string, string>;
  default_extensions?: Record<string, string>;
  allow_user_certificates?: boolean;
  allow_host_certificates?: boolean;
  allow_bare_domains?: boolean;
  allow_subdomains?: boolean;
  allow_user_key_ids?: boolean;
  key_id_format?: string;
  algorithm_signer?: string;
  not_before_duration?: string;
}

export interface SshRoleInput {
  key_type: 'otp' | 'ca' | 'dynamic';
  default_user?: string;
  allowed_users?: string;
  allowed_users_template?: boolean;
  cidr_list?: string;
  exclude_cidr_list?: string;
  port?: number;
  ttl?: string;
  max_ttl?: string;
  allowed_critical_options?: string;
  allowed_extensions?: string;
  default_critical_options?: Record<string, string>;
  default_extensions?: Record<string, string>;
  allow_user_certificates?: boolean;
  allow_host_certificates?: boolean;
  algorithm_signer?: string;
}

export interface SshCredentials {
  key?: string;
  key_type?: string;
  username?: string;
  ip?: string;
  port?: number;
}

export interface SshSignRequest {
  public_key: string;
  ttl?: string;
  valid_principals?: string;
  cert_type?: 'user' | 'host';
  key_id?: string;
  critical_options?: Record<string, string>;
  extensions?: Record<string, string>;
}

export interface SshSignedKey {
  serial_number: string;
  signed_key: string;
}

export interface SshCaConfig {
  generate_signing_key?: boolean;
  public_key?: string;
  private_key?: string;
  key_type?: string;
  key_bits?: number;
}

// =============================================================================
// TOTP Secrets Engine Types
// =============================================================================

export interface TotpKey {
  account_name?: string;
  algorithm?: 'SHA1' | 'SHA256' | 'SHA512';
  digits?: number;
  issuer?: string;
  period?: number;
  key?: string;
  url?: string;
  generate?: boolean;
  key_size?: number;
  skew?: number;
  qr_size?: number;
  exported?: boolean;
}

export interface TotpKeyInput {
  generate?: boolean;
  exported?: boolean;
  key_size?: number;
  url?: string;
  key?: string;
  issuer?: string;
  account_name?: string;
  period?: number;
  algorithm?: 'SHA1' | 'SHA256' | 'SHA512';
  digits?: number;
  skew?: number;
  qr_size?: number;
}

export interface TotpCode {
  code: string;
}

export interface TotpValidateResponse {
  valid: boolean;
}

// =============================================================================
// Identity Secrets Engine Types
// =============================================================================

export interface IdentityEntity {
  id: string;
  name: string;
  aliases?: IdentityAlias[];
  metadata?: Record<string, string>;
  policies?: string[];
  disabled?: boolean;
  creation_time?: string;
  last_update_time?: string;
  direct_group_ids?: string[];
  inherited_group_ids?: string[];
  namespace_id?: string;
}

export interface IdentityEntityInput {
  name?: string;
  metadata?: Record<string, string>;
  policies?: string[];
  disabled?: boolean;
}

export interface IdentityAlias {
  id: string;
  canonical_id: string;
  mount_accessor: string;
  mount_path: string;
  mount_type: string;
  name: string;
  metadata?: Record<string, string>;
  creation_time?: string;
  last_update_time?: string;
}

export interface IdentityAliasInput {
  name: string;
  canonical_id: string;
  mount_accessor: string;
  metadata?: Record<string, string>;
}

export interface IdentityGroup {
  id: string;
  name: string;
  type: 'internal' | 'external';
  policies?: string[];
  metadata?: Record<string, string>;
  member_entity_ids?: string[];
  member_group_ids?: string[];
  parent_group_ids?: string[];
  alias?: IdentityAlias;
  creation_time?: string;
  last_update_time?: string;
  namespace_id?: string;
}

export interface IdentityGroupInput {
  name?: string;
  type?: 'internal' | 'external';
  policies?: string[];
  metadata?: Record<string, string>;
  member_entity_ids?: string[];
  member_group_ids?: string[];
}

export interface IdentityGroupAliasInput {
  name: string;
  mount_accessor: string;
  canonical_id: string;
}

export interface EntityMergeRequest {
  from_entity_ids: string[];
  to_entity_id: string;
  force?: boolean;
  conflicting_alias_ids_to_keep?: string[];
}

// =============================================================================
// AWS Secrets Engine Types
// =============================================================================

export interface AwsRootConfig {
  access_key?: string;
  secret_key?: string;
  region?: string;
  iam_endpoint?: string;
  sts_endpoint?: string;
  max_retries?: number;
  username_template?: string;
}

export interface AwsLeaseConfig {
  lease: string;
  lease_max: string;
}

export interface AwsRole {
  credential_type: 'iam_user' | 'assumed_role' | 'federation_token' | 'session_token';
  role_arns?: string[];
  policy_arns?: string[];
  policy_document?: string;
  iam_groups?: string[];
  iam_tags?: Record<string, string>;
  default_sts_ttl?: number;
  max_sts_ttl?: number;
  user_path?: string;
  permissions_boundary_arn?: string;
}

export interface AwsRoleInput {
  credential_type: 'iam_user' | 'assumed_role' | 'federation_token' | 'session_token';
  role_arns?: string[];
  policy_arns?: string[];
  policy_document?: string;
  iam_groups?: string[];
  iam_tags?: Record<string, string>;
  default_sts_ttl?: string;
  max_sts_ttl?: string;
  user_path?: string;
  permissions_boundary_arn?: string;
}

export interface AwsCredentials {
  access_key: string;
  secret_key: string;
  security_token?: string;
  arn?: string;
}

export interface AwsStaticRole {
  username: string;
  rotation_period: number;
}

export interface AwsStaticRoleInput {
  username: string;
  rotation_period: string;
}

// =============================================================================
// Userpass Auth Method Types
// =============================================================================

export interface UserpassUser {
  token_bound_cidrs?: string[];
  token_explicit_max_ttl?: number;
  token_max_ttl?: number;
  token_no_default_policy?: boolean;
  token_num_uses?: number;
  token_period?: number;
  token_policies?: string[];
  token_ttl?: number;
  token_type?: string;
}

export interface UserpassUserInput {
  password: string;
  token_policies?: string[];
  token_ttl?: string;
  token_max_ttl?: string;
  token_bound_cidrs?: string[];
  token_explicit_max_ttl?: string;
  token_no_default_policy?: boolean;
  token_num_uses?: number;
  token_period?: string;
  token_type?: string;
}

// =============================================================================
// JWT/OIDC Auth Method Types
// =============================================================================

export interface JwtConfig {
  oidc_discovery_url?: string;
  oidc_discovery_ca_pem?: string;
  oidc_client_id?: string;
  oidc_client_secret?: string;
  oidc_response_mode?: string;
  oidc_response_types?: string[];
  jwks_url?: string;
  jwks_ca_pem?: string;
  jwt_validation_pubkeys?: string[];
  jwt_supported_algs?: string[];
  bound_issuer?: string;
  default_role?: string;
  provider_config?: Record<string, string>;
  namespace_in_state?: boolean;
}

export interface JwtRole {
  role_type?: 'jwt' | 'oidc';
  bound_audiences?: string[];
  user_claim: string;
  user_claim_json_pointer?: boolean;
  clock_skew_leeway?: number;
  expiration_leeway?: number;
  not_before_leeway?: number;
  bound_subject?: string;
  bound_claims?: Record<string, string | string[]>;
  bound_claims_type?: 'string' | 'glob';
  groups_claim?: string;
  claim_mappings?: Record<string, string>;
  oidc_scopes?: string[];
  allowed_redirect_uris?: string[];
  verbose_oidc_logging?: boolean;
  max_age?: number;
  token_ttl?: number;
  token_max_ttl?: number;
  token_policies?: string[];
  token_bound_cidrs?: string[];
  token_explicit_max_ttl?: number;
  token_no_default_policy?: boolean;
  token_num_uses?: number;
  token_period?: number;
  token_type?: string;
}

export interface JwtRoleInput {
  role_type?: 'jwt' | 'oidc';
  bound_audiences?: string[];
  user_claim: string;
  user_claim_json_pointer?: boolean;
  clock_skew_leeway?: number;
  expiration_leeway?: number;
  not_before_leeway?: number;
  bound_subject?: string;
  bound_claims?: Record<string, string | string[]>;
  bound_claims_type?: 'string' | 'glob';
  groups_claim?: string;
  claim_mappings?: Record<string, string>;
  oidc_scopes?: string[];
  allowed_redirect_uris?: string[];
  verbose_oidc_logging?: boolean;
  max_age?: number;
  token_ttl?: string;
  token_max_ttl?: string;
  token_policies?: string[];
  token_bound_cidrs?: string[];
  token_explicit_max_ttl?: string;
  token_no_default_policy?: boolean;
  token_num_uses?: number;
  token_period?: string;
  token_type?: string;
}

export interface OidcAuthUrlResponse {
  auth_url: string;
  state?: string;
}

// =============================================================================
// System Wrapping Types
// =============================================================================

export interface WrapRequest {
  ttl?: string;
}

export interface WrapLookupResponse {
  creation_time: string;
  creation_ttl: number;
  creation_path: string;
}

// =============================================================================
// System Tools Types
// =============================================================================

export interface RandomBytesResponse {
  random_bytes: string;
}

// =============================================================================
// Response Format
// =============================================================================

export type ResponseFormat = 'json' | 'markdown';
