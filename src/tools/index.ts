/**
 * Tool Registration Index
 *
 * Exports all tool registration functions for the Vault MCP server.
 */

// System and Core
export { registerSystemTools } from './system.js';
export { registerTokenTools } from './tokens.js';
export { registerLeaseTools } from './leases.js';
export { registerWrappingTools } from './wrapping.js';

// Secrets Engines
export { registerKvTools } from './kv.js';
export { registerTransitTools } from './transit.js';
export { registerPkiTools } from './pki.js';
export { registerDatabaseTools } from './database.js';
export { registerSshTools } from './ssh.js';
export { registerTotpTools } from './totp.js';
export { registerCubbyholeTools } from './cubbyhole.js';
export { registerAwsTools } from './aws.js';
export { registerIdentityTools } from './identity.js';
export { registerRabbitmqTools } from './rabbitmq.js';
export { registerConsulTools } from './consul.js';

// Auth Methods
export { registerAppRoleTools } from './approle.js';
export { registerUserpassTools } from './userpass.js';
export { registerJwtTools } from './jwt.js';
export { registerGithubTools } from './github.js';
export { registerLdapTools } from './ldap.js';
export { registerKubernetesTools } from './kubernetes.js';
export { registerCertTools } from './cert.js';
