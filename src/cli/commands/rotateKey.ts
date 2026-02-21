/**
 * CLI: openclaw security rotate-key
 * Rotate encryption keys.
 */
import { randomBytes } from 'node:crypto';
import type { OpenClawConfig } from '../../types/index.js';
import { auditCritical } from '../../security/auditLogger.js';

export async function rotateKeyCommand(_config: OpenClawConfig): Promise<void> {
  console.log('\n  Key Rotation\n');
  console.log('  ─────────────────────────────────────────\n');

  // Generate new keys
  const newEncryptionKey = randomBytes(32).toString('hex');
  const newHmacSecret = randomBytes(32).toString('hex');
  const newSessionSecret = randomBytes(32).toString('hex');
  const newGatewayToken = randomBytes(32).toString('hex');

  console.log('  New keys generated. Update your .env file:\n');
  console.log(`  OPENCLAW_ENCRYPTION_KEY=${newEncryptionKey}`);
  console.log(`  OPENCLAW_PII_HMAC_SECRET=${newHmacSecret}`);
  console.log(`  OPENCLAW_SESSION_SECRET=${newSessionSecret}`);
  console.log(`  OPENCLAW_GATEWAY_TOKEN=${newGatewayToken}`);

  console.log('\n  WARNING: Rotating the encryption key will invalidate');
  console.log('  all existing encrypted sessions and consent records.');
  console.log('  Back up your data before updating.\n');

  auditCritical('key_rotation_requested');
}
