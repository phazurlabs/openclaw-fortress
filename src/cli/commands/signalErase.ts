/**
 * CLI: openclaw signal erase-contact
 * GDPR erasure for a Signal contact.
 */
import type { OpenClawConfig } from '../../types/index.js';
import { eraseContact } from '../../security/rightToErasure.js';
import { maskPhone, isValidE164 } from '../../security/piiUtils.js';

export async function signalEraseCommand(config: OpenClawConfig, contactId?: string): Promise<void> {
  if (!contactId) {
    console.error('Usage: openclaw signal erase-contact <phone_number>');
    console.error('  Example: openclaw signal erase-contact +15551234567');
    process.exit(1);
  }

  if (!isValidE164(contactId)) {
    console.error(`Invalid phone number format: ${contactId}`);
    console.error('Must be E.164 format (e.g., +15551234567)');
    process.exit(1);
  }

  console.log(`\n  GDPR Erasure — Article 17\n`);
  console.log(`  Contact: ${maskPhone(contactId)}`);
  console.log('  This will permanently delete ALL data for this contact.\n');

  const result = eraseContact(contactId);

  console.log(`  Files deleted: ${result.filesDeleted}`);
  console.log(`  Locations cleaned: ${result.locations.join(', ') || 'none'}`);
  console.log('\n  Erasure complete.\n');
}
