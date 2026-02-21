/**
 * CLI: openclaw signal verify-contacts
 * List and manage Signal safety numbers.
 */
import type { OpenClawConfig } from '../../types/index.js';
import { listTrackedContacts, clearSuspension } from '../../security/signalSafetyNumbers.js';
import { maskPhone } from '../../security/piiUtils.js';

export async function signalVerifyCommand(config: OpenClawConfig): Promise<void> {
  const contacts = listTrackedContacts();

  if (contacts.length === 0) {
    console.log('No Signal contacts tracked yet.');
    return;
  }

  console.log('\n  Signal Safety Numbers\n');
  console.log('  ─────────────────────────────────────────\n');

  for (const c of contacts) {
    const status = c.suspended ? '\x1b[31mSUSPENDED\x1b[0m'
      : c.verified ? '\x1b[32mVERIFIED\x1b[0m'
      : '\x1b[33mUNVERIFIED\x1b[0m';
    console.log(`  ${maskPhone(c.contactId)}  ${status}  (since ${c.firstSeen})`);
  }

  const suspended = contacts.filter(c => c.suspended);
  if (suspended.length > 0) {
    console.log(`\n  ${suspended.length} contact(s) suspended due to safety number changes.`);
    console.log('  Use: openclaw signal verify-contacts --clear <number>');
  }

  // Check for --clear flag
  const clearIdx = process.argv.indexOf('--clear');
  if (clearIdx !== -1) {
    const number = process.argv[clearIdx + 1];
    if (number) {
      const cleared = clearSuspension(number);
      if (cleared) {
        console.log(`\n  Cleared suspension for ${maskPhone(number)}`);
      } else {
        console.log(`\n  Contact not found: ${maskPhone(number)}`);
      }
    }
  }
}
