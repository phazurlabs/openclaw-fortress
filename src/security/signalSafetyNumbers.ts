/**
 * S-03: Signal Safety Numbers
 * Fingerprint tracking, MITM suspension, clearance CLI.
 */
import { existsSync, readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { getOpenClawDir } from '../core/config.js';
import { auditCritical, auditInfo, auditWarn } from './auditLogger.js';

interface SafetyNumberStore {
  contacts: Record<string, {
    fingerprint: string;
    verified: boolean;
    firstSeen: string;
    lastSeen: string;
    suspended: boolean;
  }>;
}

const STORE_FILE = 'safety-numbers.json';

function getStorePath(): string {
  return join(getOpenClawDir(), STORE_FILE);
}

function loadStore(): SafetyNumberStore {
  const path = getStorePath();
  if (!existsSync(path)) return { contacts: {} };
  try {
    return JSON.parse(readFileSync(path, 'utf-8'));
  } catch {
    return { contacts: {} };
  }
}

function saveStore(store: SafetyNumberStore): void {
  const path = getStorePath();
  const dir = dirname(path);
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true, mode: 0o700 });
  writeFileSync(path, JSON.stringify(store, null, 2), { mode: 0o600 });
}

/**
 * Track a safety number for a contact.
 * Returns 'new' | 'unchanged' | 'changed' (MITM alert on 'changed').
 */
export function trackSafetyNumber(
  contactId: string,
  fingerprint: string,
  trustOnFirstUse: boolean,
): 'new' | 'unchanged' | 'changed' {
  const store = loadStore();
  const existing = store.contacts[contactId];
  const now = new Date().toISOString();

  if (!existing) {
    // First time seeing this contact
    store.contacts[contactId] = {
      fingerprint,
      verified: trustOnFirstUse,
      firstSeen: now,
      lastSeen: now,
      suspended: false,
    };
    saveStore(store);
    auditInfo('safety_number_new', { contactId });
    return 'new';
  }

  if (existing.fingerprint === fingerprint) {
    existing.lastSeen = now;
    saveStore(store);
    return 'unchanged';
  }

  // Safety number changed! Possible MITM.
  auditCritical('safety_number_changed', {
    contactId,
    details: {
      oldFingerprint: existing.fingerprint.slice(0, 8) + '...',
      newFingerprint: fingerprint.slice(0, 8) + '...',
    },
  });

  existing.fingerprint = fingerprint;
  existing.verified = false;
  existing.suspended = true;
  existing.lastSeen = now;
  saveStore(store);

  return 'changed';
}

/**
 * Check if a contact is suspended (safety number changed, not re-verified).
 */
export function isContactSuspended(contactId: string): boolean {
  const store = loadStore();
  return store.contacts[contactId]?.suspended ?? false;
}

/**
 * Clear suspension for a contact (after manual verification).
 */
export function clearSuspension(contactId: string): boolean {
  const store = loadStore();
  const contact = store.contacts[contactId];
  if (!contact) return false;
  contact.suspended = false;
  contact.verified = true;
  saveStore(store);
  auditInfo('safety_number_cleared', { contactId });
  return true;
}

/**
 * List all tracked contacts and their safety number status.
 */
export function listTrackedContacts(): Array<{
  contactId: string;
  verified: boolean;
  suspended: boolean;
  firstSeen: string;
  lastSeen: string;
}> {
  const store = loadStore();
  return Object.entries(store.contacts).map(([contactId, info]) => ({
    contactId,
    verified: info.verified,
    suspended: info.suspended,
    firstSeen: info.firstSeen,
    lastSeen: info.lastSeen,
  }));
}
