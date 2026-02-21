/**
 * E-01: PII Consent
 * Per-contact consent store (encrypted).
 */
import { join } from 'node:path';
import { getOpenClawDir } from '../core/config.js';
import { writeEncryptedJSON, readEncryptedJSON } from './encryptedStore.js';
import { auditInfo } from './auditLogger.js';
import { existsSync } from 'node:fs';

interface ConsentRecord {
  contactId: string;
  consentGiven: boolean;
  consentDate: string;
  purposes: string[];
  version: string;
}

interface ConsentStore {
  records: Record<string, ConsentRecord>;
}

const CONSENT_FILE = 'consent.enc';

function getConsentPath(): string {
  return join(getOpenClawDir(), CONSENT_FILE);
}

function loadConsents(encryptionKey: string): ConsentStore {
  const path = getConsentPath();
  if (!existsSync(path)) return { records: {} };
  try {
    return readEncryptedJSON<ConsentStore>(path, encryptionKey);
  } catch {
    return { records: {} };
  }
}

function saveConsents(store: ConsentStore, encryptionKey: string): void {
  writeEncryptedJSON(getConsentPath(), store, encryptionKey);
}

/**
 * Record consent for a contact.
 */
export function recordConsent(
  contactId: string,
  purposes: string[],
  encryptionKey: string,
): void {
  const store = loadConsents(encryptionKey);
  store.records[contactId] = {
    contactId,
    consentGiven: true,
    consentDate: new Date().toISOString(),
    purposes,
    version: '1.0',
  };
  saveConsents(store, encryptionKey);
  auditInfo('consent_recorded', { contactId, details: { purposes } });
}

/**
 * Check if a contact has given consent.
 */
export function hasConsent(contactId: string, encryptionKey: string): boolean {
  const store = loadConsents(encryptionKey);
  return store.records[contactId]?.consentGiven === true;
}

/**
 * Withdraw consent for a contact.
 */
export function withdrawConsent(contactId: string, encryptionKey: string): void {
  const store = loadConsents(encryptionKey);
  const record = store.records[contactId];
  if (record) {
    record.consentGiven = false;
    saveConsents(store, encryptionKey);
    auditInfo('consent_withdrawn', { contactId });
  }
}

/**
 * Get consent record for a contact.
 */
export function getConsentRecord(
  contactId: string,
  encryptionKey: string,
): ConsentRecord | null {
  const store = loadConsents(encryptionKey);
  return store.records[contactId] ?? null;
}
