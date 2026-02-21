/**
 * P-01: PII Utilities
 * HMAC phone hashing, masking, E.164 validation
 */
import { createHmac } from 'node:crypto';

const E164_REGEX = /^\+[1-9]\d{6,14}$/;

/**
 * Validate an E.164 phone number.
 */
export function isValidE164(phone: string): boolean {
  return E164_REGEX.test(phone);
}

/**
 * HMAC-SHA256 hash a phone number for safe storage/logging.
 * Returns hex string.
 */
export function hashPhone(phone: string, secret: string): string {
  if (!secret) throw new Error('PII HMAC secret is required');
  return createHmac('sha256', secret).update(phone).digest('hex');
}

/**
 * Mask a phone number for display: +1******1234
 */
export function maskPhone(phone: string): string {
  if (!isValidE164(phone)) return '***INVALID***';
  if (phone.length <= 6) return phone.slice(0, 2) + '****';
  const prefix = phone.slice(0, 2);
  const suffix = phone.slice(-4);
  const masked = '*'.repeat(phone.length - 6);
  return `${prefix}${masked}${suffix}`;
}

/**
 * Mask an email address: j***@example.com
 */
export function maskEmail(email: string): string {
  const atIdx = email.indexOf('@');
  if (atIdx <= 0) return '***@***';
  return email[0] + '***' + email.slice(atIdx);
}

/**
 * Mask a generic string, keeping first and last 2 chars.
 */
export function maskGeneric(value: string): string {
  if (value.length <= 4) return '****';
  return value.slice(0, 2) + '*'.repeat(value.length - 4) + value.slice(-2);
}
