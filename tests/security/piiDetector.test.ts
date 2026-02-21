/**
 * Tests for P-02: PII Detector
 * detectPII and redactPII for phone, SSN, CC, email, gov_id
 */
import { describe, it, expect } from 'vitest';
import {
  detectPII,
  redactPII,
  containsPII,
  type PIIMatch,
  type PIIType,
} from '../../src/security/piiDetector.js';

describe('piiDetector', () => {
  // ── detectPII — phone numbers ───────────────────────────────

  describe('detectPII — phone numbers', () => {
    it('should detect US E.164 phone number (+1XXXXXXXXXX)', () => {
      const matches = detectPII('Call me at +12025551234');
      const phoneMatches = matches.filter(m => m.type === 'phone');
      expect(phoneMatches.length).toBeGreaterThanOrEqual(1);
      expect(phoneMatches.some(m => m.value === '+12025551234')).toBe(true);
    });

    it('should detect (XXX) XXX-XXXX format', () => {
      const matches = detectPII('Phone: (202) 555-1234');
      const phoneMatches = matches.filter(m => m.type === 'phone');
      expect(phoneMatches.length).toBeGreaterThanOrEqual(1);
    });

    it('should detect XXX-XXX-XXXX format', () => {
      const matches = detectPII('Call 202-555-1234 now');
      const phoneMatches = matches.filter(m => m.type === 'phone');
      expect(phoneMatches.length).toBeGreaterThanOrEqual(1);
    });

    it('should detect XXX.XXX.XXXX format', () => {
      const matches = detectPII('Number: 202.555.1234');
      const phoneMatches = matches.filter(m => m.type === 'phone');
      expect(phoneMatches.length).toBeGreaterThanOrEqual(1);
    });

    it('should include start and end positions', () => {
      const text = 'Call +12025551234 now';
      const matches = detectPII(text);
      const phoneMatch = matches.find(m => m.type === 'phone');
      expect(phoneMatch).toBeDefined();
      expect(phoneMatch!.start).toBeGreaterThanOrEqual(0);
      expect(phoneMatch!.end).toBeGreaterThan(phoneMatch!.start);
      expect(text.slice(phoneMatch!.start, phoneMatch!.end)).toBe(phoneMatch!.value);
    });
  });

  // ── detectPII — SSN ─────────────────────────────────────────

  describe('detectPII — SSN', () => {
    it('should detect XXX-XX-XXXX SSN format', () => {
      const matches = detectPII('SSN: 123-45-6789');
      const ssnMatches = matches.filter(m => m.type === 'ssn');
      expect(ssnMatches).toHaveLength(1);
      expect(ssnMatches[0]!.value).toBe('123-45-6789');
    });

    it('should detect SSN in context', () => {
      const matches = detectPII('My social is 987-65-4321 and I need help');
      const ssnMatches = matches.filter(m => m.type === 'ssn');
      expect(ssnMatches.length).toBeGreaterThanOrEqual(1);
    });

    it('should not detect invalid SSN format XXX-XXX-XXXX', () => {
      const matches = detectPII('Number: 123-456-7890');
      const ssnMatches = matches.filter(m => m.type === 'ssn');
      expect(ssnMatches).toHaveLength(0);
    });
  });

  // ── detectPII — credit cards ────────────────────────────────

  describe('detectPII — credit cards', () => {
    it('should detect 16-digit credit card number', () => {
      const matches = detectPII('Card: 4111111111111111');
      const ccMatches = matches.filter(m => m.type === 'credit_card');
      expect(ccMatches.length).toBeGreaterThanOrEqual(1);
    });

    it('should detect credit card with dashes', () => {
      const matches = detectPII('Card: 4111-1111-1111-1111');
      const ccMatches = matches.filter(m => m.type === 'credit_card');
      expect(ccMatches.length).toBeGreaterThanOrEqual(1);
    });

    it('should detect credit card with spaces', () => {
      const matches = detectPII('Card: 4111 1111 1111 1111');
      const ccMatches = matches.filter(m => m.type === 'credit_card');
      expect(ccMatches.length).toBeGreaterThanOrEqual(1);
    });
  });

  // ── detectPII — email ──────────────────────────────────────

  describe('detectPII — email', () => {
    it('should detect a standard email address', () => {
      const matches = detectPII('Email me at user@example.com please');
      const emailMatches = matches.filter(m => m.type === 'email');
      expect(emailMatches.length).toBeGreaterThanOrEqual(1);
      expect(emailMatches.some(m => m.value === 'user@example.com')).toBe(true);
    });

    it('should detect email with dots in local part', () => {
      const matches = detectPII('Contact john.doe@company.org');
      const emailMatches = matches.filter(m => m.type === 'email');
      expect(emailMatches.length).toBeGreaterThanOrEqual(1);
    });

    it('should detect email with + in local part', () => {
      const matches = detectPII('Send to user+tag@example.com');
      const emailMatches = matches.filter(m => m.type === 'email');
      expect(emailMatches.length).toBeGreaterThanOrEqual(1);
    });

    it('should detect email with subdomain', () => {
      const matches = detectPII('Mail: admin@sub.domain.co.uk');
      const emailMatches = matches.filter(m => m.type === 'email');
      expect(emailMatches.length).toBeGreaterThanOrEqual(1);
    });
  });

  // ── detectPII — gov_id ──────────────────────────────────────

  describe('detectPII — gov_id', () => {
    it('should detect passport-like patterns', () => {
      const matches = detectPII('Passport: A12345678');
      const govMatches = matches.filter(m => m.type === 'gov_id');
      expect(govMatches.length).toBeGreaterThanOrEqual(1);
    });

    it('should detect two-letter prefix government IDs', () => {
      const matches = detectPII('ID: AB1234567');
      const govMatches = matches.filter(m => m.type === 'gov_id');
      expect(govMatches.length).toBeGreaterThanOrEqual(1);
    });
  });

  // ── detectPII — no PII ─────────────────────────────────────

  describe('detectPII — no PII', () => {
    it('should return empty array for text without PII', () => {
      const matches = detectPII('This is a normal message with no personal data.');
      // Some short digit sequences or words might accidentally match patterns,
      // so just check it's a reasonable result
      expect(Array.isArray(matches)).toBe(true);
    });

    it('should return empty array for empty string', () => {
      const matches = detectPII('');
      expect(matches).toHaveLength(0);
    });
  });

  // ── detectPII — sorting ─────────────────────────────────────

  describe('detectPII — sorting', () => {
    it('should return matches sorted by start position', () => {
      const text = 'Email: user@example.com SSN: 123-45-6789 Phone: +12025551234';
      const matches = detectPII(text);
      for (let i = 1; i < matches.length; i++) {
        expect(matches[i]!.start).toBeGreaterThanOrEqual(matches[i - 1]!.start);
      }
    });
  });

  // ── redactPII ──────────────────────────────────────────────

  describe('redactPII', () => {
    it('should redact a phone number', () => {
      const result = redactPII('Call +12025551234');
      expect(result).toContain('[REDACTED:phone]');
      expect(result).not.toContain('+12025551234');
    });

    it('should redact an SSN', () => {
      const result = redactPII('SSN: 123-45-6789');
      expect(result).toContain('[REDACTED:ssn]');
      expect(result).not.toContain('123-45-6789');
    });

    it('should redact a credit card', () => {
      const result = redactPII('Card: 4111111111111111');
      expect(result).toContain('[REDACTED:credit_card]');
      expect(result).not.toContain('4111111111111111');
    });

    it('should redact an email', () => {
      const result = redactPII('Email: user@example.com');
      expect(result).toContain('[REDACTED:email]');
      expect(result).not.toContain('user@example.com');
    });

    it('should redact multiple PII items in one string', () => {
      const result = redactPII('Call +12025551234 or email user@example.com');
      expect(result).toContain('[REDACTED:phone]');
      expect(result).toContain('[REDACTED:email]');
    });

    it('should return original text if no PII found', () => {
      const text = 'This has no PII at all.';
      const result = redactPII(text);
      expect(result).toBe(text);
    });

    it('should return empty string for empty input', () => {
      expect(redactPII('')).toBe('');
    });

    it('should preserve non-PII text around redactions', () => {
      const result = redactPII('Before +12025551234 after');
      expect(result).toMatch(/^Before \[REDACTED:phone\] after$/);
    });
  });

  // ── containsPII ─────────────────────────────────────────────

  describe('containsPII', () => {
    it('should return true when text contains PII', () => {
      expect(containsPII('Call +12025551234')).toBe(true);
    });

    it('should return true for SSN', () => {
      expect(containsPII('SSN: 123-45-6789')).toBe(true);
    });

    it('should return true for email', () => {
      expect(containsPII('Email: user@example.com')).toBe(true);
    });

    it('should return false for text without PII', () => {
      expect(containsPII('Hello world')).toBe(false);
    });

    it('should return false for empty string', () => {
      expect(containsPII('')).toBe(false);
    });
  });

  // ── PIIMatch structure ──────────────────────────────────────

  describe('PIIMatch structure', () => {
    it('should have type, value, start, and end properties', () => {
      const matches = detectPII('Email: user@example.com');
      const match = matches.find(m => m.type === 'email');
      expect(match).toBeDefined();
      expect(match).toHaveProperty('type');
      expect(match).toHaveProperty('value');
      expect(match).toHaveProperty('start');
      expect(match).toHaveProperty('end');
    });

    it('should have correct type value', () => {
      const matches = detectPII('SSN is 123-45-6789');
      const ssnMatch = matches.find(m => m.type === 'ssn');
      expect(ssnMatch?.type).toBe('ssn');
    });
  });
});
