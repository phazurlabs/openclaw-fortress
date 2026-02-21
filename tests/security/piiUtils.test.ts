/**
 * Tests for P-01: PII Utilities
 * hashPhone, maskPhone, maskEmail, isValidE164, maskGeneric
 */
import { describe, it, expect } from 'vitest';
import {
  hashPhone,
  maskPhone,
  maskEmail,
  isValidE164,
  maskGeneric,
} from '../../src/security/piiUtils.js';

describe('piiUtils', () => {
  // ── isValidE164 ──────────────────────────────────────────────

  describe('isValidE164', () => {
    it('should accept a standard US E.164 number', () => {
      expect(isValidE164('+12025551234')).toBe(true);
    });

    it('should accept a UK E.164 number', () => {
      expect(isValidE164('+447911123456')).toBe(true);
    });

    it('should accept minimum length E.164 (7 digits after +)', () => {
      expect(isValidE164('+1234567')).toBe(true);
    });

    it('should accept maximum length E.164 (15 digits after +)', () => {
      expect(isValidE164('+123456789012345')).toBe(true);
    });

    it('should reject a number without + prefix', () => {
      expect(isValidE164('12025551234')).toBe(false);
    });

    it('should reject a number starting with +0', () => {
      expect(isValidE164('+0123456789')).toBe(false);
    });

    it('should reject an empty string', () => {
      expect(isValidE164('')).toBe(false);
    });

    it('should reject a number that is too short (fewer than 7 digits)', () => {
      expect(isValidE164('+12345')).toBe(false);
    });

    it('should reject a number that is too long (more than 15 digits)', () => {
      expect(isValidE164('+1234567890123456')).toBe(false);
    });

    it('should reject a number with letters', () => {
      expect(isValidE164('+1202555abcd')).toBe(false);
    });

    it('should reject a number with spaces', () => {
      expect(isValidE164('+1 202 555 1234')).toBe(false);
    });

    it('should reject a number with dashes', () => {
      expect(isValidE164('+1-202-555-1234')).toBe(false);
    });

    it('should reject just a plus sign', () => {
      expect(isValidE164('+')).toBe(false);
    });
  });

  // ── hashPhone ────────────────────────────────────────────────

  describe('hashPhone', () => {
    const secret = 'test-hmac-secret-key';

    it('should return a hex string', () => {
      const hash = hashPhone('+12025551234', secret);
      expect(hash).toMatch(/^[0-9a-f]{64}$/);
    });

    it('should be deterministic (same input produces same hash)', () => {
      const h1 = hashPhone('+12025551234', secret);
      const h2 = hashPhone('+12025551234', secret);
      expect(h1).toBe(h2);
    });

    it('should produce different hashes for different numbers', () => {
      const h1 = hashPhone('+12025551234', secret);
      const h2 = hashPhone('+12025559999', secret);
      expect(h1).not.toBe(h2);
    });

    it('should produce different hashes for different secrets', () => {
      const h1 = hashPhone('+12025551234', 'secret-a');
      const h2 = hashPhone('+12025551234', 'secret-b');
      expect(h1).not.toBe(h2);
    });

    it('should throw if secret is empty', () => {
      expect(() => hashPhone('+12025551234', '')).toThrow('PII HMAC secret is required');
    });

    it('should produce a 64-char hex string (SHA-256)', () => {
      const hash = hashPhone('+12025551234', secret);
      expect(hash.length).toBe(64);
    });
  });

  // ── maskPhone ────────────────────────────────────────────────

  describe('maskPhone', () => {
    it('should mask middle digits of a standard US number', () => {
      const masked = maskPhone('+12025551234');
      expect(masked).toBe('+1******1234');
    });

    it('should return ***INVALID*** for non-E.164 input', () => {
      expect(maskPhone('not-a-number')).toBe('***INVALID***');
    });

    it('should return ***INVALID*** for empty string', () => {
      expect(maskPhone('')).toBe('***INVALID***');
    });

    it('should keep first 2 chars and last 4 chars visible', () => {
      const masked = maskPhone('+447911123456');
      expect(masked.startsWith('+4')).toBe(true);
      expect(masked.endsWith('3456')).toBe(true);
    });

    it('should have correct total length matching original', () => {
      const phone = '+12025551234';
      const masked = maskPhone(phone);
      expect(masked.length).toBe(phone.length);
    });

    it('should mask with asterisks in the middle', () => {
      const masked = maskPhone('+12025551234');
      // +1 (2 chars) + 6 asterisks + 1234 (4 chars) = 12 chars total
      expect(masked).toContain('******');
    });
  });

  // ── maskEmail ────────────────────────────────────────────────

  describe('maskEmail', () => {
    it('should keep first character and domain visible', () => {
      const masked = maskEmail('john@example.com');
      expect(masked).toBe('j***@example.com');
    });

    it('should handle single character local part', () => {
      const masked = maskEmail('j@example.com');
      expect(masked).toBe('j***@example.com');
    });

    it('should return ***@*** for invalid email without @', () => {
      expect(maskEmail('not-an-email')).toBe('***@***');
    });

    it('should return ***@*** for email starting with @', () => {
      expect(maskEmail('@example.com')).toBe('***@***');
    });

    it('should handle long local parts', () => {
      const masked = maskEmail('verylongemail@example.com');
      expect(masked).toBe('v***@example.com');
    });

    it('should preserve the full domain', () => {
      const masked = maskEmail('user@subdomain.example.co.uk');
      expect(masked).toBe('u***@subdomain.example.co.uk');
    });
  });

  // ── maskGeneric ──────────────────────────────────────────────

  describe('maskGeneric', () => {
    it('should mask middle of a long string', () => {
      const masked = maskGeneric('abcdefgh');
      expect(masked).toBe('ab****gh');
    });

    it('should return **** for strings of 4 chars or fewer', () => {
      expect(maskGeneric('abcd')).toBe('****');
      expect(maskGeneric('abc')).toBe('****');
      expect(maskGeneric('ab')).toBe('****');
      expect(maskGeneric('a')).toBe('****');
    });

    it('should keep first 2 and last 2 chars for 5-char string', () => {
      const masked = maskGeneric('abcde');
      expect(masked).toBe('ab*de');
    });

    it('should have correct length for masked output', () => {
      const input = 'helloworld';
      const masked = maskGeneric(input);
      expect(masked.length).toBe(input.length);
    });
  });
});
