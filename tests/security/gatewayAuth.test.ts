/**
 * Tests for G-01: Gateway Auth
 * verifyToken (timing-safe), checkTokenEntropy, checkRateLimit,
 * authenticateRequest, resetRateLimits, generateToken
 */
import { describe, it, expect, beforeEach, vi } from 'vitest';
import {
  verifyToken,
  checkTokenEntropy,
  checkRateLimit,
  authenticateRequest,
  resetRateLimits,
  generateToken,
} from '../../src/security/gatewayAuth.js';

// Mock auditLogger to prevent file I/O during tests
vi.mock('../../src/security/auditLogger.js', () => ({
  auditWarn: vi.fn(),
  auditCritical: vi.fn(),
  auditInfo: vi.fn(),
  auditError: vi.fn(),
  audit: vi.fn(),
}));

describe('gatewayAuth', () => {
  beforeEach(() => {
    resetRateLimits();
  });

  // ── verifyToken ──────────────────────────────────────────────

  describe('verifyToken', () => {
    it('should return true for matching tokens', () => {
      const token = 'my-secret-token-1234';
      expect(verifyToken(token, token)).toBe(true);
    });

    it('should return false for non-matching tokens of same length', () => {
      expect(verifyToken('aaaa-bbbb-cccc-dddd', 'xxxx-yyyy-zzzz-wwww')).toBe(false);
    });

    it('should return false for non-matching tokens of different length', () => {
      expect(verifyToken('short', 'much-longer-token-here')).toBe(false);
    });

    it('should return false when provided token is empty', () => {
      expect(verifyToken('', 'expected-token')).toBe(false);
    });

    it('should return false when expected token is empty', () => {
      expect(verifyToken('provided-token', '')).toBe(false);
    });

    it('should return false when both tokens are empty', () => {
      expect(verifyToken('', '')).toBe(false);
    });

    it('should handle very long tokens', () => {
      const longToken = 'a'.repeat(1000);
      expect(verifyToken(longToken, longToken)).toBe(true);
    });

    it('should handle tokens with special characters', () => {
      const token = 'tok3n!@#$%^&*()_+-=[]{}|;:,.<>?';
      expect(verifyToken(token, token)).toBe(true);
    });

    it('should handle unicode tokens', () => {
      const token = 'token-with-unicode-\u00e9\u00e8\u00ea';
      expect(verifyToken(token, token)).toBe(true);
    });
  });

  // ── checkTokenEntropy ────────────────────────────────────────

  describe('checkTokenEntropy', () => {
    it('should accept a 64-char hex token (256-bit)', () => {
      const token = 'a'.repeat(64);
      expect(checkTokenEntropy(token)).toBe(true);
    });

    it('should accept a 32-char hex token (128-bit)', () => {
      const token = 'abcdef0123456789abcdef0123456789';
      expect(checkTokenEntropy(token)).toBe(true);
    });

    it('should reject a very short token', () => {
      expect(checkTokenEntropy('short')).toBe(false);
    });

    it('should reject an empty token', () => {
      expect(checkTokenEntropy('')).toBe(false);
    });

    it('should reject a 16-char hex token (only 64-bit)', () => {
      expect(checkTokenEntropy('abcdef0123456789')).toBe(false);
    });

    it('should only count hex characters for entropy', () => {
      // 'zzzzzz' has no hex chars, so entropy is 0
      expect(checkTokenEntropy('zzzzzzzzzzzzzzzz')).toBe(false);
    });

    it('should accept a generated token', () => {
      const token = generateToken(32); // 64 hex chars = 256 bits
      expect(checkTokenEntropy(token)).toBe(true);
    });

    it('should accept mixed-case hex', () => {
      const token = 'AbCdEf0123456789AbCdEf0123456789';
      expect(checkTokenEntropy(token)).toBe(true);
    });
  });

  // ── checkRateLimit ───────────────────────────────────────────

  describe('checkRateLimit', () => {
    it('should allow the first request', () => {
      expect(checkRateLimit('192.168.1.1')).toBe(true);
    });

    it('should allow requests under the limit', () => {
      for (let i = 0; i < 59; i++) {
        expect(checkRateLimit('192.168.1.2')).toBe(true);
      }
    });

    it('should block requests at the default limit (60)', () => {
      for (let i = 0; i < 60; i++) {
        checkRateLimit('192.168.1.3');
      }
      expect(checkRateLimit('192.168.1.3')).toBe(false);
    });

    it('should track limits per IP independently', () => {
      // Fill up IP A
      for (let i = 0; i < 60; i++) {
        checkRateLimit('10.0.0.1');
      }
      // IP B should still be allowed
      expect(checkRateLimit('10.0.0.2')).toBe(true);
    });

    it('should respect custom maxRequests', () => {
      for (let i = 0; i < 5; i++) {
        checkRateLimit('192.168.1.4', 5);
      }
      expect(checkRateLimit('192.168.1.4', 5)).toBe(false);
    });

    it('should reset correctly via resetRateLimits', () => {
      for (let i = 0; i < 60; i++) {
        checkRateLimit('192.168.1.5');
      }
      expect(checkRateLimit('192.168.1.5')).toBe(false);
      resetRateLimits();
      expect(checkRateLimit('192.168.1.5')).toBe(true);
    });
  });

  // ── generateToken ────────────────────────────────────────────

  describe('generateToken', () => {
    it('should generate a hex string of correct length', () => {
      const token = generateToken(32);
      expect(token).toMatch(/^[0-9a-f]{64}$/);
    });

    it('should generate unique tokens', () => {
      const t1 = generateToken();
      const t2 = generateToken();
      expect(t1).not.toBe(t2);
    });

    it('should generate tokens of custom byte length', () => {
      const token = generateToken(16);
      expect(token.length).toBe(32); // 16 bytes = 32 hex chars
    });

    it('should default to 32 bytes (64 hex chars)', () => {
      const token = generateToken();
      expect(token.length).toBe(64);
    });
  });

  // ── authenticateRequest ──────────────────────────────────────

  describe('authenticateRequest', () => {
    const validToken = 'a-valid-secret-token-for-gateway';

    it('should allow when no expectedToken is configured (open gateway)', () => {
      const result = authenticateRequest('anything', undefined, '127.0.0.1');
      expect(result.ok).toBe(true);
    });

    it('should reject when no providedToken is given but expectedToken is set', () => {
      const result = authenticateRequest(undefined, validToken, '127.0.0.1');
      expect(result.ok).toBe(false);
      expect(result.reason).toBe('Missing authentication token');
    });

    it('should allow matching tokens', () => {
      const result = authenticateRequest(validToken, validToken, '127.0.0.1');
      expect(result.ok).toBe(true);
    });

    it('should reject mismatched tokens', () => {
      const result = authenticateRequest('wrong-token', validToken, '127.0.0.1');
      expect(result.ok).toBe(false);
      expect(result.reason).toBe('Invalid authentication token');
    });

    it('should reject when rate limited', () => {
      // Exhaust rate limit
      for (let i = 0; i < 60; i++) {
        authenticateRequest(validToken, validToken, '10.10.10.10');
      }
      const result = authenticateRequest(validToken, validToken, '10.10.10.10');
      expect(result.ok).toBe(false);
      expect(result.reason).toBe('Rate limited');
    });

    it('should not rate-limit before checking token when expectedToken is undefined', () => {
      const result = authenticateRequest('any', undefined, '127.0.0.1');
      expect(result.ok).toBe(true);
      // No rate limit check when no token is expected
    });
  });
});
