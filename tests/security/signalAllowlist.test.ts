/**
 * Tests for S-02: Signal Allowlist
 * isNumberAllowed, isGroupAllowed, checkAllowlist, resetContactRateLimits
 */
import { describe, it, expect, beforeEach, vi } from 'vitest';
import {
  isNumberAllowed,
  isGroupAllowed,
  checkAllowlist,
  resetContactRateLimits,
  type AllowlistConfig,
} from '../../src/security/signalAllowlist.js';

// Mock auditLogger to prevent file I/O during tests
vi.mock('../../src/security/auditLogger.js', () => ({
  auditWarn: vi.fn(),
  auditCritical: vi.fn(),
  auditInfo: vi.fn(),
  auditError: vi.fn(),
  audit: vi.fn(),
}));

describe('signalAllowlist', () => {
  beforeEach(() => {
    resetContactRateLimits();
  });

  // ── isNumberAllowed ──────────────────────────────────────────

  describe('isNumberAllowed', () => {
    it('should allow any number when allowlist is empty (open mode)', () => {
      expect(isNumberAllowed('+12025551234', [])).toBe(true);
    });

    it('should allow a number that is on the allowlist', () => {
      const allowed = ['+12025551234', '+12025559999'];
      expect(isNumberAllowed('+12025551234', allowed)).toBe(true);
    });

    it('should reject a number that is not on the allowlist', () => {
      const allowed = ['+12025551234', '+12025559999'];
      expect(isNumberAllowed('+10000000000', allowed)).toBe(false);
    });

    it('should be case sensitive / exact match', () => {
      const allowed = ['+12025551234'];
      expect(isNumberAllowed('+1202555123', allowed)).toBe(false);
    });
  });

  // ── isGroupAllowed ──────────────────────────────────────────

  describe('isGroupAllowed', () => {
    it('should allow any group when allowlist is empty (open mode)', () => {
      expect(isGroupAllowed('any-group-id', [])).toBe(true);
    });

    it('should allow a group on the allowlist', () => {
      const allowed = ['group-abc', 'group-xyz'];
      expect(isGroupAllowed('group-abc', allowed)).toBe(true);
    });

    it('should reject a group not on the allowlist', () => {
      const allowed = ['group-abc', 'group-xyz'];
      expect(isGroupAllowed('group-unknown', allowed)).toBe(false);
    });
  });

  // ── checkAllowlist ──────────────────────────────────────────

  describe('checkAllowlist', () => {
    const openConfig: AllowlistConfig = {
      allowedNumbers: [],
      allowedGroups: [],
      rateLimitPerMinute: 30,
    };

    const restrictedConfig: AllowlistConfig = {
      allowedNumbers: ['+12025551234', '+12025559999'],
      allowedGroups: ['group-alpha', 'group-beta'],
      rateLimitPerMinute: 30,
    };

    // DM messages (no groupId)
    it('should allow a DM from an allowed number', () => {
      const result = checkAllowlist('+12025551234', undefined, restrictedConfig);
      expect(result.allowed).toBe(true);
    });

    it('should block a DM from a non-allowed number', () => {
      const result = checkAllowlist('+10000000000', undefined, restrictedConfig);
      expect(result.allowed).toBe(false);
      expect(result.reason).toBe('Number not in allowlist');
    });

    it('should allow all DMs in open mode', () => {
      const result = checkAllowlist('+19999999999', undefined, openConfig);
      expect(result.allowed).toBe(true);
    });

    // Group messages
    it('should allow a group message from an allowed group and sender', () => {
      const result = checkAllowlist('+12025551234', 'group-alpha', restrictedConfig);
      expect(result.allowed).toBe(true);
    });

    it('should block a group message from a non-allowed group', () => {
      const result = checkAllowlist('+12025551234', 'group-unknown', restrictedConfig);
      expect(result.allowed).toBe(false);
      expect(result.reason).toBe('Group not in allowlist');
    });

    it('should block when group is allowed but sender is not', () => {
      const result = checkAllowlist('+10000000000', 'group-alpha', restrictedConfig);
      expect(result.allowed).toBe(false);
      expect(result.reason).toBe('Number not in allowlist');
    });

    // Rate limiting
    it('should rate limit a sender after exceeding the per-minute limit', () => {
      const lowLimitConfig: AllowlistConfig = {
        allowedNumbers: [],
        allowedGroups: [],
        rateLimitPerMinute: 3,
      };

      // First 3 should pass
      expect(checkAllowlist('+12025551111', undefined, lowLimitConfig).allowed).toBe(true);
      expect(checkAllowlist('+12025551111', undefined, lowLimitConfig).allowed).toBe(true);
      expect(checkAllowlist('+12025551111', undefined, lowLimitConfig).allowed).toBe(true);

      // 4th should be rate limited
      const result = checkAllowlist('+12025551111', undefined, lowLimitConfig);
      expect(result.allowed).toBe(false);
      expect(result.reason).toBe('Rate limited');
    });

    it('should not rate limit different senders independently', () => {
      const lowLimitConfig: AllowlistConfig = {
        allowedNumbers: [],
        allowedGroups: [],
        rateLimitPerMinute: 2,
      };

      // Fill up sender A
      checkAllowlist('+1111', undefined, lowLimitConfig);
      checkAllowlist('+1111', undefined, lowLimitConfig);
      expect(checkAllowlist('+1111', undefined, lowLimitConfig).allowed).toBe(false);

      // Sender B should still be fine
      expect(checkAllowlist('+2222', undefined, lowLimitConfig).allowed).toBe(true);
    });

    it('should check group before number (group blocked first)', () => {
      const config: AllowlistConfig = {
        allowedNumbers: ['+12025551234'],
        allowedGroups: ['group-only'],
        rateLimitPerMinute: 30,
      };
      // Allowed number, but blocked group
      const result = checkAllowlist('+12025551234', 'wrong-group', config);
      expect(result.allowed).toBe(false);
      expect(result.reason).toBe('Group not in allowlist');
    });
  });

  // ── resetContactRateLimits ──────────────────────────────────

  describe('resetContactRateLimits', () => {
    it('should reset rate limits allowing previously blocked sender', () => {
      const config: AllowlistConfig = {
        allowedNumbers: [],
        allowedGroups: [],
        rateLimitPerMinute: 1,
      };

      checkAllowlist('+12025551234', undefined, config);
      expect(checkAllowlist('+12025551234', undefined, config).allowed).toBe(false);

      resetContactRateLimits();

      expect(checkAllowlist('+12025551234', undefined, config).allowed).toBe(true);
    });
  });
});
