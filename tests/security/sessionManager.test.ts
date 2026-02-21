/**
 * Tests for A-03: Session Manager
 * createSession, validateSession (binding, expiry), rotateSession,
 * destroySession, clearAllSessions, getSessionCount, pruneExpiredSessions
 */
import { describe, it, expect, beforeEach, vi } from 'vitest';
import {
  createSession,
  validateSession,
  rotateSession,
  destroySession,
  clearAllSessions,
  getSessionCount,
  pruneExpiredSessions,
  generateSessionId,
} from '../../src/security/sessionManager.js';

// Mock auditLogger to prevent file I/O during tests
vi.mock('../../src/security/auditLogger.js', () => ({
  auditWarn: vi.fn(),
  auditCritical: vi.fn(),
  auditInfo: vi.fn(),
  auditError: vi.fn(),
  audit: vi.fn(),
}));

describe('sessionManager', () => {
  beforeEach(() => {
    clearAllSessions();
  });

  // ── generateSessionId ───────────────────────────────────────

  describe('generateSessionId', () => {
    it('should generate a base64url string', () => {
      const id = generateSessionId();
      expect(id).toMatch(/^[A-Za-z0-9_-]+$/);
    });

    it('should generate unique IDs', () => {
      const id1 = generateSessionId();
      const id2 = generateSessionId();
      expect(id1).not.toBe(id2);
    });

    it('should generate IDs of consistent length (~43 chars for 32 bytes base64url)', () => {
      const id = generateSessionId();
      // 32 bytes base64url = 43 chars (no padding)
      expect(id.length).toBe(43);
    });
  });

  // ── createSession ───────────────────────────────────────────

  describe('createSession', () => {
    it('should create a session with correct fields', () => {
      const session = createSession('+12025551234', 'signal', 3600);
      expect(session.id).toBeDefined();
      expect(session.contactId).toBe('+12025551234');
      expect(session.channel).toBe('signal');
      expect(session.createdAt).toBeGreaterThan(0);
      expect(session.lastActiveAt).toBeGreaterThan(0);
      expect(session.expiresAt).toBeGreaterThan(session.createdAt);
    });

    it('should set expiresAt correctly based on maxAgeSeconds', () => {
      const before = Date.now();
      const session = createSession('user-1', 'webchat', 7200);
      const after = Date.now();

      // expiresAt should be approximately now + 7200 * 1000
      expect(session.expiresAt).toBeGreaterThanOrEqual(before + 7200 * 1000);
      expect(session.expiresAt).toBeLessThanOrEqual(after + 7200 * 1000);
    });

    it('should increment session count', () => {
      expect(getSessionCount()).toBe(0);
      createSession('user-1', 'signal', 3600);
      expect(getSessionCount()).toBe(1);
      createSession('user-2', 'discord', 3600);
      expect(getSessionCount()).toBe(2);
    });

    it('should create unique session IDs', () => {
      const s1 = createSession('user-1', 'signal', 3600);
      const s2 = createSession('user-2', 'signal', 3600);
      expect(s1.id).not.toBe(s2.id);
    });
  });

  // ── validateSession ─────────────────────────────────────────

  describe('validateSession', () => {
    it('should validate a valid session', () => {
      const session = createSession('+12025551234', 'signal', 3600);
      const result = validateSession(session.id, '+12025551234', 'signal');
      expect(result.valid).toBe(true);
      expect(result.session).toBeDefined();
      expect(result.session!.id).toBe(session.id);
    });

    it('should reject a non-existent session', () => {
      const result = validateSession('nonexistent-id', 'user', 'signal');
      expect(result.valid).toBe(false);
      expect(result.reason).toBe('Session not found');
    });

    it('should reject an expired session', async () => {
      // Create a session that expires in 1ms
      const session = createSession('user-1', 'signal', 0);
      // Wait to ensure it's expired (Date.now() > expiresAt requires time to pass)
      await new Promise(resolve => setTimeout(resolve, 5));
      const result = validateSession(session.id, 'user-1', 'signal');
      expect(result.valid).toBe(false);
      expect(result.reason).toBe('Session expired');
    });

    it('should reject channel binding mismatch', () => {
      const session = createSession('user-1', 'signal', 3600);
      const result = validateSession(session.id, 'user-1', 'discord');
      expect(result.valid).toBe(false);
      expect(result.reason).toBe('Channel binding mismatch');
    });

    it('should reject contact binding mismatch', () => {
      const session = createSession('user-1', 'signal', 3600);
      const result = validateSession(session.id, 'user-2', 'signal');
      expect(result.valid).toBe(false);
      expect(result.reason).toBe('Contact binding mismatch');
    });

    it('should update lastActiveAt on successful validation', () => {
      const session = createSession('user-1', 'signal', 3600);
      const originalLastActive = session.lastActiveAt;

      // Small delay to ensure time difference
      const result = validateSession(session.id, 'user-1', 'signal');
      expect(result.valid).toBe(true);
      expect(result.session!.lastActiveAt).toBeGreaterThanOrEqual(originalLastActive);
    });

    it('should delete expired session on validation attempt', async () => {
      const session = createSession('user-1', 'signal', 0);
      expect(getSessionCount()).toBe(1);
      // Wait to ensure it's expired
      await new Promise(resolve => setTimeout(resolve, 5));
      validateSession(session.id, 'user-1', 'signal');
      // Expired session should be removed
      expect(getSessionCount()).toBe(0);
    });
  });

  // ── rotateSession ───────────────────────────────────────────

  describe('rotateSession', () => {
    it('should create a new session with a new ID', () => {
      const original = createSession('user-1', 'signal', 3600);
      const rotated = rotateSession(original.id);
      expect(rotated).not.toBeNull();
      expect(rotated!.id).not.toBe(original.id);
    });

    it('should preserve contactId and channel from original', () => {
      const original = createSession('user-1', 'discord', 3600);
      const rotated = rotateSession(original.id);
      expect(rotated!.contactId).toBe('user-1');
      expect(rotated!.channel).toBe('discord');
    });

    it('should set rotatedFrom to the old session ID', () => {
      const original = createSession('user-1', 'signal', 3600);
      const rotated = rotateSession(original.id);
      expect(rotated!.rotatedFrom).toBe(original.id);
    });

    it('should delete the old session', () => {
      const original = createSession('user-1', 'signal', 3600);
      expect(getSessionCount()).toBe(1);
      rotateSession(original.id);
      // Should still be 1 (old deleted, new created)
      expect(getSessionCount()).toBe(1);

      // Old session should not validate
      const oldResult = validateSession(original.id, 'user-1', 'signal');
      expect(oldResult.valid).toBe(false);
    });

    it('should return null for non-existent session', () => {
      const result = rotateSession('does-not-exist');
      expect(result).toBeNull();
    });

    it('should preserve expiresAt from original session', () => {
      const original = createSession('user-1', 'signal', 3600);
      const rotated = rotateSession(original.id);
      expect(rotated!.expiresAt).toBe(original.expiresAt);
    });

    it('new session should validate with same contact and channel', () => {
      const original = createSession('user-1', 'signal', 3600);
      const rotated = rotateSession(original.id);
      const result = validateSession(rotated!.id, 'user-1', 'signal');
      expect(result.valid).toBe(true);
    });
  });

  // ── destroySession ──────────────────────────────────────────

  describe('destroySession', () => {
    it('should destroy an existing session and return true', () => {
      const session = createSession('user-1', 'signal', 3600);
      const result = destroySession(session.id);
      expect(result).toBe(true);
      expect(getSessionCount()).toBe(0);
    });

    it('should return false for non-existent session', () => {
      const result = destroySession('does-not-exist');
      expect(result).toBe(false);
    });

    it('should make session invalid after destruction', () => {
      const session = createSession('user-1', 'signal', 3600);
      destroySession(session.id);
      const result = validateSession(session.id, 'user-1', 'signal');
      expect(result.valid).toBe(false);
      expect(result.reason).toBe('Session not found');
    });
  });

  // ── clearAllSessions ────────────────────────────────────────

  describe('clearAllSessions', () => {
    it('should clear all sessions', () => {
      createSession('user-1', 'signal', 3600);
      createSession('user-2', 'discord', 3600);
      createSession('user-3', 'webchat', 3600);
      expect(getSessionCount()).toBe(3);

      clearAllSessions();
      expect(getSessionCount()).toBe(0);
    });

    it('should be safe to call on empty state', () => {
      clearAllSessions();
      expect(getSessionCount()).toBe(0);
    });
  });

  // ── pruneExpiredSessions ────────────────────────────────────

  describe('pruneExpiredSessions', () => {
    it('should prune expired sessions and return count', async () => {
      createSession('user-1', 'signal', 0); // expires immediately
      createSession('user-2', 'signal', 0); // expires immediately
      createSession('user-3', 'signal', 3600); // valid
      expect(getSessionCount()).toBe(3);

      // Wait to ensure sessions with maxAge=0 have expired
      await new Promise(resolve => setTimeout(resolve, 5));

      const pruned = pruneExpiredSessions();
      expect(pruned).toBe(2);
      expect(getSessionCount()).toBe(1);
    });

    it('should return 0 when no sessions are expired', () => {
      createSession('user-1', 'signal', 3600);
      createSession('user-2', 'signal', 3600);
      const pruned = pruneExpiredSessions();
      expect(pruned).toBe(0);
    });

    it('should return 0 when no sessions exist', () => {
      const pruned = pruneExpiredSessions();
      expect(pruned).toBe(0);
    });
  });

  // ── getSessionCount ─────────────────────────────────────────

  describe('getSessionCount', () => {
    it('should return 0 initially', () => {
      expect(getSessionCount()).toBe(0);
    });

    it('should track session creation and deletion', () => {
      const s1 = createSession('user-1', 'signal', 3600);
      expect(getSessionCount()).toBe(1);
      const s2 = createSession('user-2', 'signal', 3600);
      expect(getSessionCount()).toBe(2);
      destroySession(s1.id);
      expect(getSessionCount()).toBe(1);
      destroySession(s2.id);
      expect(getSessionCount()).toBe(0);
    });
  });
});
