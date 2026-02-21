/**
 * Tests for G-02: Path Security
 * isValidSessionId, isInsideJail, containsNullByte, validatePath, sanitizePathSegment
 */
import { describe, it, expect } from 'vitest';
import {
  isValidSessionId,
  isInsideJail,
  containsNullByte,
  validatePath,
  sanitizePathSegment,
} from '../../src/security/pathSecurity.js';

describe('pathSecurity', () => {
  // ── isValidSessionId ─────────────────────────────────────────

  describe('isValidSessionId', () => {
    it('should accept a valid alphanumeric session ID', () => {
      expect(isValidSessionId('abc12345')).toBe(true);
    });

    it('should accept a UUID-style session ID with hyphens', () => {
      expect(isValidSessionId('550e8400-e29b-41d4-a716-446655440000')).toBe(true);
    });

    it('should accept an 8-character minimum ID', () => {
      expect(isValidSessionId('abcd1234')).toBe(true);
    });

    it('should accept a 128-character maximum ID', () => {
      expect(isValidSessionId('a'.repeat(128))).toBe(true);
    });

    it('should reject a 7-character ID (too short)', () => {
      expect(isValidSessionId('abcdefg')).toBe(false);
    });

    it('should reject a 129-character ID (too long)', () => {
      expect(isValidSessionId('a'.repeat(129))).toBe(false);
    });

    it('should reject an empty string', () => {
      expect(isValidSessionId('')).toBe(false);
    });

    it('should reject IDs with path traversal (..)', () => {
      expect(isValidSessionId('abc..def12')).toBe(false);
    });

    it('should reject IDs with null bytes', () => {
      expect(isValidSessionId('abcdef12\0')).toBe(false);
    });

    it('should reject IDs with slashes', () => {
      expect(isValidSessionId('abc/def/12345678')).toBe(false);
    });

    it('should reject IDs with spaces', () => {
      expect(isValidSessionId('abc def 12')).toBe(false);
    });

    it('should reject IDs with special characters', () => {
      expect(isValidSessionId('abc@def!12')).toBe(false);
    });

    it('should allow only hyphens as non-alphanumeric chars', () => {
      expect(isValidSessionId('test-session-id-123')).toBe(true);
    });

    it('should reject underscores', () => {
      expect(isValidSessionId('test_session_id')).toBe(false);
    });
  });

  // ── isInsideJail ─────────────────────────────────────────────

  describe('isInsideJail', () => {
    const jailDir = '/var/data/openclaw';

    it('should return true for a path inside the jail', () => {
      expect(isInsideJail('/var/data/openclaw/sessions/abc.json', jailDir)).toBe(true);
    });

    it('should return true for the jail directory itself', () => {
      expect(isInsideJail('/var/data/openclaw', jailDir)).toBe(true);
    });

    it('should return true for nested subdirectories', () => {
      expect(isInsideJail('/var/data/openclaw/a/b/c/d.txt', jailDir)).toBe(true);
    });

    it('should return false for a path outside the jail', () => {
      expect(isInsideJail('/var/data/other/file.txt', jailDir)).toBe(false);
    });

    it('should return false for path traversal escape', () => {
      expect(isInsideJail('/var/data/openclaw/../other/file.txt', jailDir)).toBe(false);
    });

    it('should return false for parent directory', () => {
      expect(isInsideJail('/var/data', jailDir)).toBe(false);
    });

    it('should return false for root directory', () => {
      expect(isInsideJail('/', jailDir)).toBe(false);
    });

    it('should handle trailing slashes consistently', () => {
      expect(isInsideJail('/var/data/openclaw/', '/var/data/openclaw')).toBe(true);
      expect(isInsideJail('/var/data/openclaw', '/var/data/openclaw/')).toBe(true);
    });
  });

  // ── containsNullByte ─────────────────────────────────────────

  describe('containsNullByte', () => {
    it('should return true when input contains a null byte', () => {
      expect(containsNullByte('hello\0world')).toBe(true);
    });

    it('should return true for null byte at start', () => {
      expect(containsNullByte('\0hello')).toBe(true);
    });

    it('should return true for null byte at end', () => {
      expect(containsNullByte('hello\0')).toBe(true);
    });

    it('should return false for a normal string', () => {
      expect(containsNullByte('hello world')).toBe(false);
    });

    it('should return false for an empty string', () => {
      expect(containsNullByte('')).toBe(false);
    });

    it('should return true for just a null byte', () => {
      expect(containsNullByte('\0')).toBe(true);
    });

    it('should detect multiple null bytes', () => {
      expect(containsNullByte('a\0b\0c')).toBe(true);
    });
  });

  // ── sanitizePathSegment ──────────────────────────────────────

  describe('sanitizePathSegment', () => {
    it('should keep alphanumeric characters', () => {
      expect(sanitizePathSegment('abc123')).toBe('abc123');
    });

    it('should keep hyphens, underscores, and periods', () => {
      expect(sanitizePathSegment('file-name_v2.txt')).toBe('file-name_v2.txt');
    });

    it('should strip slashes', () => {
      expect(sanitizePathSegment('path/to/file')).toBe('pathtofile');
    });

    it('should strip null bytes', () => {
      expect(sanitizePathSegment('file\0name')).toBe('filename');
    });

    it('should strip spaces and special characters', () => {
      expect(sanitizePathSegment('file name!@#$%')).toBe('filename');
    });

    it('should return empty string for all-special-chars input', () => {
      expect(sanitizePathSegment('!@#$%^&*()')).toBe('');
    });
  });

  // ── validatePath ─────────────────────────────────────────────

  describe('validatePath', () => {
    const jailDir = '/tmp/test-jail';

    it('should accept a valid path inside the jail', () => {
      const result = validatePath('session.json', jailDir);
      expect(result.ok).toBe(true);
      expect(result.resolved).toBeDefined();
    });

    it('should accept a subdirectory path', () => {
      const result = validatePath('sessions/abc.json', jailDir);
      expect(result.ok).toBe(true);
    });

    it('should reject path with null bytes', () => {
      const result = validatePath('file\0.json', jailDir);
      expect(result.ok).toBe(false);
      expect(result.reason).toBe('Null byte in path');
    });

    it('should reject path traversal with ..', () => {
      const result = validatePath('../etc/passwd', jailDir);
      expect(result.ok).toBe(false);
      expect(result.reason).toBe('Path traversal detected');
    });

    it('should reject deeply nested traversal', () => {
      const result = validatePath('a/b/../../..', jailDir);
      expect(result.ok).toBe(false);
      expect(result.reason).toBe('Path traversal detected');
    });

    it('should reject mid-path traversal', () => {
      const result = validatePath('sessions/../../../etc/shadow', jailDir);
      expect(result.ok).toBe(false);
      expect(result.reason).toBe('Path traversal detected');
    });

    it('should include the resolved path on success', () => {
      const result = validatePath('data.json', jailDir);
      expect(result.ok).toBe(true);
      expect(result.resolved).toContain('test-jail');
      expect(result.resolved).toContain('data.json');
    });

    it('should reject null byte combined with traversal', () => {
      const result = validatePath('file\0../etc/passwd', jailDir);
      expect(result.ok).toBe(false);
      expect(result.reason).toBe('Null byte in path');
    });
  });
});
