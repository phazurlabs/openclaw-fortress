/**
 * Tests for G-03: SSRF Guard
 * isPrivateIP, validateURL (private IPs, bad schemes, credentials in URL)
 */
import { describe, it, expect, vi } from 'vitest';
import { isPrivateIP, validateURL } from '../../src/security/ssrfGuard.js';

// Mock auditLogger to prevent file I/O during tests
vi.mock('../../src/security/auditLogger.js', () => ({
  auditWarn: vi.fn(),
  auditCritical: vi.fn(),
  auditInfo: vi.fn(),
  auditError: vi.fn(),
  audit: vi.fn(),
}));

describe('ssrfGuard', () => {
  // ── isPrivateIP ──────────────────────────────────────────────

  describe('isPrivateIP', () => {
    // Class A private: 10.0.0.0/8
    it('should detect 10.0.0.0/8 as private', () => {
      expect(isPrivateIP('10.0.0.1')).toBe(true);
      expect(isPrivateIP('10.255.255.255')).toBe(true);
      expect(isPrivateIP('10.128.0.1')).toBe(true);
    });

    // Class B private: 172.16.0.0/12
    it('should detect 172.16.0.0/12 as private', () => {
      expect(isPrivateIP('172.16.0.1')).toBe(true);
      expect(isPrivateIP('172.31.255.255')).toBe(true);
      expect(isPrivateIP('172.20.0.1')).toBe(true);
    });

    it('should not flag 172.32.0.1 as private', () => {
      expect(isPrivateIP('172.32.0.1')).toBe(false);
    });

    // Class C private: 192.168.0.0/16
    it('should detect 192.168.0.0/16 as private', () => {
      expect(isPrivateIP('192.168.0.1')).toBe(true);
      expect(isPrivateIP('192.168.255.255')).toBe(true);
      expect(isPrivateIP('192.168.1.100')).toBe(true);
    });

    // Loopback: 127.0.0.0/8
    it('should detect loopback addresses as private', () => {
      expect(isPrivateIP('127.0.0.1')).toBe(true);
      expect(isPrivateIP('127.255.255.255')).toBe(true);
    });

    // Link-local: 169.254.0.0/16
    it('should detect link-local addresses as private', () => {
      expect(isPrivateIP('169.254.0.1')).toBe(true);
      expect(isPrivateIP('169.254.169.254')).toBe(true); // AWS metadata
    });

    // Zero network: 0.0.0.0/8
    it('should detect 0.0.0.0/8 as private', () => {
      expect(isPrivateIP('0.0.0.0')).toBe(true);
      expect(isPrivateIP('0.255.255.255')).toBe(true);
    });

    // IPv6 loopback
    it('should detect IPv6 loopback ::1 as private', () => {
      expect(isPrivateIP('::1')).toBe(true);
    });

    it('should detect IPv4-mapped IPv6 loopback as private', () => {
      expect(isPrivateIP('::ffff:127.0.0.1')).toBe(true);
    });

    // Public IPs
    it('should not flag public IPs as private', () => {
      expect(isPrivateIP('8.8.8.8')).toBe(false);
      expect(isPrivateIP('1.1.1.1')).toBe(false);
      expect(isPrivateIP('203.0.113.1')).toBe(false);
      expect(isPrivateIP('93.184.216.34')).toBe(false);
    });
  });

  // ── validateURL ──────────────────────────────────────────────

  describe('validateURL', () => {
    // Valid public URLs
    it('should accept a valid HTTPS URL', () => {
      const result = validateURL('https://example.com/api/data');
      expect(result.ok).toBe(true);
      expect(result.parsed).toBeDefined();
      expect(result.parsed!.hostname).toBe('example.com');
    });

    it('should accept a valid HTTP URL', () => {
      const result = validateURL('http://example.com/api');
      expect(result.ok).toBe(true);
    });

    // Invalid URLs
    it('should reject an invalid URL', () => {
      const result = validateURL('not-a-url');
      expect(result.ok).toBe(false);
      expect(result.reason).toBe('Invalid URL');
    });

    it('should reject an empty string', () => {
      const result = validateURL('');
      expect(result.ok).toBe(false);
      expect(result.reason).toBe('Invalid URL');
    });

    // Blocked schemes
    it('should block ftp: scheme', () => {
      const result = validateURL('ftp://example.com/file');
      expect(result.ok).toBe(false);
      expect(result.reason).toContain('Blocked scheme');
    });

    it('should block file: scheme', () => {
      const result = validateURL('file:///etc/passwd');
      expect(result.ok).toBe(false);
      expect(result.reason).toContain('Blocked scheme');
    });

    it('should block javascript: scheme', () => {
      const result = validateURL('javascript:alert(1)');
      expect(result.ok).toBe(false);
    });

    it('should block data: scheme', () => {
      const result = validateURL('data:text/html,<h1>hi</h1>');
      expect(result.ok).toBe(false);
    });

    // Credentials in URL
    it('should reject URL with username', () => {
      const result = validateURL('http://admin@example.com/');
      expect(result.ok).toBe(false);
      expect(result.reason).toBe('Credentials in URL not allowed');
    });

    it('should reject URL with username and password', () => {
      const result = validateURL('http://admin:password@example.com/');
      expect(result.ok).toBe(false);
      expect(result.reason).toBe('Credentials in URL not allowed');
    });

    // Private IP blocking
    it('should block private IP 10.0.0.1', () => {
      const result = validateURL('http://10.0.0.1/admin');
      expect(result.ok).toBe(false);
      expect(result.reason).toContain('Private IP blocked');
    });

    it('should block private IP 192.168.1.1', () => {
      const result = validateURL('http://192.168.1.1:8080/api');
      expect(result.ok).toBe(false);
      expect(result.reason).toContain('Private IP blocked');
    });

    it('should block loopback 127.0.0.1', () => {
      const result = validateURL('http://127.0.0.1:3000/');
      expect(result.ok).toBe(false);
      expect(result.reason).toContain('Private IP blocked');
    });

    it('should block link-local 169.254.169.254 (AWS metadata)', () => {
      const result = validateURL('http://169.254.169.254/latest/meta-data/');
      expect(result.ok).toBe(false);
      expect(result.reason).toContain('Private IP blocked');
    });

    // Localhost hostname blocking
    it('should block localhost hostname', () => {
      const result = validateURL('http://localhost:8080/');
      expect(result.ok).toBe(false);
      expect(result.reason).toContain('Blocked hostname');
    });

    it('should block .local hostname', () => {
      const result = validateURL('http://myserver.local/api');
      expect(result.ok).toBe(false);
      expect(result.reason).toContain('Blocked hostname');
    });

    it('should block .internal hostname', () => {
      const result = validateURL('http://api.internal/v1/data');
      expect(result.ok).toBe(false);
      expect(result.reason).toContain('Blocked hostname');
    });

    // allowPrivate option
    it('should allow private IPs when allowPrivate is true', () => {
      const result = validateURL('http://192.168.1.1/api', { allowPrivate: true });
      expect(result.ok).toBe(true);
    });

    it('should allow localhost when allowPrivate is true', () => {
      const result = validateURL('http://localhost:8080/', { allowPrivate: true });
      expect(result.ok).toBe(true);
    });

    it('should still block bad schemes even with allowPrivate', () => {
      const result = validateURL('ftp://192.168.1.1/file', { allowPrivate: true });
      expect(result.ok).toBe(false);
      expect(result.reason).toContain('Blocked scheme');
    });

    it('should still block credentials even with allowPrivate', () => {
      const result = validateURL('http://user:pass@192.168.1.1/', { allowPrivate: true });
      expect(result.ok).toBe(false);
      expect(result.reason).toBe('Credentials in URL not allowed');
    });
  });
});
