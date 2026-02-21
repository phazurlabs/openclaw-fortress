/**
 * Tests for A-02: Audit Logger
 * audit function writes JSONL, PII scrubbing in details, severity levels
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { readFileSync, mkdtempSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

// We need to mock the config.resolvePath and piiDetector before importing
vi.mock('../../src/core/config.js', () => ({
  resolvePath: vi.fn((p: string) => p),
}));

vi.mock('../../src/security/piiDetector.js', () => ({
  redactPII: vi.fn((text: string) => {
    // Simulate PII redaction for testing
    return text
      .replace(/\+1\d{10}/g, '[REDACTED:phone]')
      .replace(/\b\d{3}-\d{2}-\d{4}\b/g, '[REDACTED:ssn]')
      .replace(/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g, '[REDACTED:email]');
  }),
  detectPII: vi.fn(() => []),
  containsPII: vi.fn(() => false),
}));

import {
  audit,
  auditInfo,
  auditWarn,
  auditError,
  auditCritical,
  initAuditLog,
} from '../../src/security/auditLogger.js';
import { resolvePath } from '../../src/core/config.js';

describe('auditLogger', () => {
  let tmpDir: string;
  let logFile: string;

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), 'openclaw-audit-test-'));
    logFile = join(tmpDir, 'audit.jsonl');
    // Override resolvePath to return the path as-is (already absolute)
    vi.mocked(resolvePath).mockImplementation((p: string) => p);
    initAuditLog(logFile);
  });

  afterEach(() => {
    if (existsSync(tmpDir)) {
      rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  // Helper to read log entries
  function readLogEntries(): Array<Record<string, unknown>> {
    if (!existsSync(logFile)) return [];
    const content = readFileSync(logFile, 'utf-8');
    return content
      .trim()
      .split('\n')
      .filter(Boolean)
      .map(line => JSON.parse(line));
  }

  // ── Basic logging ───────────────────────────────────────────

  describe('basic logging', () => {
    it('should write a JSONL entry to the audit log', () => {
      audit('INFO', 'test_event');
      const entries = readLogEntries();
      expect(entries).toHaveLength(1);
      expect(entries[0]!['event']).toBe('test_event');
      expect(entries[0]!['severity']).toBe('INFO');
    });

    it('should include a timestamp in ISO format', () => {
      audit('INFO', 'timestamp_test');
      const entries = readLogEntries();
      expect(entries[0]!['timestamp']).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/);
    });

    it('should write multiple entries as separate lines', () => {
      audit('INFO', 'event_1');
      audit('WARN', 'event_2');
      audit('ERROR', 'event_3');
      const entries = readLogEntries();
      expect(entries).toHaveLength(3);
      expect(entries[0]!['event']).toBe('event_1');
      expect(entries[1]!['event']).toBe('event_2');
      expect(entries[2]!['event']).toBe('event_3');
    });
  });

  // ── Severity levels ─────────────────────────────────────────

  describe('severity levels', () => {
    it('should log INFO severity', () => {
      auditInfo('info_event');
      const entries = readLogEntries();
      expect(entries[0]!['severity']).toBe('INFO');
    });

    it('should log WARN severity', () => {
      auditWarn('warn_event');
      const entries = readLogEntries();
      expect(entries[0]!['severity']).toBe('WARN');
    });

    it('should log ERROR severity', () => {
      auditError('error_event');
      const entries = readLogEntries();
      expect(entries[0]!['severity']).toBe('ERROR');
    });

    it('should log CRITICAL severity', () => {
      // Capture stderr to avoid test noise
      const stderrSpy = vi.spyOn(process.stderr, 'write').mockReturnValue(true);
      auditCritical('critical_event');
      const entries = readLogEntries();
      expect(entries[0]!['severity']).toBe('CRITICAL');
      stderrSpy.mockRestore();
    });

    it('should write CRITICAL events to stderr', () => {
      const stderrSpy = vi.spyOn(process.stderr, 'write').mockReturnValue(true);
      auditCritical('security_breach');
      expect(stderrSpy).toHaveBeenCalledWith(
        expect.stringContaining('[CRITICAL AUDIT] security_breach'),
      );
      stderrSpy.mockRestore();
    });
  });

  // ── Optional fields ─────────────────────────────────────────

  describe('optional fields', () => {
    it('should include channel when provided', () => {
      audit('INFO', 'channel_test', { channel: 'signal' });
      const entries = readLogEntries();
      expect(entries[0]!['channel']).toBe('signal');
    });

    it('should include sessionId when provided', () => {
      audit('INFO', 'session_test', { sessionId: 'sess-123' });
      const entries = readLogEntries();
      expect(entries[0]!['sessionId']).toBe('sess-123');
    });

    it('should include details when provided', () => {
      audit('INFO', 'details_test', { details: { key: 'value', count: 5 } });
      const entries = readLogEntries();
      const details = entries[0]!['details'] as Record<string, unknown>;
      expect(details['key']).toBe('value');
      expect(details['count']).toBe(5);
    });

    it('should omit undefined optional fields', () => {
      audit('INFO', 'minimal_test');
      const entries = readLogEntries();
      expect(entries[0]!['channel']).toBeUndefined();
      expect(entries[0]!['contactId']).toBeUndefined();
      expect(entries[0]!['sessionId']).toBeUndefined();
      expect(entries[0]!['details']).toBeUndefined();
    });
  });

  // ── PII scrubbing ──────────────────────────────────────────

  describe('PII scrubbing', () => {
    it('should scrub phone numbers from contactId', () => {
      audit('INFO', 'pii_test', { contactId: '+12025551234' });
      const entries = readLogEntries();
      expect(entries[0]!['contactId']).toBe('[REDACTED:phone]');
    });

    it('should scrub phone numbers from string values in details', () => {
      audit('INFO', 'pii_details_test', {
        details: { sender: '+12025551234' },
      });
      const entries = readLogEntries();
      const details = entries[0]!['details'] as Record<string, unknown>;
      expect(details['sender']).toBe('[REDACTED:phone]');
    });

    it('should scrub email addresses from string values in details', () => {
      audit('INFO', 'pii_email_test', {
        details: { email: 'user@example.com' },
      });
      const entries = readLogEntries();
      const details = entries[0]!['details'] as Record<string, unknown>;
      expect(details['email']).toBe('[REDACTED:email]');
    });

    it('should not modify non-string values in details', () => {
      audit('INFO', 'pii_nonstring_test', {
        details: { count: 42, active: true },
      });
      const entries = readLogEntries();
      const details = entries[0]!['details'] as Record<string, unknown>;
      expect(details['count']).toBe(42);
      expect(details['active']).toBe(true);
    });

    it('should scrub SSN from details', () => {
      audit('INFO', 'pii_ssn_test', {
        details: { note: 'SSN is 123-45-6789' },
      });
      const entries = readLogEntries();
      const details = entries[0]!['details'] as Record<string, unknown>;
      expect(details['note']).toBe('SSN is [REDACTED:ssn]');
    });
  });

  // ── Convenience methods ─────────────────────────────────────

  describe('convenience methods', () => {
    it('auditInfo should pass options through', () => {
      auditInfo('info_with_opts', { channel: 'webchat', sessionId: 'abc' });
      const entries = readLogEntries();
      expect(entries[0]!['severity']).toBe('INFO');
      expect(entries[0]!['channel']).toBe('webchat');
      expect(entries[0]!['sessionId']).toBe('abc');
    });

    it('auditWarn should pass options through', () => {
      auditWarn('warn_with_opts', { details: { reason: 'test' } });
      const entries = readLogEntries();
      expect(entries[0]!['severity']).toBe('WARN');
    });

    it('auditError should pass options through', () => {
      auditError('error_with_opts', { contactId: 'user-123' });
      const entries = readLogEntries();
      expect(entries[0]!['severity']).toBe('ERROR');
    });
  });
});
