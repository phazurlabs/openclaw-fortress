/**
 * A-02: Audit Logger
 * Structured JSONL audit log with PII scrubbing and CRITICAL alerting.
 */
import { appendFileSync, existsSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { resolvePath } from '../core/config.js';
import { redactPII } from './piiDetector.js';
import type { AuditSeverity, AuditEntry, ChannelType } from '../types/index.js';

let auditLogPath: string = '~/.openclaw/audit.jsonl';

/**
 * Initialize the audit logger with a configured path.
 */
export function initAuditLog(path: string): void {
  auditLogPath = path;
  const resolved = resolvePath(auditLogPath);
  const dir = dirname(resolved);
  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true, mode: 0o700 });
  }
}

/**
 * Write an audit entry. Scrubs PII from all string values in details.
 */
export function audit(
  severity: AuditSeverity,
  event: string,
  opts?: {
    channel?: ChannelType;
    contactId?: string;
    sessionId?: string;
    details?: Record<string, unknown>;
  },
): void {
  const entry: AuditEntry = {
    timestamp: new Date().toISOString(),
    severity,
    event,
    channel: opts?.channel,
    contactId: opts?.contactId ? scrubValue(opts.contactId) : undefined,
    sessionId: opts?.sessionId,
    details: opts?.details ? scrubDetails(opts.details) : undefined,
  };

  const line = JSON.stringify(entry) + '\n';

  try {
    const resolved = resolvePath(auditLogPath);
    appendFileSync(resolved, line, { mode: 0o600 });
  } catch (err) {
    // Fallback to stderr if file write fails
    process.stderr.write(`[AUDIT-FALLBACK] ${line}`);
  }

  // CRITICAL events go to stderr immediately
  if (severity === 'CRITICAL') {
    process.stderr.write(`\x1b[91m[CRITICAL AUDIT] ${event}\x1b[0m\n`);
  }
}

/**
 * Convenience methods.
 */
export const auditInfo = (event: string, opts?: Parameters<typeof audit>[2]) =>
  audit('INFO', event, opts);

export const auditWarn = (event: string, opts?: Parameters<typeof audit>[2]) =>
  audit('WARN', event, opts);

export const auditError = (event: string, opts?: Parameters<typeof audit>[2]) =>
  audit('ERROR', event, opts);

export const auditCritical = (event: string, opts?: Parameters<typeof audit>[2]) =>
  audit('CRITICAL', event, opts);

// ── Internal ─────────────────────────────────────────────────

function scrubValue(value: string): string {
  return redactPII(value);
}

function scrubDetails(details: Record<string, unknown>): Record<string, unknown> {
  const scrubbed: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(details)) {
    if (typeof value === 'string') {
      scrubbed[key] = redactPII(value);
    } else {
      scrubbed[key] = value;
    }
  }
  return scrubbed;
}
