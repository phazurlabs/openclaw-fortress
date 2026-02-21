/**
 * CLI: openclaw security audit
 * View the audit log.
 */
import { readFileSync, existsSync } from 'node:fs';
import type { OpenClawConfig, AuditEntry } from '../../types/index.js';
import { resolvePath } from '../../core/config.js';

export async function auditViewCommand(config: OpenClawConfig): Promise<void> {
  const logPath = resolvePath(config.security.auditLogPath);

  if (!existsSync(logPath)) {
    console.log('No audit log found yet.');
    return;
  }

  const lines = readFileSync(logPath, 'utf-8').trim().split('\n');

  // Show last 50 entries by default
  const tailFlag = process.argv.indexOf('--tail');
  const count = tailFlag !== -1 ? parseInt(process.argv[tailFlag + 1] ?? '50', 10) : 50;
  const entries = lines.slice(-count);

  console.log(`\n  Audit Log (last ${entries.length} entries)\n`);
  console.log('  ─────────────────────────────────────────\n');

  for (const line of entries) {
    try {
      const entry: AuditEntry = JSON.parse(line);
      const severityColor = entry.severity === 'CRITICAL' ? '\x1b[91m'
        : entry.severity === 'ERROR' ? '\x1b[31m'
        : entry.severity === 'WARN' ? '\x1b[33m'
        : '\x1b[90m';
      const time = entry.timestamp.slice(11, 19);
      console.log(`  ${time} ${severityColor}${entry.severity.padEnd(8)}\x1b[0m ${entry.event}`);
    } catch {
      // skip malformed lines
    }
  }

  console.log(`\n  Total entries: ${lines.length}`);
  console.log(`  Log path: ${logPath}\n`);
}
