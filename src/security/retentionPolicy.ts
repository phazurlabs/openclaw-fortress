/**
 * E-04: Retention Policy
 * Configurable TTLs, auto-expiry, secure deletion.
 */
import { existsSync, readdirSync, rmSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { getOpenClawDir } from '../core/config.js';
import { auditInfo } from './auditLogger.js';

export interface RetentionConfig {
  sessionTTLDays: number;
  transcriptTTLDays: number;
  auditLogTTLDays: number;
}

const DEFAULT_RETENTION: RetentionConfig = {
  sessionTTLDays: 30,
  transcriptTTLDays: 90,
  auditLogTTLDays: 365,
};

/**
 * Run retention policy enforcement.
 * Returns total number of files cleaned up.
 */
export function enforceRetention(config: Partial<RetentionConfig> = {}): {
  totalPurged: number;
  breakdown: Record<string, number>;
} {
  const retention = { ...DEFAULT_RETENTION, ...config };
  const baseDir = getOpenClawDir();
  const breakdown: Record<string, number> = {};

  // Sessions
  breakdown['sessions'] = purgeDir(
    join(baseDir, 'sessions'),
    retention.sessionTTLDays,
  );

  // Transcripts
  breakdown['transcripts'] = purgeDir(
    join(baseDir, 'transcripts'),
    retention.transcriptTTLDays,
  );

  const totalPurged = Object.values(breakdown).reduce((a, b) => a + b, 0);

  if (totalPurged > 0) {
    auditInfo('retention_enforced', {
      details: { totalPurged, breakdown },
    });
  }

  return { totalPurged, breakdown };
}

/**
 * Purge files older than TTL days from a directory.
 */
function purgeDir(dirPath: string, ttlDays: number): number {
  if (!existsSync(dirPath)) return 0;

  const cutoff = Date.now() - ttlDays * 86400_000;
  let purged = 0;

  for (const file of readdirSync(dirPath)) {
    const filePath = join(dirPath, file);
    try {
      const stat = statSync(filePath);
      if (stat.isFile() && stat.mtimeMs < cutoff) {
        rmSync(filePath);
        purged++;
      }
    } catch { /* skip unreadable files */ }
  }

  return purged;
}
