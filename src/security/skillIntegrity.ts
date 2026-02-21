/**
 * A-04: Skill Integrity
 * SHA256 manifest verification on every execution.
 */
import { createHash } from 'node:crypto';
import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { auditCritical, auditInfo } from './auditLogger.js';
import type { SkillManifest } from '../types/index.js';

/**
 * Compute SHA256 hash of a file.
 */
export function hashFile(filePath: string): string {
  const content = readFileSync(filePath);
  return createHash('sha256').update(content).digest('hex');
}

/**
 * Compute SHA256 hash of a string.
 */
export function hashString(content: string): string {
  return createHash('sha256').update(content).digest('hex');
}

/**
 * Verify a skill's integrity against its manifest hash.
 */
export function verifySkillIntegrity(
  skillDir: string,
  manifest: SkillManifest,
): { valid: boolean; reason?: string } {
  if (!manifest.hash) {
    return { valid: true }; // no hash = no verification (dev mode)
  }

  const entryPath = join(skillDir, manifest.entryPoint);
  if (!existsSync(entryPath)) {
    auditCritical('skill_integrity_missing_entry', {
      details: { skill: manifest.name, path: entryPath },
    });
    return { valid: false, reason: `Entry point not found: ${manifest.entryPoint}` };
  }

  const actualHash = hashFile(entryPath);
  if (actualHash !== manifest.hash) {
    auditCritical('skill_integrity_failed', {
      details: {
        skill: manifest.name,
        expected: manifest.hash,
        actual: actualHash,
      },
    });
    return {
      valid: false,
      reason: `Hash mismatch for ${manifest.name}: expected ${manifest.hash}, got ${actualHash}`,
    };
  }

  auditInfo('skill_integrity_verified', {
    details: { skill: manifest.name },
  });
  return { valid: true };
}

/**
 * Generate and store a manifest hash for a skill entry point.
 */
export function generateManifestHash(skillDir: string, entryPoint: string): string {
  const entryPath = join(skillDir, entryPoint);
  return hashFile(entryPath);
}
