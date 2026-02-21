/**
 * 1.8: Skill Loader
 * Load skills from ~/.openclaw/skills/ directories.
 */
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { getOpenClawDir } from '../core/config.js';
import { verifySkillIntegrity } from '../security/skillIntegrity.js';
import { auditInfo, auditWarn, auditError } from '../security/auditLogger.js';
import type { SkillManifest, ToolDefinition } from '../types/index.js';

const SKILLS_DIR = 'skills';
const MANIFEST_FILE = 'manifest.json';

export interface LoadedSkill {
  manifest: SkillManifest;
  directory: string;
}

/**
 * Discover and load all skills from the skills directory.
 */
export function loadSkills(): LoadedSkill[] {
  const skillsDir = join(getOpenClawDir(), SKILLS_DIR);
  if (!existsSync(skillsDir)) return [];

  const loaded: LoadedSkill[] = [];

  for (const entry of readdirSync(skillsDir)) {
    const skillDir = join(skillsDir, entry);
    if (!statSync(skillDir).isDirectory()) continue;

    const manifestPath = join(skillDir, MANIFEST_FILE);
    if (!existsSync(manifestPath)) {
      auditWarn('skill_no_manifest', { details: { dir: entry } });
      continue;
    }

    try {
      const raw = readFileSync(manifestPath, 'utf-8');
      const manifest: SkillManifest = JSON.parse(raw);

      // Verify integrity
      const integrity = verifySkillIntegrity(skillDir, manifest);
      if (!integrity.valid) {
        auditError('skill_integrity_check_failed', {
          details: { skill: manifest.name, reason: integrity.reason },
        });
        continue;
      }

      loaded.push({ manifest, directory: skillDir });
      auditInfo('skill_loaded', { details: { name: manifest.name, version: manifest.version } });
    } catch (err) {
      auditError('skill_load_failed', {
        details: { dir: entry, error: String(err) },
      });
    }
  }

  console.log(`[Skills] Loaded ${loaded.length} skill(s)`);
  return loaded;
}

/**
 * Get all tool definitions from loaded skills.
 */
export function getToolDefinitions(skills: LoadedSkill[]): ToolDefinition[] {
  const tools: ToolDefinition[] = [];
  for (const skill of skills) {
    tools.push(...skill.manifest.tools);
  }
  return tools;
}
