/**
 * Skill Runner
 * Execute skill tools with workspace isolation.
 */
import { join } from 'node:path';
import { existsSync } from 'node:fs';
import type { LoadedSkill } from './skillLoader.js';
import { verifySkillIntegrity } from '../security/skillIntegrity.js';
import { auditInfo, auditError, auditCritical } from '../security/auditLogger.js';
import type { ToolExecutor } from '../core/agent.js';

/**
 * Create a tool executor from loaded skills.
 */
export function createToolExecutor(skills: LoadedSkill[]): ToolExecutor {
  // Build a map of tool name → skill
  const toolMap = new Map<string, LoadedSkill>();

  for (const skill of skills) {
    for (const tool of skill.manifest.tools) {
      if (toolMap.has(tool.name)) {
        auditError('skill_tool_conflict', {
          details: { tool: tool.name, skill: skill.manifest.name },
        });
        continue;
      }
      toolMap.set(tool.name, skill);
    }
  }

  return async (toolName: string, input: Record<string, unknown>): Promise<string> => {
    const skill = toolMap.get(toolName);
    if (!skill) {
      throw new Error(`Unknown tool: ${toolName}`);
    }

    // Re-verify integrity before each execution
    const integrity = verifySkillIntegrity(skill.directory, skill.manifest);
    if (!integrity.valid) {
      auditCritical('skill_integrity_failed_at_runtime', {
        details: { skill: skill.manifest.name, tool: toolName, reason: integrity.reason },
      });
      throw new Error(`Skill integrity check failed: ${integrity.reason}`);
    }

    const entryPath = join(skill.directory, skill.manifest.entryPoint);
    if (!existsSync(entryPath)) {
      throw new Error(`Skill entry point not found: ${entryPath}`);
    }

    auditInfo('skill_tool_executing', {
      details: { skill: skill.manifest.name, tool: toolName },
    });

    try {
      // Dynamic import of the skill module
      const mod = await import(entryPath);
      if (typeof mod[toolName] !== 'function') {
        throw new Error(`Tool function '${toolName}' not exported from skill`);
      }

      const result = await mod[toolName](input);
      return typeof result === 'string' ? result : JSON.stringify(result);
    } catch (err) {
      auditError('skill_tool_execution_failed', {
        details: { skill: skill.manifest.name, tool: toolName, error: String(err) },
      });
      throw err;
    }
  };
}
