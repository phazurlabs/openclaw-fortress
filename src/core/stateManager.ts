/**
 * 1.10: State Management
 * ~/.openclaw/ directory management, agent workspaces, session storage.
 */
import { existsSync, mkdirSync, readdirSync, rmSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { getOpenClawDir, ensureOpenClawDir } from './config.js';
import { writeEncryptedJSON, readEncryptedJSON } from '../security/encryptedStore.js';
import { isValidSessionId, isInsideJail } from '../security/pathSecurity.js';
import { auditInfo, auditWarn } from '../security/auditLogger.js';
import type { AgentSession } from '../types/index.js';

const AGENTS_DIR = 'agents';
const SESSIONS_DIR = 'sessions';

export class StateManager {
  private baseDir: string;
  private encryptionKey: string;

  constructor(encryptionKey: string) {
    this.baseDir = getOpenClawDir();
    this.encryptionKey = encryptionKey;
    this.ensureDirs();
  }

  private ensureDirs(): void {
    ensureOpenClawDir();
    const dirs = [AGENTS_DIR, SESSIONS_DIR, 'skills', 'transcripts'];
    for (const dir of dirs) {
      const full = join(this.baseDir, dir);
      if (!existsSync(full)) {
        mkdirSync(full, { recursive: true, mode: 0o700 });
      }
    }
  }

  // ── Agent Workspaces ────────────────────────────────────────

  getAgentDir(agentId: string): string {
    if (!isValidSessionId(agentId)) throw new Error('Invalid agent ID');
    return join(this.baseDir, AGENTS_DIR, agentId);
  }

  ensureAgentDir(agentId: string): string {
    const dir = this.getAgentDir(agentId);
    if (!existsSync(dir)) {
      mkdirSync(dir, { recursive: true, mode: 0o700 });
    }
    return dir;
  }

  deleteAgentDir(agentId: string): void {
    const dir = this.getAgentDir(agentId);
    if (!isInsideJail(dir, join(this.baseDir, AGENTS_DIR))) {
      throw new Error('Path escape detected');
    }
    if (existsSync(dir)) {
      rmSync(dir, { recursive: true, force: true });
      auditInfo('agent_workspace_deleted', { details: { agentId } });
    }
  }

  listAgents(): string[] {
    const dir = join(this.baseDir, AGENTS_DIR);
    if (!existsSync(dir)) return [];
    return readdirSync(dir).filter(f => {
      const stat = statSync(join(dir, f));
      return stat.isDirectory();
    });
  }

  // ── Sessions ────────────────────────────────────────────────

  saveSession(session: AgentSession): void {
    const filePath = join(this.baseDir, SESSIONS_DIR, `${session.id}.enc`);
    writeEncryptedJSON(filePath, session, this.encryptionKey);
  }

  loadSession(sessionId: string): AgentSession | null {
    if (!isValidSessionId(sessionId)) return null;
    const filePath = join(this.baseDir, SESSIONS_DIR, `${sessionId}.enc`);
    try {
      return readEncryptedJSON<AgentSession>(filePath, this.encryptionKey);
    } catch {
      return null;
    }
  }

  deleteSession(sessionId: string): void {
    if (!isValidSessionId(sessionId)) return;
    const filePath = join(this.baseDir, SESSIONS_DIR, `${sessionId}.enc`);
    const dir = join(this.baseDir, SESSIONS_DIR);
    if (!isInsideJail(filePath, dir)) return;
    if (existsSync(filePath)) {
      rmSync(filePath);
      auditInfo('session_deleted', { sessionId });
    }
  }

  listSessions(): string[] {
    const dir = join(this.baseDir, SESSIONS_DIR);
    if (!existsSync(dir)) return [];
    return readdirSync(dir)
      .filter(f => f.endsWith('.enc'))
      .map(f => f.replace('.enc', ''));
  }

  // ── Auto-prune ──────────────────────────────────────────────

  pruneExpiredSessions(): number {
    let pruned = 0;
    const now = Date.now();
    for (const sid of this.listSessions()) {
      const session = this.loadSession(sid);
      if (session && session.expiresAt < now) {
        this.deleteSession(sid);
        pruned++;
      }
    }
    if (pruned > 0) {
      auditInfo('sessions_pruned', { details: { count: pruned } });
    }
    return pruned;
  }

  /**
   * Prune transcripts older than retentionDays.
   */
  pruneTranscripts(retentionDays: number): number {
    const dir = join(this.baseDir, 'transcripts');
    if (!existsSync(dir)) return 0;
    const cutoff = Date.now() - retentionDays * 86400_000;
    let pruned = 0;
    for (const file of readdirSync(dir)) {
      const filePath = join(dir, file);
      const stat = statSync(filePath);
      if (stat.mtimeMs < cutoff) {
        rmSync(filePath);
        pruned++;
      }
    }
    return pruned;
  }
}
