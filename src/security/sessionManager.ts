/**
 * A-03: Session Manager
 * Crypto-random IDs, channel binding, rotation, expiry.
 */
import { randomBytes } from 'node:crypto';
import { auditInfo, auditWarn } from './auditLogger.js';
import type { ChannelType } from '../types/index.js';

interface ManagedSession {
  id: string;
  contactId: string;
  channel: ChannelType;
  createdAt: number;
  lastActiveAt: number;
  expiresAt: number;
  rotatedFrom?: string;
}

const sessions = new Map<string, ManagedSession>();

/**
 * Generate a cryptographically random session ID (base64url, 32 bytes).
 */
export function generateSessionId(): string {
  return randomBytes(32).toString('base64url');
}

/**
 * Create a new managed session.
 */
export function createSession(
  contactId: string,
  channel: ChannelType,
  maxAgeSeconds: number,
): ManagedSession {
  const now = Date.now();
  const session: ManagedSession = {
    id: generateSessionId(),
    contactId,
    channel,
    createdAt: now,
    lastActiveAt: now,
    expiresAt: now + maxAgeSeconds * 1000,
  };
  sessions.set(session.id, session);
  auditInfo('session_created_managed', { sessionId: session.id, channel, contactId });
  return session;
}

/**
 * Validate a session: exists, not expired, channel+contact binding match.
 */
export function validateSession(
  sessionId: string,
  contactId: string,
  channel: ChannelType,
): { valid: boolean; reason?: string; session?: ManagedSession } {
  const session = sessions.get(sessionId);
  if (!session) {
    return { valid: false, reason: 'Session not found' };
  }

  if (Date.now() > session.expiresAt) {
    sessions.delete(sessionId);
    auditWarn('session_expired_validation', { sessionId });
    return { valid: false, reason: 'Session expired' };
  }

  // Channel binding
  if (session.channel !== channel) {
    auditWarn('session_channel_mismatch', {
      sessionId,
      details: { expected: session.channel, got: channel },
    });
    return { valid: false, reason: 'Channel binding mismatch' };
  }

  // Contact binding
  if (session.contactId !== contactId) {
    auditWarn('session_contact_mismatch', { sessionId, contactId });
    return { valid: false, reason: 'Contact binding mismatch' };
  }

  session.lastActiveAt = Date.now();
  return { valid: true, session };
}

/**
 * Rotate a session (new ID, preserves binding).
 */
export function rotateSession(oldSessionId: string): ManagedSession | null {
  const old = sessions.get(oldSessionId);
  if (!old) return null;

  const newSession: ManagedSession = {
    ...old,
    id: generateSessionId(),
    lastActiveAt: Date.now(),
    rotatedFrom: old.id,
  };

  sessions.delete(oldSessionId);
  sessions.set(newSession.id, newSession);
  auditInfo('session_rotated', {
    sessionId: newSession.id,
    details: { from: oldSessionId },
  });
  return newSession;
}

/**
 * Destroy a session.
 */
export function destroySession(sessionId: string): boolean {
  const existed = sessions.delete(sessionId);
  if (existed) {
    auditInfo('session_destroyed', { sessionId });
  }
  return existed;
}

/**
 * Prune all expired sessions.
 */
export function pruneExpiredSessions(): number {
  const now = Date.now();
  let pruned = 0;
  for (const [id, session] of sessions) {
    if (now > session.expiresAt) {
      sessions.delete(id);
      pruned++;
    }
  }
  return pruned;
}

/**
 * Get active session count.
 */
export function getSessionCount(): number {
  return sessions.size;
}

/**
 * Clear all sessions (for testing).
 */
export function clearAllSessions(): void {
  sessions.clear();
}
