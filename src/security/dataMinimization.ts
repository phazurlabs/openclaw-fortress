/**
 * E-02: Data Minimization
 * LLM metadata stripping, session pruning.
 */
import type { AgentMessage } from '../types/index.js';
import { auditInfo } from './auditLogger.js';

/**
 * Strip metadata from messages before sending to LLM.
 * Removes contactId, channel info, and other identifying data.
 */
export function stripMetadataForLLM(messages: AgentMessage[]): Array<{ role: string; content: string }> {
  return messages.map(m => ({
    role: m.role,
    content: m.content,
    // Intentionally omitting: timestamp, channel, contactId
  }));
}

/**
 * Prune a conversation to keep only the most recent N messages.
 */
export function pruneConversation(
  messages: AgentMessage[],
  maxMessages: number,
): AgentMessage[] {
  if (messages.length <= maxMessages) return messages;
  const pruned = messages.slice(-maxMessages);
  auditInfo('conversation_pruned', {
    details: {
      original: messages.length,
      remaining: pruned.length,
    },
  });
  return pruned;
}

/**
 * Scrub all PII-like fields from a metadata object before storage.
 */
export function minimizeMetadata(metadata: Record<string, unknown>): Record<string, unknown> {
  const sensitiveKeys = ['ip', 'email', 'phone', 'address', 'ssn', 'name', 'userAgent'];
  const result: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(metadata)) {
    if (sensitiveKeys.includes(key.toLowerCase())) continue;
    result[key] = value;
  }
  return result;
}
