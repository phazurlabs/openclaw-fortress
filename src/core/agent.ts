/**
 * 1.3: Agent Runtime
 * Per-contact agent instances with conversation history and tool execution.
 */
import type { MessageParam } from '@anthropic-ai/sdk/resources/messages.js';
import type { AgentSession, IncomingMessage, ChannelType, ToolDefinition } from '../types/index.js';
import { LLMClient, type LLMResponse, type ToolCall } from './llm.js';
import type { StateManager } from './stateManager.js';
import { auditInfo, auditError } from '../security/auditLogger.js';

const MAX_TOOL_ROUNDS = 5;

export type ToolExecutor = (name: string, input: Record<string, unknown>) => Promise<string>;

export interface AgentOptions {
  llm: LLMClient;
  systemPrompt: string;
  tools?: ToolDefinition[];
  toolExecutor?: ToolExecutor;
  maxContextMessages: number;
  maxSessionAge: number;
  stateManager?: StateManager;
}

export class Agent {
  private llm: LLMClient;
  private systemPrompt: string;
  private tools: ToolDefinition[];
  private toolExecutor?: ToolExecutor;
  private maxContextMessages: number;
  private sessions = new Map<string, AgentSession>();
  private maxSessionAge: number;
  private stateManager?: StateManager;

  constructor(opts: AgentOptions) {
    this.llm = opts.llm;
    this.systemPrompt = opts.systemPrompt;
    this.tools = opts.tools ?? [];
    this.toolExecutor = opts.toolExecutor;
    this.maxContextMessages = opts.maxContextMessages;
    this.maxSessionAge = opts.maxSessionAge;
    this.stateManager = opts.stateManager;
  }

  /**
   * Handle an incoming message and return the agent's response.
   */
  async handleMessage(msg: IncomingMessage): Promise<string> {
    const session = this.getOrCreateSession(msg.contactId, msg.channel);

    // Add user message to history
    session.messages.push({
      role: 'user',
      content: msg.text,
      timestamp: msg.timestamp,
      channel: msg.channel,
      contactId: msg.contactId,
    });

    // Trim history if over limit
    this.trimHistory(session);

    // Build messages for LLM
    const messages: MessageParam[] = session.messages.map(m => ({
      role: m.role,
      content: m.content,
    }));

    try {
      let response = await this.llm.chat({
        systemPrompt: this.systemPrompt,
        messages,
        tools: this.tools,
        maxTokens: undefined,
        temperature: undefined,
      });

      // Tool use loop
      let toolRounds = 0;
      while (response.toolCalls.length > 0 && toolRounds < MAX_TOOL_ROUNDS) {
        toolRounds++;
        const toolResults = await this.executeTools(response.toolCalls, session);

        // Add assistant response (with tool calls) to messages
        messages.push({ role: 'assistant', content: response.content || 'Using tools...' });

        response = await this.llm.continueWithToolResults(
          { systemPrompt: this.systemPrompt, messages, tools: this.tools },
          toolResults,
        );
      }

      const responseText = response.content || 'I apologize, but I was unable to generate a response.';

      // Add assistant response to history
      session.messages.push({
        role: 'assistant',
        content: responseText,
        timestamp: Date.now(),
        channel: msg.channel,
        contactId: msg.contactId,
      });

      session.lastActiveAt = Date.now();
      this.persistSession(session);

      auditInfo('agent_response', {
        channel: msg.channel,
        contactId: msg.contactId,
        sessionId: session.id,
        details: {
          inputTokens: response.inputTokens,
          outputTokens: response.outputTokens,
          toolRounds,
        },
      });

      return responseText;
    } catch (err) {
      auditError('agent_error', {
        channel: msg.channel,
        contactId: msg.contactId,
        sessionId: session.id,
        details: { error: String(err) },
      });
      return 'I encountered an error processing your message. Please try again.';
    }
  }

  /**
   * Get an existing session or create a new one.
   * Checks in-memory cache first, then disk (via StateManager), then creates new.
   */
  private getOrCreateSession(contactId: string, channel: ChannelType): AgentSession {
    const key = `${channel}:${contactId}`;
    let session = this.sessions.get(key);

    if (session && session.expiresAt < Date.now()) {
      this.sessions.delete(key);
      if (this.stateManager) {
        try { this.stateManager.deleteSession(session.id); } catch { /* best effort */ }
      }
      session = undefined;
      auditInfo('session_expired', { channel, contactId });
    }

    // Try disk restore on cache miss
    if (!session && this.stateManager) {
      session = this.tryRestoreFromDisk(key, contactId, channel);
    }

    if (!session) {
      session = {
        id: crypto.randomUUID(),
        agentId: 'default',
        contactId,
        channel,
        messages: [],
        createdAt: Date.now(),
        lastActiveAt: Date.now(),
        expiresAt: Date.now() + this.maxSessionAge * 1000,
        metadata: {},
      };
      this.sessions.set(key, session);
      auditInfo('session_created', { channel, contactId, sessionId: session.id });
    }

    return session;
  }

  /**
   * Try to restore a session from disk by scanning persisted sessions
   * for a matching channel:contactId key.
   */
  private tryRestoreFromDisk(key: string, contactId: string, channel: ChannelType): AgentSession | undefined {
    if (!this.stateManager) return undefined;
    const sessionIds = this.stateManager.listSessions();
    for (const sid of sessionIds) {
      const loaded = this.stateManager.loadSession(sid);
      if (!loaded) continue;
      if (loaded.channel === channel && loaded.contactId === contactId) {
        if (loaded.expiresAt < Date.now()) {
          this.stateManager.deleteSession(sid);
          auditInfo('session_expired', { channel, contactId });
          return undefined;
        }
        this.sessions.set(key, loaded);
        auditInfo('session_restored', { channel, contactId, sessionId: loaded.id });
        return loaded;
      }
    }
    return undefined;
  }

  /**
   * Trim conversation history to maxContextMessages.
   */
  private trimHistory(session: AgentSession): void {
    if (session.messages.length > this.maxContextMessages) {
      const excess = session.messages.length - this.maxContextMessages;
      session.messages.splice(0, excess);
    }
  }

  /**
   * Execute tool calls and return results.
   */
  private async executeTools(
    toolCalls: ToolCall[],
    session: AgentSession,
  ): Promise<Array<{ tool_use_id: string; content: string; is_error?: boolean }>> {
    const results: Array<{ tool_use_id: string; content: string; is_error?: boolean }> = [];

    for (const call of toolCalls) {
      try {
        if (!this.toolExecutor) {
          results.push({
            tool_use_id: call.id,
            content: 'Tool execution not available',
            is_error: true,
          });
          continue;
        }

        auditInfo('tool_execution', {
          sessionId: session.id,
          details: { tool: call.name },
        });

        const result = await this.toolExecutor(call.name, call.input);
        results.push({ tool_use_id: call.id, content: result });
      } catch (err) {
        auditError('tool_execution_failed', {
          sessionId: session.id,
          details: { tool: call.name, error: String(err) },
        });
        results.push({
          tool_use_id: call.id,
          content: `Error: ${err instanceof Error ? err.message : String(err)}`,
          is_error: true,
        });
      }
    }

    return results;
  }

  /**
   * Persist a session to disk via StateManager.
   */
  private persistSession(session: AgentSession): void {
    if (!this.stateManager) return;
    try {
      this.stateManager.saveSession(session);
    } catch (err) {
      auditError('session_persist_failed', {
        sessionId: session.id,
        details: { error: String(err) },
      });
    }
  }

  /**
   * Restore all non-expired sessions from disk into memory.
   * Returns the count of restored sessions.
   */
  restoreAllSessions(): number {
    if (!this.stateManager) return 0;
    const now = Date.now();
    let restored = 0;
    const pruned = this.stateManager.pruneExpiredSessions();
    if (pruned > 0) {
      auditInfo('sessions_pruned_on_startup', { details: { count: pruned } });
    }
    for (const sid of this.stateManager.listSessions()) {
      const session = this.stateManager.loadSession(sid);
      if (!session) continue;
      if (session.expiresAt < now) {
        this.stateManager.deleteSession(sid);
        continue;
      }
      const key = `${session.channel}:${session.contactId}`;
      if (!this.sessions.has(key)) {
        this.sessions.set(key, session);
        restored++;
      }
    }
    return restored;
  }

  /**
   * Clear a specific session (memory + disk).
   */
  clearSession(contactId: string, channel: ChannelType): void {
    const key = `${channel}:${contactId}`;
    const session = this.sessions.get(key);
    if (session && this.stateManager) {
      try { this.stateManager.deleteSession(session.id); } catch { /* best effort */ }
    }
    this.sessions.delete(key);
  }

  /**
   * Clear all sessions (memory + disk).
   */
  clearAllSessions(): void {
    if (this.stateManager) {
      for (const session of this.sessions.values()) {
        try { this.stateManager.deleteSession(session.id); } catch { /* best effort */ }
      }
    }
    this.sessions.clear();
  }

  /**
   * Get session count.
   */
  getSessionCount(): number {
    return this.sessions.size;
  }
}
