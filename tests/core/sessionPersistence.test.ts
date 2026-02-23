/**
 * Tests for Session Persistence via StateManager.
 * Verifies that sessions survive agent recreation (simulated restart).
 */
import { describe, it, expect, beforeEach, vi } from 'vitest';
import { Agent, type AgentOptions, type ToolExecutor } from '../../src/core/agent.js';
import type { LLMClient, LLMResponse } from '../../src/core/llm.js';
import type { IncomingMessage, ChannelType, AgentSession } from '../../src/types/index.js';
import type { StateManager } from '../../src/core/stateManager.js';

// Mock auditLogger
vi.mock('../../src/security/auditLogger.js', () => ({
  auditWarn: vi.fn(),
  auditCritical: vi.fn(),
  auditInfo: vi.fn(),
  auditError: vi.fn(),
  audit: vi.fn(),
}));

function createMockLLM(response?: Partial<LLMResponse>): LLMClient {
  const defaultResponse: LLMResponse = {
    content: 'Hello from OpenClaw Fortress.',
    toolCalls: [],
    stopReason: 'end_turn',
    inputTokens: 100,
    outputTokens: 50,
    ...response,
  };
  return {
    chat: vi.fn(async () => defaultResponse),
    continueWithToolResults: vi.fn(async () => defaultResponse),
  } as unknown as LLMClient;
}

function createIncomingMessage(overrides?: Partial<IncomingMessage>): IncomingMessage {
  return {
    channel: 'signal' as ChannelType,
    contactId: '+12025551234',
    text: 'Hello!',
    timestamp: Date.now(),
    ...overrides,
  };
}

/**
 * Create a mock StateManager backed by an in-memory Map.
 * Simulates encrypted disk persistence without actual file I/O.
 */
function createMockStateManager(): StateManager {
  const store = new Map<string, AgentSession>();

  return {
    saveSession: vi.fn((session: AgentSession) => {
      store.set(session.id, structuredClone(session));
    }),
    loadSession: vi.fn((sessionId: string) => {
      const s = store.get(sessionId);
      return s ? structuredClone(s) : null;
    }),
    deleteSession: vi.fn((sessionId: string) => {
      store.delete(sessionId);
    }),
    listSessions: vi.fn(() => Array.from(store.keys())),
    pruneExpiredSessions: vi.fn(() => {
      let pruned = 0;
      const now = Date.now();
      for (const [id, session] of store.entries()) {
        if (session.expiresAt < now) {
          store.delete(id);
          pruned++;
        }
      }
      return pruned;
    }),
    // Stubs for unused methods
    getAgentDir: vi.fn(),
    ensureAgentDir: vi.fn(),
    deleteAgentDir: vi.fn(),
    listAgents: vi.fn(() => []),
    pruneTranscripts: vi.fn(() => 0),
  } as unknown as StateManager;
}

function createAgentWithStateManager(
  stateManager?: StateManager,
  llm?: LLMClient,
): Agent {
  return new Agent({
    llm: llm ?? createMockLLM(),
    systemPrompt: 'You are a test assistant.',
    maxContextMessages: 20,
    maxSessionAge: 3600,
    stateManager,
  });
}

describe('Session Persistence', () => {
  let stateManager: StateManager;

  beforeEach(() => {
    stateManager = createMockStateManager();
  });

  it('should save session to StateManager after LLM response', async () => {
    const agent = createAgentWithStateManager(stateManager);
    await agent.handleMessage(createIncomingMessage());

    expect(stateManager.saveSession).toHaveBeenCalled();
    const savedSession = vi.mocked(stateManager.saveSession).mock.calls[0][0];
    expect(savedSession.contactId).toBe('+12025551234');
    expect(savedSession.channel).toBe('signal');
    expect(savedSession.messages.length).toBeGreaterThan(0);
  });

  it('should restore sessions from StateManager in a new Agent (simulated restart)', async () => {
    const agent1 = createAgentWithStateManager(stateManager);
    await agent1.handleMessage(createIncomingMessage({ text: 'First message' }));
    expect(agent1.getSessionCount()).toBe(1);

    // Simulate restart: create new Agent with same StateManager
    const agent2 = createAgentWithStateManager(stateManager);
    expect(agent2.getSessionCount()).toBe(0); // not yet restored

    const restored = agent2.restoreAllSessions();
    expect(restored).toBe(1);
    expect(agent2.getSessionCount()).toBe(1);
  });

  it('should prune expired sessions on restore', async () => {
    // Create agent with very short session age
    const shortAgent = new Agent({
      llm: createMockLLM(),
      systemPrompt: 'Test',
      maxContextMessages: 20,
      maxSessionAge: 0, // expires immediately
      stateManager,
    });

    await shortAgent.handleMessage(createIncomingMessage());

    // Wait a tick for expiry
    await new Promise(r => setTimeout(r, 10));

    // New agent should prune on restore
    const agent2 = createAgentWithStateManager(stateManager);
    const restored = agent2.restoreAllSessions();
    expect(restored).toBe(0);
  });

  it('should delete session from disk on clearSession', async () => {
    const agent = createAgentWithStateManager(stateManager);
    await agent.handleMessage(createIncomingMessage());

    agent.clearSession('+12025551234', 'signal');
    expect(stateManager.deleteSession).toHaveBeenCalled();
    expect(agent.getSessionCount()).toBe(0);
  });

  it('should delete all sessions from disk on clearAllSessions', async () => {
    const agent = createAgentWithStateManager(stateManager);
    await agent.handleMessage(createIncomingMessage({ contactId: 'user-1' }));
    await agent.handleMessage(createIncomingMessage({ contactId: 'user-2' }));

    agent.clearAllSessions();
    expect(vi.mocked(stateManager.deleteSession).mock.calls.length).toBe(2);
    expect(agent.getSessionCount()).toBe(0);
  });

  it('should work normally without StateManager (no errors)', async () => {
    const agent = createAgentWithStateManager(undefined);
    const response = await agent.handleMessage(createIncomingMessage());

    expect(response).toBe('Hello from OpenClaw Fortress.');
    expect(agent.getSessionCount()).toBe(1);

    agent.clearSession('+12025551234', 'signal');
    expect(agent.getSessionCount()).toBe(0);
  });

  it('should continue conversation after simulated restart', async () => {
    const mockLLM = createMockLLM();
    const agent1 = createAgentWithStateManager(stateManager, mockLLM);

    await agent1.handleMessage(createIncomingMessage({ text: 'Remember the code is 42' }));

    // Simulate restart
    const mockLLM2 = createMockLLM({ content: 'Yes, the code is 42!' });
    const agent2 = createAgentWithStateManager(stateManager, mockLLM2);
    agent2.restoreAllSessions();

    const response = await agent2.handleMessage(
      createIncomingMessage({ text: 'What was the code?' }),
    );

    expect(response).toBe('Yes, the code is 42!');
    // Verify the LLM was called with conversation history (more than just the new message)
    const chatCall = vi.mocked(mockLLM2.chat).mock.calls[0][0];
    expect(chatCall.messages.length).toBeGreaterThan(1);
  });
});
