/**
 * Tests for 1.3: Agent Runtime
 * Test Agent class creation with mocked LLM.
 */
import { describe, it, expect, beforeEach, vi } from 'vitest';
import { Agent, type AgentOptions, type ToolExecutor } from '../../src/core/agent.js';
import type { LLMClient, LLMResponse } from '../../src/core/llm.js';
import type { IncomingMessage, ChannelType } from '../../src/types/index.js';

// Mock auditLogger to prevent file I/O during tests
vi.mock('../../src/security/auditLogger.js', () => ({
  auditWarn: vi.fn(),
  auditCritical: vi.fn(),
  auditInfo: vi.fn(),
  auditError: vi.fn(),
  audit: vi.fn(),
}));

// Create a mock LLM client
function createMockLLM(response?: Partial<LLMResponse>): LLMClient {
  const defaultResponse: LLMResponse = {
    content: 'Hello! I am the AI assistant.',
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

describe('Agent', () => {
  let mockLLM: LLMClient;
  let agent: Agent;

  beforeEach(() => {
    mockLLM = createMockLLM();
    agent = new Agent({
      llm: mockLLM,
      systemPrompt: 'You are a test assistant.',
      maxContextMessages: 20,
      maxSessionAge: 3600,
    });
  });

  // ── Constructor ─────────────────────────────────────────────

  describe('constructor', () => {
    it('should create an agent instance', () => {
      expect(agent).toBeInstanceOf(Agent);
    });

    it('should accept tools and toolExecutor', () => {
      const toolExecutor: ToolExecutor = vi.fn(async () => 'tool result');
      const agentWithTools = new Agent({
        llm: mockLLM,
        systemPrompt: 'Test',
        tools: [{ name: 'test_tool', description: 'A test tool', input_schema: {} }],
        toolExecutor,
        maxContextMessages: 20,
        maxSessionAge: 3600,
      });
      expect(agentWithTools).toBeInstanceOf(Agent);
    });

    it('should start with zero sessions', () => {
      expect(agent.getSessionCount()).toBe(0);
    });
  });

  // ── handleMessage ───────────────────────────────────────────

  describe('handleMessage', () => {
    it('should return a response from the LLM', async () => {
      const msg = createIncomingMessage();
      const response = await agent.handleMessage(msg);
      expect(response).toBe('Hello! I am the AI assistant.');
    });

    it('should call the LLM chat method', async () => {
      const msg = createIncomingMessage();
      await agent.handleMessage(msg);
      expect(mockLLM.chat).toHaveBeenCalledTimes(1);
    });

    it('should pass the system prompt to the LLM', async () => {
      const msg = createIncomingMessage();
      await agent.handleMessage(msg);
      expect(mockLLM.chat).toHaveBeenCalledWith(
        expect.objectContaining({
          systemPrompt: 'You are a test assistant.',
        }),
      );
    });

    it('should create a session on first message', async () => {
      expect(agent.getSessionCount()).toBe(0);
      await agent.handleMessage(createIncomingMessage());
      expect(agent.getSessionCount()).toBe(1);
    });

    it('should reuse session for same contact and channel', async () => {
      const msg1 = createIncomingMessage({ text: 'First message' });
      const msg2 = createIncomingMessage({ text: 'Second message' });

      await agent.handleMessage(msg1);
      await agent.handleMessage(msg2);
      expect(agent.getSessionCount()).toBe(1);
    });

    it('should create separate sessions for different contacts', async () => {
      await agent.handleMessage(createIncomingMessage({ contactId: 'user-1' }));
      await agent.handleMessage(createIncomingMessage({ contactId: 'user-2' }));
      expect(agent.getSessionCount()).toBe(2);
    });

    it('should create separate sessions for different channels', async () => {
      await agent.handleMessage(createIncomingMessage({ channel: 'signal', contactId: 'user-1' }));
      await agent.handleMessage(createIncomingMessage({ channel: 'discord', contactId: 'user-1' }));
      expect(agent.getSessionCount()).toBe(2);
    });

    it('should return error message on LLM failure', async () => {
      const failingLLM = createMockLLM();
      vi.mocked(failingLLM.chat).mockRejectedValue(new Error('API error'));

      const failAgent = new Agent({
        llm: failingLLM,
        systemPrompt: 'Test',
        maxContextMessages: 20,
        maxSessionAge: 3600,
      });

      const response = await failAgent.handleMessage(createIncomingMessage());
      expect(response).toContain('error');
    });

    it('should handle empty LLM response gracefully', async () => {
      const emptyLLM = createMockLLM({ content: '' });
      const emptyAgent = new Agent({
        llm: emptyLLM,
        systemPrompt: 'Test',
        maxContextMessages: 20,
        maxSessionAge: 3600,
      });

      const response = await emptyAgent.handleMessage(createIncomingMessage());
      expect(response).toBeTruthy(); // Should return fallback message
    });
  });

  // ── Tool execution ──────────────────────────────────────────

  describe('tool execution', () => {
    it('should execute tools when LLM returns tool calls', async () => {
      const toolExecutor: ToolExecutor = vi.fn(async () => 'tool result');

      const toolCallResponse: LLMResponse = {
        content: '',
        toolCalls: [{ id: 'call-1', name: 'test_tool', input: { query: 'test' } }],
        stopReason: 'tool_use',
        inputTokens: 100,
        outputTokens: 50,
      };

      const finalResponse: LLMResponse = {
        content: 'Based on the tool result...',
        toolCalls: [],
        stopReason: 'end_turn',
        inputTokens: 150,
        outputTokens: 80,
      };

      const toolLLM = createMockLLM();
      vi.mocked(toolLLM.chat).mockResolvedValueOnce(toolCallResponse);
      vi.mocked(toolLLM.continueWithToolResults).mockResolvedValueOnce(finalResponse);

      const toolAgent = new Agent({
        llm: toolLLM,
        systemPrompt: 'Test',
        tools: [{ name: 'test_tool', description: 'A test tool', input_schema: {} }],
        toolExecutor,
        maxContextMessages: 20,
        maxSessionAge: 3600,
      });

      const response = await toolAgent.handleMessage(createIncomingMessage());
      expect(toolExecutor).toHaveBeenCalledWith('test_tool', { query: 'test' });
      expect(response).toBe('Based on the tool result...');
    });

    it('should handle tool execution errors gracefully', async () => {
      const failingToolExecutor: ToolExecutor = vi.fn(async () => {
        throw new Error('Tool failed');
      });

      const toolCallResponse: LLMResponse = {
        content: '',
        toolCalls: [{ id: 'call-1', name: 'failing_tool', input: {} }],
        stopReason: 'tool_use',
        inputTokens: 100,
        outputTokens: 50,
      };

      const finalResponse: LLMResponse = {
        content: 'I encountered an issue with the tool.',
        toolCalls: [],
        stopReason: 'end_turn',
        inputTokens: 150,
        outputTokens: 80,
      };

      const toolLLM = createMockLLM();
      vi.mocked(toolLLM.chat).mockResolvedValueOnce(toolCallResponse);
      vi.mocked(toolLLM.continueWithToolResults).mockResolvedValueOnce(finalResponse);

      const toolAgent = new Agent({
        llm: toolLLM,
        systemPrompt: 'Test',
        tools: [{ name: 'failing_tool', description: 'A tool that fails', input_schema: {} }],
        toolExecutor: failingToolExecutor,
        maxContextMessages: 20,
        maxSessionAge: 3600,
      });

      const response = await toolAgent.handleMessage(createIncomingMessage());
      expect(response).toBeTruthy();
    });

    it('should report error when no toolExecutor is provided', async () => {
      const toolCallResponse: LLMResponse = {
        content: '',
        toolCalls: [{ id: 'call-1', name: 'any_tool', input: {} }],
        stopReason: 'tool_use',
        inputTokens: 100,
        outputTokens: 50,
      };

      const finalResponse: LLMResponse = {
        content: 'Tool execution not available, sorry.',
        toolCalls: [],
        stopReason: 'end_turn',
        inputTokens: 150,
        outputTokens: 80,
      };

      const noToolLLM = createMockLLM();
      vi.mocked(noToolLLM.chat).mockResolvedValueOnce(toolCallResponse);
      vi.mocked(noToolLLM.continueWithToolResults).mockResolvedValueOnce(finalResponse);

      const noToolAgent = new Agent({
        llm: noToolLLM,
        systemPrompt: 'Test',
        tools: [{ name: 'any_tool', description: 'A tool', input_schema: {} }],
        // No toolExecutor provided
        maxContextMessages: 20,
        maxSessionAge: 3600,
      });

      const response = await noToolAgent.handleMessage(createIncomingMessage());
      expect(response).toBeTruthy();
    });
  });

  // ── Session management ──────────────────────────────────────

  describe('session management', () => {
    it('should clear a specific session', async () => {
      await agent.handleMessage(createIncomingMessage({ contactId: 'user-1', channel: 'signal' }));
      await agent.handleMessage(createIncomingMessage({ contactId: 'user-2', channel: 'signal' }));
      expect(agent.getSessionCount()).toBe(2);

      agent.clearSession('user-1', 'signal');
      expect(agent.getSessionCount()).toBe(1);
    });

    it('should clear all sessions', async () => {
      await agent.handleMessage(createIncomingMessage({ contactId: 'user-1' }));
      await agent.handleMessage(createIncomingMessage({ contactId: 'user-2' }));
      expect(agent.getSessionCount()).toBe(2);

      agent.clearAllSessions();
      expect(agent.getSessionCount()).toBe(0);
    });

    it('should create a new session after the old one expired', async () => {
      const shortLivedAgent = new Agent({
        llm: mockLLM,
        systemPrompt: 'Test',
        maxContextMessages: 20,
        maxSessionAge: 0, // expires immediately
      });

      await shortLivedAgent.handleMessage(createIncomingMessage());
      // Second message should create a new session since the old one expired
      await shortLivedAgent.handleMessage(createIncomingMessage());
      // We expect 1 session because the expired one was replaced
      expect(shortLivedAgent.getSessionCount()).toBe(1);
    });
  });

  // ── Context trimming ────────────────────────────────────────

  describe('context trimming', () => {
    it('should trim history to maxContextMessages', async () => {
      const tinyAgent = new Agent({
        llm: mockLLM,
        systemPrompt: 'Test',
        maxContextMessages: 4,
        maxSessionAge: 3600,
      });

      // Send 6 messages (each creates a user + assistant message = 2 per round)
      for (let i = 0; i < 6; i++) {
        await tinyAgent.handleMessage(createIncomingMessage({ text: `Message ${i}` }));
      }

      // The LLM should have been called with trimmed context
      const lastCall = vi.mocked(mockLLM.chat).mock.calls.at(-1);
      expect(lastCall).toBeDefined();
      const messages = lastCall![0].messages;
      expect(messages.length).toBeLessThanOrEqual(5); // maxContextMessages + 1 for the new user message
    });
  });
});
