/**
 * 1.4: LLM Integration (Anthropic Claude)
 * SDK wrapper with retry logic, streaming, token management.
 */
import Anthropic from '@anthropic-ai/sdk';
import type { MessageParam, ContentBlock, ToolUseBlock, ToolResultBlockParam } from '@anthropic-ai/sdk/resources/messages.js';
import type { LLMConfig, ToolDefinition } from '../types/index.js';
import { auditInfo, auditError } from '../security/auditLogger.js';

const MAX_RETRIES = 3;
const RETRY_DELAY_MS = 1000;

export interface LLMRequest {
  systemPrompt: string;
  messages: MessageParam[];
  tools?: ToolDefinition[];
  maxTokens?: number;
  temperature?: number;
}

export interface LLMResponse {
  content: string;
  toolCalls: ToolCall[];
  stopReason: string | null;
  inputTokens: number;
  outputTokens: number;
}

export interface ToolCall {
  id: string;
  name: string;
  input: Record<string, unknown>;
}

export class LLMClient {
  private client: Anthropic;
  private config: LLMConfig;

  constructor(config: LLMConfig) {
    this.config = config;
    const apiKey = config.apiKey;
    if (!apiKey) {
      throw new Error('Anthropic API key not configured. Set ANTHROPIC_API_KEY env var.');
    }
    this.client = new Anthropic({ apiKey });
  }

  /**
   * Send a message to Claude with retry logic.
   */
  async chat(request: LLMRequest): Promise<LLMResponse> {
    const tools = request.tools?.map(t => ({
      name: t.name,
      description: t.description,
      input_schema: t.input_schema as Anthropic.Tool['input_schema'],
    }));

    let lastError: Error | null = null;

    for (let attempt = 0; attempt < MAX_RETRIES; attempt++) {
      try {
        const response = await this.client.messages.create({
          model: this.config.model,
          max_tokens: request.maxTokens ?? this.config.maxTokens,
          temperature: request.temperature ?? this.config.temperature,
          system: request.systemPrompt,
          messages: request.messages,
          ...(tools && tools.length > 0 ? { tools } : {}),
        });

        const textBlocks = response.content
          .filter((b): b is ContentBlock & { type: 'text' } => b.type === 'text')
          .map(b => b.text);

        const toolCalls = response.content
          .filter((b): b is ToolUseBlock => b.type === 'tool_use')
          .map(b => ({
            id: b.id,
            name: b.name,
            input: b.input as Record<string, unknown>,
          }));

        auditInfo('llm_request', {
          details: {
            model: this.config.model,
            inputTokens: response.usage.input_tokens,
            outputTokens: response.usage.output_tokens,
          },
        });

        return {
          content: textBlocks.join('\n'),
          toolCalls,
          stopReason: response.stop_reason,
          inputTokens: response.usage.input_tokens,
          outputTokens: response.usage.output_tokens,
        };
      } catch (err) {
        lastError = err instanceof Error ? err : new Error(String(err));
        auditError('llm_request_failed', {
          details: { attempt: attempt + 1, error: lastError.message },
        });

        // Don't retry on auth errors
        if (lastError.message.includes('401') || lastError.message.includes('authentication')) {
          throw lastError;
        }

        if (attempt < MAX_RETRIES - 1) {
          await sleep(RETRY_DELAY_MS * (attempt + 1));
        }
      }
    }

    throw lastError ?? new Error('LLM request failed');
  }

  /**
   * Continue a conversation after tool use results.
   */
  async continueWithToolResults(
    request: LLMRequest,
    toolResults: Array<{ tool_use_id: string; content: string; is_error?: boolean }>,
  ): Promise<LLMResponse> {
    const toolResultContent: ToolResultBlockParam[] = toolResults.map(r => ({
      type: 'tool_result' as const,
      tool_use_id: r.tool_use_id,
      content: r.content,
      is_error: r.is_error,
    }));

    const updatedMessages: MessageParam[] = [
      ...request.messages,
      { role: 'user' as const, content: toolResultContent },
    ];

    return this.chat({
      ...request,
      messages: updatedMessages,
    });
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}
