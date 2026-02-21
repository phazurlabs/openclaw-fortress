/**
 * Agent Manager
 * Creates and manages agent instances for the gateway.
 */
import type { OpenClawConfig, IncomingMessage } from '../types/index.js';
import { Agent, type ToolExecutor } from './agent.js';
import { LLMClient } from './llm.js';
import { auditInfo } from '../security/auditLogger.js';

export class AgentManager {
  private agent: Agent;
  private config: OpenClawConfig;

  constructor(config: OpenClawConfig, toolExecutor?: ToolExecutor) {
    this.config = config;

    const llm = new LLMClient(config.llm);

    this.agent = new Agent({
      llm,
      systemPrompt: config.systemPrompt,
      tools: [],
      toolExecutor,
      maxContextMessages: config.llm.maxContextMessages,
      maxSessionAge: config.security.maxSessionAge,
    });

    auditInfo('agent_manager_initialized');
  }

  /**
   * Route an incoming message to the agent.
   */
  async handleMessage(msg: IncomingMessage): Promise<string> {
    return this.agent.handleMessage(msg);
  }

  /**
   * Update tools available to the agent (e.g., after skill loading).
   */
  updateAgent(toolExecutor: ToolExecutor, tools: import('../types/index.js').ToolDefinition[]): void {
    const llm = new LLMClient(this.config.llm);
    this.agent = new Agent({
      llm,
      systemPrompt: this.config.systemPrompt,
      tools,
      toolExecutor,
      maxContextMessages: this.config.llm.maxContextMessages,
      maxSessionAge: this.config.security.maxSessionAge,
    });
  }

  getSessionCount(): number {
    return this.agent.getSessionCount();
  }
}
