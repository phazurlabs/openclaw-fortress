/**
 * Agent Manager
 * Creates and manages agent instances for the gateway.
 */
import type { OpenClawConfig, IncomingMessage } from '../types/index.js';
import { Agent, type ToolExecutor } from './agent.js';
import { LLMClient } from './llm.js';
import { StateManager } from './stateManager.js';
import { resolveSecret } from './config.js';
import { auditInfo } from '../security/auditLogger.js';

export class AgentManager {
  private agent: Agent;
  private config: OpenClawConfig;
  private stateManager?: StateManager;

  constructor(config: OpenClawConfig, toolExecutor?: ToolExecutor) {
    this.config = config;

    // Initialize StateManager if encryption key is available
    const encryptionKey = resolveSecret(config.security.encryptionKey, config.security.encryptionKeyEnv);
    if (encryptionKey) {
      this.stateManager = new StateManager(encryptionKey);
    } else {
      console.warn('[Sessions] No encryption key — sessions will not persist across restarts');
    }

    const llm = new LLMClient(config.llm);

    this.agent = new Agent({
      llm,
      systemPrompt: config.systemPrompt,
      tools: [],
      toolExecutor,
      maxContextMessages: config.llm.maxContextMessages,
      maxSessionAge: config.security.maxSessionAge,
      stateManager: this.stateManager,
    });

    // Restore persisted sessions
    const restored = this.agent.restoreAllSessions();
    if (restored > 0) {
      console.log(`[Sessions] Restored ${restored} session(s) from disk`);
      auditInfo('sessions_restored', { details: { count: restored } });
    }

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
   * Preserves the StateManager across agent rebuilds.
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
      stateManager: this.stateManager,
    });
  }

  getSessionCount(): number {
    return this.agent.getSessionCount();
  }
}
