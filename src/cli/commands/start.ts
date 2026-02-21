/**
 * CLI: openclaw start
 * Launch gateway + all enabled channels.
 */
import type { OpenClawConfig } from '../../types/index.js';
import { Gateway } from '../../core/gateway.js';
import { AgentManager } from '../../core/agentManager.js';
import { SignalChannel } from '../../channels/signal.js';
import { DiscordChannel } from '../../channels/discord.js';
import { mountWebChatUI } from '../../channels/webchat.js';
import { loadSkills, getToolDefinitions } from '../../skills/skillLoader.js';
import { createToolExecutor } from '../../skills/skillRunner.js';
import { auditInfo } from '../../security/auditLogger.js';

export async function startCommand(config: OpenClawConfig): Promise<void> {
  console.log('Starting OpenClaw Fortress...\n');

  // Load skills
  const skills = loadSkills();
  const tools = getToolDefinitions(skills);
  const toolExecutor = skills.length > 0 ? createToolExecutor(skills) : undefined;

  // Create agent manager
  const agentManager = new AgentManager(config, toolExecutor);
  if (skills.length > 0 && toolExecutor) {
    agentManager.updateAgent(toolExecutor, tools);
  }

  // Create gateway
  const gateway = new Gateway({
    config,
    onMessage: (msg) => agentManager.handleMessage(msg),
  });

  // Mount WebChat UI if enabled
  if (config.channels.webchat?.enabled !== false) {
    mountWebChatUI(gateway.expressApp);
    console.log('[WebChat] UI enabled');
  }

  // Start gateway
  await gateway.start();

  // Start Signal channel if enabled
  if (config.channels.signal?.enabled) {
    const signal = new SignalChannel(config, (msg) => agentManager.handleMessage(msg));
    await signal.start();
  }

  // Start Discord channel if enabled
  if (config.channels.discord?.enabled) {
    const discord = new DiscordChannel(config, (msg) => agentManager.handleMessage(msg));
    await discord.start();
  }

  auditInfo('openclaw_started', {
    details: {
      channels: {
        webchat: config.channels.webchat?.enabled !== false,
        signal: config.channels.signal?.enabled ?? false,
        discord: config.channels.discord?.enabled ?? false,
      },
      skills: skills.length,
    },
  });

  console.log('\nOpenClaw Fortress is running. Press Ctrl+C to stop.\n');

  // Graceful shutdown
  const shutdown = async () => {
    console.log('\nShutting down...');
    await gateway.stop();
    auditInfo('openclaw_stopped');
    process.exit(0);
  };

  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}
