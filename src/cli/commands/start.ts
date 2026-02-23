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
import { getBuiltinToolDefinitions } from '../../tools/builtinTools.js';
import { createBuiltinToolExecutor } from '../../tools/builtinToolExecutor.js';
import { createCompositeToolExecutor } from '../../tools/compositeToolExecutor.js';
import { auditInfo } from '../../security/auditLogger.js';
import type { SignalFileDeliveryContext } from '../../tools/signalFileDelivery.js';

/**
 * Build a comprehensive system prompt that gives the agent its identity,
 * capabilities, security stance, and behavioral guidance.
 */
function buildSystemPrompt(
  config: OpenClawConfig,
  builtinToolCount: number,
  skillCount: number,
): string {
  const sections: string[] = [];

  // Identity
  sections.push(
    `You are OpenClaw Fortress, a security-hardened AI assistant built on the OpenClaw platform.` +
    ` You prioritize accuracy, conciseness, and user safety in every interaction.`,
  );

  // Capabilities
  const capabilities: string[] = [];
  if (builtinToolCount > 0) {
    capabilities.push(
      `File Tools (${builtinToolCount} tools): You have sandboxed file system access via fortress_* tools.` +
      ` You can read, write, and list files in ~/Desktop, ~/Documents, ~/Downloads, and ~/.openclaw/output/.` +
      ` You can generate PDF documents and create directories. All file operations are audit-logged.`,
    );
  }
  if (skillCount > 0) {
    capabilities.push(`Skills: ${skillCount} skill(s) loaded providing additional tool capabilities.`);
  }
  capabilities.push(`Conversation Memory: You maintain conversation context across messages within a session.`);

  if (config.channels.signal?.enabled) {
    capabilities.push(
      `Signal Delivery: Your primary channel is Signal (E2E encrypted).` +
      ` Files you create can be sent as attachments via the fortress_send_file_via_signal tool.`,
    );
  }

  if (capabilities.length > 0) {
    sections.push(`Capabilities:\n${capabilities.map(c => `- ${c}`).join('\n')}`);
  }

  // Security stance
  sections.push(
    `Security Posture:` +
    `\n- All file access is sandboxed to allowed directories only` +
    `\n- Every file operation is audit-logged` +
    `\n- Path traversal, symlink escapes, and null bytes are blocked` +
    `\n- Sessions are encrypted at rest with AES-256-GCM` +
    (config.channels.signal?.enabled ? `\n- Signal channel: E2E encrypted, contact allowlist enforced, safety numbers verified` : ''),
  );

  // Behavioral rules
  sections.push(
    `Behavioral Rules:` +
    `\n- Be concise and accurate. Avoid unnecessary verbosity.` +
    `\n- When creating files, confirm the file path and result to the user.` +
    `\n- Never output credentials, API keys, encryption keys, or secrets.` +
    `\n- If a user asks you to access a path outside your sandbox, explain the restriction.` +
    `\n- Format responses for readability using markdown where appropriate.`,
  );

  // Tool guidance
  if (builtinToolCount > 0) {
    sections.push(
      `Tool Guidance:` +
      `\n- Use fortress_write_file to create text files in allowed directories.` +
      `\n- Use fortress_read_file to read existing files.` +
      `\n- Use fortress_generate_pdf for document generation (supports headings, bold, italic, bullet lists).` +
      `\n- Use fortress_save_to_desktop as a shortcut for saving to ~/Desktop.` +
      `\n- Use fortress_list_directory to browse allowed directories.` +
      `\n- Use fortress_create_directory to create new directories within the sandbox.` +
      (config.channels.signal?.enabled
        ? `\n- Use fortress_send_file_via_signal to send created files as Signal attachments to the current contact.`
        : ''),
    );
  }

  return sections.join('\n\n');
}

export async function startCommand(config: OpenClawConfig): Promise<void> {
  console.log('Starting OpenClaw Fortress...\n');

  // Load skills
  const skills = loadSkills();
  const skillTools = getToolDefinitions(skills);
  const skillExecutor = skills.length > 0 ? createToolExecutor(skills) : undefined;

  // Load built-in file tools
  // Create a mutable context that will be populated when Signal starts
  const signalDeliveryContext: SignalFileDeliveryContext = {};
  const fileToolsEnabled = config.fileTools.enabled;
  const builtinTools = fileToolsEnabled ? getBuiltinToolDefinitions() : [];
  const builtinExecutor = fileToolsEnabled ? createBuiltinToolExecutor(signalDeliveryContext) : undefined;

  // Merge all tools
  const allTools = [...builtinTools, ...skillTools];
  const compositeExecutor = builtinExecutor
    ? createCompositeToolExecutor(builtinExecutor, skillExecutor)
    : skillExecutor;

  // Build system prompt with full agent identity
  const systemPrompt = buildSystemPrompt(config, builtinTools.length, skills.length);
  const configWithPrompt: OpenClawConfig = { ...config, systemPrompt };

  // Create agent manager with composite executor
  const agentManager = new AgentManager(configWithPrompt, compositeExecutor);
  if (allTools.length > 0 && compositeExecutor) {
    agentManager.updateAgent(compositeExecutor, allTools);
  }

  if (fileToolsEnabled) {
    console.log(`[File Tools] ${builtinTools.length} built-in tools enabled`);
  }
  if (skills.length > 0) {
    console.log(`[Skills] ${skills.length} skill(s) loaded with ${skillTools.length} tool(s)`);
  }

  // Create gateway
  const gateway = new Gateway({
    config,
    onMessage: (msg) => agentManager.handleMessage(msg),
  });

  // Mount WebChat UI if enabled
  const webchatEnabled = config.channels.webchat?.enabled ?? false;
  if (webchatEnabled) {
    mountWebChatUI(gateway.expressApp);
    console.log('[WebChat] UI enabled');
  }

  // Channel availability warning
  const signalEnabled = config.channels.signal?.enabled ?? false;
  const discordEnabled = config.channels.discord?.enabled ?? false;
  if (!signalEnabled && !discordEnabled && !webchatEnabled) {
    console.log('[WARNING] No channels enabled. Enable Signal in config or add --webchat for testing.');
  }

  // Start gateway
  await gateway.start();

  // Start Signal channel if enabled
  if (signalEnabled) {
    const signal = new SignalChannel(config, (msg) => {
      // Wire per-message context for Signal file delivery
      signalDeliveryContext.contactId = msg.contactId;
      signalDeliveryContext.channel = msg.channel;
      signalDeliveryContext.sendAttachment = async (
        _filePath, base64Data, filename, contentType, caption,
      ) => {
        await signal.sendAttachment(msg.contactId, base64Data, filename, contentType, caption, msg.groupId);
      };
      return agentManager.handleMessage(msg);
    });
    await signal.start();
  }

  // Start Discord channel if enabled
  if (discordEnabled) {
    const discord = new DiscordChannel(config, (msg) => agentManager.handleMessage(msg));
    await discord.start();
  }

  auditInfo('openclaw_started', {
    details: {
      channels: {
        webchat: webchatEnabled,
        signal: signalEnabled,
        discord: discordEnabled,
      },
      skills: skills.length,
      builtinTools: builtinTools.length,
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
