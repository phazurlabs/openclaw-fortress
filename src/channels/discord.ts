/**
 * 1.7: Discord Channel
 * Discord.js bot with DM support and channel allowlist.
 */
import { Client, Events, GatewayIntentBits, type Message } from 'discord.js';
import type { OpenClawConfig, IncomingMessage, ChannelType } from '../types/index.js';
import { auditInfo, auditWarn, auditError } from '../security/auditLogger.js';

export type DiscordMessageHandler = (msg: IncomingMessage) => Promise<string>;

export class DiscordChannel {
  private client: Client;
  private config: OpenClawConfig;
  private allowedChannels: Set<string>;
  private allowedServers: Set<string>;
  private onMessage: DiscordMessageHandler;

  constructor(config: OpenClawConfig, onMessage: DiscordMessageHandler) {
    this.config = config;
    this.onMessage = onMessage;
    const dc = config.channels.discord!;
    this.allowedChannels = new Set(dc.allowedChannels);
    this.allowedServers = new Set(dc.allowedServers);

    this.client = new Client({
      intents: [
        GatewayIntentBits.Guilds,
        GatewayIntentBits.GuildMessages,
        GatewayIntentBits.MessageContent,
        GatewayIntentBits.DirectMessages,
      ],
    });

    this.setupHandlers();
  }

  private setupHandlers(): void {
    this.client.on(Events.ClientReady, (c) => {
      auditInfo('discord_ready', { details: { username: c.user.tag } });
      console.log(`[Discord] Bot logged in as ${c.user.tag}`);
    });

    this.client.on(Events.MessageCreate, async (message: Message) => {
      await this.handleMessage(message);
    });

    this.client.on(Events.Error, (err) => {
      auditError('discord_error', { details: { error: err.message } });
    });
  }

  private async handleMessage(message: Message): Promise<void> {
    // Ignore bot messages
    if (message.author.bot) return;

    // Check if DM or allowed channel/server
    const isDM = !message.guild;
    if (!isDM) {
      // Server message — check allowlists
      if (this.allowedServers.size > 0 && !this.allowedServers.has(message.guild!.id)) {
        return; // silent drop
      }
      if (this.allowedChannels.size > 0 && !this.allowedChannels.has(message.channel.id)) {
        return; // silent drop
      }
    }

    // Check if the message mentions the bot or is a DM
    const mentionsBot = message.mentions.users.has(this.client.user!.id);
    if (!isDM && !mentionsBot) return; // only respond to DMs or mentions

    // Strip the bot mention from the message
    let text = message.content;
    if (mentionsBot) {
      text = text.replace(/<@!?\d+>/g, '').trim();
    }
    if (!text) return;

    const msg: IncomingMessage = {
      channel: 'discord' as ChannelType,
      contactId: message.author.id,
      text,
      groupId: message.guild?.id,
      timestamp: message.createdTimestamp,
    };

    try {
      if ('sendTyping' in message.channel) {
        await (message.channel as { sendTyping(): Promise<void> }).sendTyping();
      }
      const response = await this.onMessage(msg);

      // Discord message limit is 2000 chars
      if (response.length <= 2000) {
        await message.reply(response);
      } else {
        // Split into chunks
        const chunks = splitMessage(response, 2000);
        for (const chunk of chunks) {
          await message.reply(chunk);
        }
      }
    } catch (err) {
      auditError('discord_response_failed', {
        contactId: message.author.id,
        details: { error: String(err) },
      });
      await message.reply('Sorry, I encountered an error. Please try again.').catch(() => {});
    }
  }

  /**
   * Start the Discord bot.
   */
  async start(): Promise<void> {
    const token = this.config.channels.discord!.botToken;
    if (!token) {
      throw new Error('Discord bot token not configured');
    }
    await this.client.login(token);
    console.log('[Discord] Bot starting...');
  }

  /**
   * Stop the Discord bot.
   */
  async stop(): Promise<void> {
    this.client.destroy();
    auditInfo('discord_channel_stopped');
  }
}

function splitMessage(text: string, maxLength: number): string[] {
  const chunks: string[] = [];
  let remaining = text;
  while (remaining.length > 0) {
    if (remaining.length <= maxLength) {
      chunks.push(remaining);
      break;
    }
    // Try to split at a newline
    let splitIdx = remaining.lastIndexOf('\n', maxLength);
    if (splitIdx === -1 || splitIdx < maxLength / 2) {
      splitIdx = maxLength;
    }
    chunks.push(remaining.slice(0, splitIdx));
    remaining = remaining.slice(splitIdx).trimStart();
  }
  return chunks;
}
