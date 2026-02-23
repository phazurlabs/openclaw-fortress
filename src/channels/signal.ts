/**
 * 1.5: Signal Channel
 * Connect to signal-cli daemon via HTTP API (SSE event stream).
 */
import { EventSource } from 'eventsource';
import type { OpenClawConfig, IncomingMessage, ChannelType } from '../types/index.js';
import { parseSignalEvent, type SignalSSEEvent, type SignalDataMessage } from '../security/signalSchema.js';
import { checkAllowlist, type AllowlistConfig } from '../security/signalAllowlist.js';
import { assertLoopback, checkDaemonHealth } from '../security/signalDaemonGuard.js';
import { trackSafetyNumber, isContactSuspended } from '../security/signalSafetyNumbers.js';
import { auditInfo, auditWarn, auditError } from '../security/auditLogger.js';

const ALLOWED_MIME_TYPES = new Set([
  'image/jpeg', 'image/png', 'image/gif', 'image/webp',
  'application/pdf', 'text/plain',
]);
const MAX_ATTACHMENT_SIZE = 10 * 1024 * 1024; // 10MB

export type SignalMessageHandler = (msg: IncomingMessage) => Promise<string>;

export class SignalChannel {
  private config: OpenClawConfig;
  private apiUrl: string;
  private phoneNumber: string;
  private allowlistConfig: AllowlistConfig;
  private eventSource: EventSource | null = null;
  private onMessage: SignalMessageHandler;

  constructor(config: OpenClawConfig, onMessage: SignalMessageHandler) {
    this.config = config;
    const signalConfig = config.channels.signal!;
    this.apiUrl = signalConfig.apiUrl;
    this.phoneNumber = signalConfig.phoneNumber;
    this.allowlistConfig = {
      allowedNumbers: signalConfig.allowedNumbers,
      allowedGroups: signalConfig.allowedGroups,
      rateLimitPerMinute: signalConfig.rateLimitPerMinute,
    };
    this.onMessage = onMessage;
  }

  /**
   * Start listening for Signal messages via SSE.
   */
  async start(): Promise<void> {
    // Security: assert loopback
    if (this.config.security.signalDaemonLoopbackOnly) {
      if (!assertLoopback(this.apiUrl)) {
        throw new Error('Signal daemon API is not on loopback — refusing to connect');
      }
    }

    // Health check
    const health = await checkDaemonHealth(this.apiUrl);
    if (!health.healthy) {
      throw new Error(`Signal daemon unhealthy: ${health.error}`);
    }
    console.log(`[Signal] Daemon healthy (v${health.version})`);

    // Connect to SSE stream
    const sseUrl = `${this.apiUrl}/v1/receive/${encodeURIComponent(this.phoneNumber)}`;
    this.eventSource = new EventSource(sseUrl);

    this.eventSource.onmessage = async (event: MessageEvent) => {
      await this.handleSSEMessage(event.data);
    };

    this.eventSource.onerror = (err: Event) => {
      auditError('signal_sse_error', { details: { error: String(err) } });
    };

    auditInfo('signal_channel_started', { details: { phoneNumber: this.phoneNumber } });
    console.log(`[Signal] Listening for messages on ${this.phoneNumber}`);
  }

  /**
   * Stop listening.
   */
  stop(): void {
    this.eventSource?.close();
    this.eventSource = null;
    auditInfo('signal_channel_stopped');
  }

  /**
   * Handle a raw SSE message.
   */
  private async handleSSEMessage(raw: string): Promise<void> {
    const event = parseSignalEvent(raw);
    if (!event) {
      auditWarn('signal_invalid_event', { details: { raw: raw.slice(0, 200) } });
      return;
    }

    const envelope = event.envelope;
    const dataMessage = envelope.dataMessage;
    if (!dataMessage?.message && !dataMessage?.attachments?.length) return;

    const sender = envelope.sourceNumber ?? envelope.source ?? '';
    if (!sender) return;

    // Allowlist check (silent drop)
    const groupId = dataMessage.groupInfo?.groupId;
    const allowed = checkAllowlist(sender, groupId, this.allowlistConfig);
    if (!allowed.allowed) return; // silent drop

    // Safety number check
    if (isContactSuspended(sender)) {
      auditWarn('signal_suspended_contact', { contactId: sender });
      return; // drop until manually cleared
    }

    // Build incoming message
    const msg: IncomingMessage = {
      channel: 'signal' as ChannelType,
      contactId: sender,
      text: dataMessage.message ?? '',
      groupId,
      timestamp: envelope.timestamp,
      attachments: this.validateAttachments(dataMessage),
      raw: event,
    };

    try {
      const response = await this.onMessage(msg);
      await this.sendMessage(sender, response, groupId);
    } catch (err) {
      auditError('signal_response_failed', {
        contactId: sender,
        details: { error: String(err) },
      });
    }
  }

  /**
   * Send a message via signal-cli REST API.
   */
  async sendMessage(recipient: string, text: string, groupId?: string): Promise<void> {
    const url = `${this.apiUrl}/v2/send`;
    const body: Record<string, unknown> = {
      message: text,
      number: this.phoneNumber,
      recipients: groupId ? undefined : [recipient],
    };

    if (groupId) {
      body['recipients'] = [groupId];
    }

    const resp = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });

    if (!resp.ok) {
      throw new Error(`Signal send failed: HTTP ${resp.status}`);
    }
  }

  /**
   * Send a file attachment via signal-cli REST API.
   */
  async sendAttachment(
    recipient: string,
    base64Data: string,
    filename: string,
    contentType: string,
    caption?: string,
    groupId?: string,
  ): Promise<void> {
    const url = `${this.apiUrl}/v2/send`;
    const body: Record<string, unknown> = {
      number: this.phoneNumber,
      recipients: groupId ? [groupId] : [recipient],
      base64_attachments: [
        `data:${contentType};filename=${filename};base64,${base64Data}`,
      ],
    };

    if (caption) {
      body['message'] = caption;
    }

    const resp = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });

    if (!resp.ok) {
      throw new Error(`Signal attachment send failed: HTTP ${resp.status}`);
    }

    auditInfo('signal_attachment_sent', {
      contactId: recipient,
      details: { filename, contentType },
    });
  }

  /**
   * Validate attachments (MIME type, size).
   */
  private validateAttachments(dm: SignalDataMessage): IncomingMessage['attachments'] {
    if (!dm.attachments?.length) return undefined;
    return dm.attachments
      .filter(a => {
        if (!ALLOWED_MIME_TYPES.has(a.contentType)) {
          auditWarn('signal_blocked_attachment', { details: { contentType: a.contentType } });
          return false;
        }
        if (a.size && a.size > MAX_ATTACHMENT_SIZE) {
          auditWarn('signal_attachment_too_large', { details: { size: a.size } });
          return false;
        }
        return true;
      })
      .map(a => ({
        contentType: a.contentType,
        filename: a.filename,
        size: a.size,
      }));
  }
}
