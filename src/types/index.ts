import { z } from 'zod';

// ── Channel Configs ──────────────────────────────────────────

export const SignalChannelConfigSchema = z.object({
  enabled: z.boolean().default(false),
  apiUrl: z.string().url().default('http://127.0.0.1:8080'),
  phoneNumber: z.string().regex(/^\+\d{10,15}$/, 'Must be E.164 format'),
  allowedNumbers: z.array(z.string()).default([]),
  allowedGroups: z.array(z.string()).default([]),
  rateLimitPerMinute: z.number().int().positive().default(30),
  trustOnFirstUse: z.boolean().default(true),
});
export type SignalChannelConfig = z.infer<typeof SignalChannelConfigSchema>;

export const DiscordChannelConfigSchema = z.object({
  enabled: z.boolean().default(false),
  botToken: z.string().optional(),
  botTokenEnv: z.string().default('DISCORD_BOT_TOKEN'),
  applicationId: z.string().optional(),
  allowedChannels: z.array(z.string()).default([]),
  allowedServers: z.array(z.string()).default([]),
});
export type DiscordChannelConfig = z.infer<typeof DiscordChannelConfigSchema>;

export const WebChatConfigSchema = z.object({
  enabled: z.boolean().default(true),
  port: z.number().int().default(18789),
  corsOrigin: z.string().default('http://localhost:18789'),
});
export type WebChatConfig = z.infer<typeof WebChatConfigSchema>;

export const ChannelConfigSchema = z.object({
  signal: SignalChannelConfigSchema.optional(),
  discord: DiscordChannelConfigSchema.optional(),
  webchat: WebChatConfigSchema.optional(),
});
export type ChannelConfig = z.infer<typeof ChannelConfigSchema>;

// ── Security Config ──────────────────────────────────────────

export const SecurityConfigSchema = z.object({
  gatewayToken: z.string().optional(),
  gatewayTokenEnv: z.string().default('OPENCLAW_GATEWAY_TOKEN'),
  encryptionKey: z.string().optional(),
  encryptionKeyEnv: z.string().default('OPENCLAW_ENCRYPTION_KEY'),
  piiHmacSecret: z.string().optional(),
  piiHmacSecretEnv: z.string().default('OPENCLAW_PII_HMAC_SECRET'),
  sessionSecret: z.string().optional(),
  sessionSecretEnv: z.string().default('OPENCLAW_SESSION_SECRET'),
  promptGuardEnabled: z.boolean().default(true),
  piiDetectionEnabled: z.boolean().default(true),
  auditLogPath: z.string().default('~/.openclaw/audit.jsonl'),
  retentionDays: z.number().int().positive().default(90),
  maxSessionAge: z.number().int().positive().default(86400), // 24h in seconds
  signalDaemonLoopbackOnly: z.boolean().default(true),
});
export type SecurityConfig = z.infer<typeof SecurityConfigSchema>;

// ── LLM Config ───────────────────────────────────────────────

export const LLMConfigSchema = z.object({
  provider: z.literal('anthropic').default('anthropic'),
  model: z.string().default('claude-sonnet-4-20250514'),
  apiKey: z.string().optional(),
  apiKeyEnv: z.string().default('ANTHROPIC_API_KEY'),
  maxTokens: z.number().int().positive().default(4096),
  temperature: z.number().min(0).max(1).default(0.7),
  maxContextMessages: z.number().int().positive().default(50),
});
export type LLMConfig = z.infer<typeof LLMConfigSchema>;

// ── Main Config ──────────────────────────────────────────────

export const OpenClawConfigSchema = z.object({
  name: z.string().default('OpenClaw Fortress'),
  version: z.string().default('1.0.0'),
  gateway: z.object({
    host: z.string().default('127.0.0.1'),
    port: z.number().int().default(18789),
  }).default(() => ({ host: '127.0.0.1', port: 18789 })),
  llm: LLMConfigSchema.default(() => ({
    provider: 'anthropic' as const,
    model: 'claude-sonnet-4-20250514',
    apiKeyEnv: 'ANTHROPIC_API_KEY',
    maxTokens: 4096,
    temperature: 0.7,
    maxContextMessages: 50,
  })),
  channels: ChannelConfigSchema.default(() => ({})),
  security: SecurityConfigSchema.default(() => ({
    gatewayTokenEnv: 'OPENCLAW_GATEWAY_TOKEN',
    encryptionKeyEnv: 'OPENCLAW_ENCRYPTION_KEY',
    piiHmacSecretEnv: 'OPENCLAW_PII_HMAC_SECRET',
    sessionSecretEnv: 'OPENCLAW_SESSION_SECRET',
    promptGuardEnabled: true,
    piiDetectionEnabled: true,
    auditLogPath: '~/.openclaw/audit.jsonl',
    retentionDays: 90,
    maxSessionAge: 86400,
    signalDaemonLoopbackOnly: true,
  })),
  systemPrompt: z.string().default(
    'You are a helpful AI assistant. Be concise and accurate.',
  ),
});
export type OpenClawConfig = z.infer<typeof OpenClawConfigSchema>;

// ── Agent & Session Types ────────────────────────────────────

export interface AgentMessage {
  role: 'user' | 'assistant';
  content: string;
  timestamp: number;
  channel: ChannelType;
  contactId: string;
}

export interface AgentSession {
  id: string;
  agentId: string;
  contactId: string;
  channel: ChannelType;
  messages: AgentMessage[];
  createdAt: number;
  lastActiveAt: number;
  expiresAt: number;
  metadata: Record<string, unknown>;
}

export type ChannelType = 'signal' | 'discord' | 'webchat';

// ── Skill Types ──────────────────────────────────────────────

export type SkillRiskLevel = 'low' | 'medium' | 'high' | 'critical';

export interface ToolDefinition {
  name: string;
  description: string;
  input_schema: Record<string, unknown>;
}

export interface SkillManifest {
  name: string;
  version: string;
  description: string;
  author?: string;
  riskLevel: SkillRiskLevel;
  tools: ToolDefinition[];
  entryPoint: string;
  hash?: string;
}

// ── Channel Message ──────────────────────────────────────────

export interface IncomingMessage {
  channel: ChannelType;
  contactId: string;
  text: string;
  groupId?: string;
  attachments?: Attachment[];
  timestamp: number;
  raw?: unknown;
}

export interface OutgoingMessage {
  channel: ChannelType;
  contactId: string;
  text: string;
  groupId?: string;
  attachments?: Attachment[];
}

export interface Attachment {
  contentType: string;
  filename?: string;
  data?: Buffer;
  url?: string;
  size?: number;
}

// ── Audit Types ──────────────────────────────────────────────

export type AuditSeverity = 'INFO' | 'WARN' | 'ERROR' | 'CRITICAL';

export interface AuditEntry {
  timestamp: string;
  severity: AuditSeverity;
  event: string;
  channel?: ChannelType;
  contactId?: string;
  sessionId?: string;
  details?: Record<string, unknown>;
}

// ── Security Check Types ─────────────────────────────────────

export type SecurityCheckStatus = 'PASS' | 'FAIL' | 'WARN' | 'SKIP';

export interface SecurityCheckResult {
  id: string;
  name: string;
  status: SecurityCheckStatus;
  message: string;
}
