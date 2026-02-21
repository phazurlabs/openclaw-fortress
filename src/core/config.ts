import { readFileSync, existsSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';
import { OpenClawConfigSchema, type OpenClawConfig } from '../types/index.js';

const OPENCLAW_DIR = join(homedir(), '.openclaw');
const CONFIG_PATH = join(OPENCLAW_DIR, 'openclaw.json');

export function getOpenClawDir(): string {
  return OPENCLAW_DIR;
}

export function ensureOpenClawDir(): void {
  if (!existsSync(OPENCLAW_DIR)) {
    mkdirSync(OPENCLAW_DIR, { recursive: true, mode: 0o700 });
  }
}

/**
 * Resolve a value that may come from config or an env var.
 * Pattern: if `value` is set use it, otherwise read `envKey` from process.env.
 */
export function resolveSecret(value: string | undefined, envKey: string): string | undefined {
  if (value) return value;
  return process.env[envKey];
}

/**
 * Load and validate the OpenClaw config.
 * Falls back to defaults if no config file exists.
 */
export function loadConfig(overridePath?: string): OpenClawConfig {
  const configPath = overridePath ?? CONFIG_PATH;
  let raw: unknown = {};

  if (existsSync(configPath)) {
    try {
      const content = readFileSync(configPath, 'utf-8');
      raw = JSON.parse(content);
    } catch (err) {
      throw new Error(`Failed to parse config at ${configPath}: ${err}`);
    }
  }

  const config = OpenClawConfigSchema.parse(raw);

  // Resolve secrets from env vars
  const sec = config.security;
  sec.gatewayToken = resolveSecret(sec.gatewayToken, sec.gatewayTokenEnv);
  sec.encryptionKey = resolveSecret(sec.encryptionKey, sec.encryptionKeyEnv);
  sec.piiHmacSecret = resolveSecret(sec.piiHmacSecret, sec.piiHmacSecretEnv);
  sec.sessionSecret = resolveSecret(sec.sessionSecret, sec.sessionSecretEnv);

  const llm = config.llm;
  llm.apiKey = resolveSecret(llm.apiKey, llm.apiKeyEnv);

  // Resolve channel token env vars
  if (config.channels.discord) {
    const dc = config.channels.discord;
    if (!dc.botToken && dc.botTokenEnv) {
      dc.botToken = process.env[dc.botTokenEnv];
    }
  }

  return config;
}

/**
 * Resolve tilde-prefixed paths to absolute.
 */
export function resolvePath(p: string): string {
  if (p.startsWith('~/')) {
    return join(homedir(), p.slice(2));
  }
  return p;
}
