/**
 * Tests for 1.2: Gateway Server
 * Basic test that Gateway class can be instantiated with mock config.
 * Does NOT start a server.
 */
import { describe, it, expect, vi } from 'vitest';
import { Gateway, type GatewayOptions, type MessageHandler } from '../../src/core/gateway.js';
import type { OpenClawConfig } from '../../src/types/index.js';

// Mock auditLogger to prevent file I/O during tests
vi.mock('../../src/security/auditLogger.js', () => ({
  auditWarn: vi.fn(),
  auditCritical: vi.fn(),
  auditInfo: vi.fn(),
  auditError: vi.fn(),
  audit: vi.fn(),
}));

// Mock security modules used by Gateway
vi.mock('../../src/security/gatewayAuth.js', () => ({
  authenticateRequest: vi.fn(() => ({ ok: true })),
}));

vi.mock('../../src/security/securityHeaders.js', () => ({
  getHelmetConfig: vi.fn(() => ({})),
  getCorsConfig: vi.fn(() => ({ origin: '*' })),
  additionalSecurityHeaders: vi.fn(() => (_req: unknown, _res: unknown, next: () => void) => next()),
}));

describe('Gateway', () => {
  const mockConfig: OpenClawConfig = {
    name: 'Test OpenClaw',
    version: '1.0.0-test',
    gateway: {
      host: '127.0.0.1',
      port: 0, // Use 0 so OS picks a free port if we ever listen
    },
    llm: {
      provider: 'anthropic' as const,
      model: 'claude-sonnet-4-20250514',
      apiKeyEnv: 'ANTHROPIC_API_KEY',
      maxTokens: 4096,
      temperature: 0.7,
      maxContextMessages: 50,
    },
    channels: {
      webchat: {
        enabled: true,
        port: 0,
        corsOrigin: 'http://localhost:3000',
      },
    },
    security: {
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
    },
    systemPrompt: 'You are a test assistant.',
  };

  const mockOnMessage: MessageHandler = vi.fn(async () => 'Test response');

  describe('constructor', () => {
    it('should instantiate without throwing', () => {
      expect(() => {
        new Gateway({ config: mockConfig, onMessage: mockOnMessage });
      }).not.toThrow();
    });

    it('should create a Gateway instance', () => {
      const gw = new Gateway({ config: mockConfig, onMessage: mockOnMessage });
      expect(gw).toBeInstanceOf(Gateway);
    });

    it('should expose an express app', () => {
      const gw = new Gateway({ config: mockConfig, onMessage: mockOnMessage });
      expect(gw.expressApp).toBeDefined();
      expect(typeof gw.expressApp.get).toBe('function');
      expect(typeof gw.expressApp.use).toBe('function');
    });
  });

  describe('sendToConnection', () => {
    it('should return false for a non-existent connection', () => {
      const gw = new Gateway({ config: mockConfig, onMessage: mockOnMessage });
      const result = gw.sendToConnection('non-existent-id', 'hello');
      expect(result).toBe(false);
    });
  });

  describe('methods exist', () => {
    it('should have start method', () => {
      const gw = new Gateway({ config: mockConfig, onMessage: mockOnMessage });
      expect(typeof gw.start).toBe('function');
    });

    it('should have stop method', () => {
      const gw = new Gateway({ config: mockConfig, onMessage: mockOnMessage });
      expect(typeof gw.stop).toBe('function');
    });

    it('should have sendToConnection method', () => {
      const gw = new Gateway({ config: mockConfig, onMessage: mockOnMessage });
      expect(typeof gw.sendToConnection).toBe('function');
    });
  });

  describe('config handling', () => {
    it('should accept a config without webchat corsOrigin (uses default)', () => {
      const configNoCors = {
        ...mockConfig,
        channels: {},
      };
      expect(() => {
        new Gateway({ config: configNoCors, onMessage: mockOnMessage });
      }).not.toThrow();
    });

    it('should accept a config with gateway token', () => {
      const configWithToken = {
        ...mockConfig,
        security: {
          ...mockConfig.security,
          gatewayToken: 'test-token-123',
        },
      };
      expect(() => {
        new Gateway({ config: configWithToken, onMessage: mockOnMessage });
      }).not.toThrow();
    });
  });
});
