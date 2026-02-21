/**
 * Tests for 1.5: Signal Channel
 * Signal schema parsing with parseSignalEvent, and allowlist integration
 */
import { describe, it, expect, vi } from 'vitest';
import {
  parseSignalEvent,
  SignalSSEEventSchema,
  SignalEnvelopeSchema,
  SignalDataMessageSchema,
  SignalAttachmentSchema,
  type SignalSSEEvent,
  type SignalDataMessage,
} from '../../src/security/signalSchema.js';
import {
  isNumberAllowed,
  isGroupAllowed,
  checkAllowlist,
  resetContactRateLimits,
} from '../../src/security/signalAllowlist.js';

// Mock auditLogger to prevent file I/O during tests
vi.mock('../../src/security/auditLogger.js', () => ({
  auditWarn: vi.fn(),
  auditCritical: vi.fn(),
  auditInfo: vi.fn(),
  auditError: vi.fn(),
  audit: vi.fn(),
}));

describe('Signal Schema Parsing', () => {
  // ── parseSignalEvent — valid events ─────────────────────────

  describe('parseSignalEvent — valid events', () => {
    it('should parse a valid data message event', () => {
      const raw = JSON.stringify({
        envelope: {
          source: '+12025551234',
          sourceNumber: '+12025551234',
          timestamp: Date.now(),
          dataMessage: {
            timestamp: Date.now(),
            message: 'Hello, world!',
          },
        },
        account: '+10000000000',
      });

      const result = parseSignalEvent(raw);
      expect(result).not.toBeNull();
      expect(result!.envelope.sourceNumber).toBe('+12025551234');
      expect(result!.envelope.dataMessage?.message).toBe('Hello, world!');
      expect(result!.account).toBe('+10000000000');
    });

    it('should parse an event with attachments', () => {
      const raw = JSON.stringify({
        envelope: {
          source: '+12025551234',
          timestamp: Date.now(),
          dataMessage: {
            timestamp: Date.now(),
            message: 'Check this image',
            attachments: [
              {
                contentType: 'image/jpeg',
                filename: 'photo.jpg',
                size: 102400,
              },
            ],
          },
        },
        account: '+10000000000',
      });

      const result = parseSignalEvent(raw);
      expect(result).not.toBeNull();
      expect(result!.envelope.dataMessage?.attachments).toHaveLength(1);
      expect(result!.envelope.dataMessage?.attachments![0]!.contentType).toBe('image/jpeg');
    });

    it('should parse an event with group info', () => {
      const raw = JSON.stringify({
        envelope: {
          source: '+12025551234',
          timestamp: Date.now(),
          dataMessage: {
            timestamp: Date.now(),
            message: 'Group message',
            groupInfo: {
              groupId: 'group-abc-123',
              type: 'DELIVER',
            },
          },
        },
        account: '+10000000000',
      });

      const result = parseSignalEvent(raw);
      expect(result).not.toBeNull();
      expect(result!.envelope.dataMessage?.groupInfo?.groupId).toBe('group-abc-123');
    });

    it('should parse an event with receipt message', () => {
      const raw = JSON.stringify({
        envelope: {
          source: '+12025551234',
          timestamp: Date.now(),
          receiptMessage: {
            when: Date.now(),
            isDelivery: true,
            timestamps: [1234567890],
          },
        },
        account: '+10000000000',
      });

      const result = parseSignalEvent(raw);
      expect(result).not.toBeNull();
      expect(result!.envelope.receiptMessage?.isDelivery).toBe(true);
    });

    it('should parse an event with typing message', () => {
      const raw = JSON.stringify({
        envelope: {
          source: '+12025551234',
          timestamp: Date.now(),
          typingMessage: {
            action: 'STARTED',
            timestamp: Date.now(),
          },
        },
        account: '+10000000000',
      });

      const result = parseSignalEvent(raw);
      expect(result).not.toBeNull();
      expect(result!.envelope.typingMessage?.action).toBe('STARTED');
    });

    it('should parse an event with sync message', () => {
      const raw = JSON.stringify({
        envelope: {
          source: '+12025551234',
          timestamp: Date.now(),
          syncMessage: {
            sentMessage: {
              timestamp: Date.now(),
              message: 'Synced message',
            },
          },
        },
        account: '+10000000000',
      });

      const result = parseSignalEvent(raw);
      expect(result).not.toBeNull();
      expect(result!.envelope.syncMessage?.sentMessage?.message).toBe('Synced message');
    });

    it('should parse event with all optional envelope fields', () => {
      const raw = JSON.stringify({
        envelope: {
          source: '+12025551234',
          sourceNumber: '+12025551234',
          sourceUuid: 'uuid-abc-123',
          sourceName: 'Alice',
          sourceDevice: 1,
          timestamp: Date.now(),
          dataMessage: {
            timestamp: Date.now(),
            message: 'Full event',
          },
        },
        account: '+10000000000',
      });

      const result = parseSignalEvent(raw);
      expect(result).not.toBeNull();
      expect(result!.envelope.sourceUuid).toBe('uuid-abc-123');
      expect(result!.envelope.sourceName).toBe('Alice');
      expect(result!.envelope.sourceDevice).toBe(1);
    });

    it('should handle null message in dataMessage', () => {
      const raw = JSON.stringify({
        envelope: {
          source: '+12025551234',
          timestamp: Date.now(),
          dataMessage: {
            timestamp: Date.now(),
            message: null,
            attachments: [{ contentType: 'image/png' }],
          },
        },
        account: '+10000000000',
      });

      const result = parseSignalEvent(raw);
      expect(result).not.toBeNull();
      expect(result!.envelope.dataMessage?.message).toBeNull();
    });
  });

  // ── parseSignalEvent — invalid events ───────────────────────

  describe('parseSignalEvent — invalid events', () => {
    it('should return null for invalid JSON', () => {
      expect(parseSignalEvent('not json at all')).toBeNull();
    });

    it('should return null for empty string', () => {
      expect(parseSignalEvent('')).toBeNull();
    });

    it('should return null for missing envelope', () => {
      const raw = JSON.stringify({ account: '+10000000000' });
      expect(parseSignalEvent(raw)).toBeNull();
    });

    it('should return null for missing account', () => {
      const raw = JSON.stringify({
        envelope: {
          source: '+12025551234',
          timestamp: Date.now(),
        },
      });
      expect(parseSignalEvent(raw)).toBeNull();
    });

    it('should return null for missing timestamp in envelope', () => {
      const raw = JSON.stringify({
        envelope: {
          source: '+12025551234',
          // no timestamp
        },
        account: '+10000000000',
      });
      expect(parseSignalEvent(raw)).toBeNull();
    });

    it('should return null for plain number (not JSON object)', () => {
      expect(parseSignalEvent('42')).toBeNull();
    });

    it('should return null for array JSON', () => {
      expect(parseSignalEvent('[]')).toBeNull();
    });
  });

  // ── Schema validation details ───────────────────────────────

  describe('Schema validation', () => {
    it('SignalAttachmentSchema should accept valid attachment', () => {
      const result = SignalAttachmentSchema.safeParse({
        contentType: 'image/jpeg',
        filename: 'photo.jpg',
        id: 'att-123',
        size: 1024,
        width: 800,
        height: 600,
        caption: 'A photo',
      });
      expect(result.success).toBe(true);
    });

    it('SignalAttachmentSchema should require contentType', () => {
      const result = SignalAttachmentSchema.safeParse({
        filename: 'photo.jpg',
      });
      expect(result.success).toBe(false);
    });

    it('SignalDataMessageSchema should accept minimal data message', () => {
      const result = SignalDataMessageSchema.safeParse({
        timestamp: Date.now(),
      });
      expect(result.success).toBe(true);
    });

    it('SignalDataMessageSchema should accept data message with reaction', () => {
      const result = SignalDataMessageSchema.safeParse({
        timestamp: Date.now(),
        reaction: {
          emoji: '\u{1F44D}',
          targetAuthor: '+12025551234',
          targetSentTimestamp: Date.now(),
          isRemove: false,
        },
      });
      expect(result.success).toBe(true);
    });

    it('SignalDataMessageSchema should accept data message with quote', () => {
      const result = SignalDataMessageSchema.safeParse({
        timestamp: Date.now(),
        quote: {
          id: 123456,
          author: '+12025551234',
          text: 'Quoted text',
        },
      });
      expect(result.success).toBe(true);
    });

    it('SignalEnvelopeSchema should accept minimal envelope', () => {
      const result = SignalEnvelopeSchema.safeParse({
        timestamp: Date.now(),
      });
      expect(result.success).toBe(true);
    });

    it('SignalSSEEventSchema should accept valid SSE event', () => {
      const result = SignalSSEEventSchema.safeParse({
        envelope: { timestamp: Date.now() },
        account: '+10000000000',
      });
      expect(result.success).toBe(true);
    });
  });

  // ── Allowlist integration ───────────────────────────────────

  describe('Allowlist integration with Signal events', () => {
    beforeEach(() => {
      resetContactRateLimits();
    });

    it('should allow a message from an allowed sender to pass', () => {
      const allowedNumbers = ['+12025551234'];
      const sender = '+12025551234';

      expect(isNumberAllowed(sender, allowedNumbers)).toBe(true);
    });

    it('should block a message from a non-allowed sender', () => {
      const allowedNumbers = ['+12025551234'];
      const sender = '+19999999999';

      expect(isNumberAllowed(sender, allowedNumbers)).toBe(false);
    });

    it('should allow group messages from allowed groups', () => {
      const allowedGroups = ['group-trusted'];
      expect(isGroupAllowed('group-trusted', allowedGroups)).toBe(true);
    });

    it('should block group messages from non-allowed groups', () => {
      const allowedGroups = ['group-trusted'];
      expect(isGroupAllowed('group-untrusted', allowedGroups)).toBe(false);
    });

    it('should enforce combined sender + group allowlist', () => {
      const config = {
        allowedNumbers: ['+12025551234'],
        allowedGroups: ['group-trusted'],
        rateLimitPerMinute: 30,
      };

      // Allowed sender + allowed group
      expect(checkAllowlist('+12025551234', 'group-trusted', config).allowed).toBe(true);

      // Allowed sender + blocked group
      expect(checkAllowlist('+12025551234', 'group-blocked', config).allowed).toBe(false);

      // Blocked sender + allowed group
      expect(checkAllowlist('+19999999999', 'group-trusted', config).allowed).toBe(false);
    });

    it('end-to-end: parse event then check allowlist', () => {
      const raw = JSON.stringify({
        envelope: {
          source: '+12025551234',
          sourceNumber: '+12025551234',
          timestamp: Date.now(),
          dataMessage: {
            timestamp: Date.now(),
            message: 'Hello',
          },
        },
        account: '+10000000000',
      });

      const event = parseSignalEvent(raw);
      expect(event).not.toBeNull();

      const sender = event!.envelope.sourceNumber!;
      const groupId = event!.envelope.dataMessage?.groupInfo?.groupId;

      const config = {
        allowedNumbers: ['+12025551234'],
        allowedGroups: [],
        rateLimitPerMinute: 30,
      };

      const result = checkAllowlist(sender, groupId, config);
      expect(result.allowed).toBe(true);
    });

    it('end-to-end: parse group event then check allowlist', () => {
      const raw = JSON.stringify({
        envelope: {
          source: '+12025551234',
          sourceNumber: '+12025551234',
          timestamp: Date.now(),
          dataMessage: {
            timestamp: Date.now(),
            message: 'Group hello',
            groupInfo: {
              groupId: 'group-xyz',
            },
          },
        },
        account: '+10000000000',
      });

      const event = parseSignalEvent(raw);
      expect(event).not.toBeNull();

      const sender = event!.envelope.sourceNumber!;
      const groupId = event!.envelope.dataMessage?.groupInfo?.groupId;

      const config = {
        allowedNumbers: ['+12025551234'],
        allowedGroups: ['group-xyz'],
        rateLimitPerMinute: 30,
      };

      const result = checkAllowlist(sender, groupId, config);
      expect(result.allowed).toBe(true);
    });
  });
});
