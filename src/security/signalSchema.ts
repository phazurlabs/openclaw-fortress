/**
 * S-04: Signal Schema
 * Zod validation for all signal-cli SSE event fields.
 */
import { z } from 'zod';

// ── Envelope ─────────────────────────────────────────────────

export const SignalAttachmentSchema = z.object({
  contentType: z.string(),
  filename: z.string().optional(),
  id: z.string().optional(),
  size: z.number().optional(),
  width: z.number().optional(),
  height: z.number().optional(),
  caption: z.string().optional(),
});

export const SignalDataMessageSchema = z.object({
  timestamp: z.number(),
  message: z.string().nullable().optional(),
  expiresInSeconds: z.number().optional(),
  viewOnce: z.boolean().optional(),
  attachments: z.array(SignalAttachmentSchema).optional(),
  groupInfo: z.object({
    groupId: z.string(),
    type: z.string().optional(),
  }).optional(),
  reaction: z.object({
    emoji: z.string(),
    targetAuthor: z.string(),
    targetSentTimestamp: z.number(),
    isRemove: z.boolean(),
  }).optional(),
  quote: z.object({
    id: z.number(),
    author: z.string(),
    text: z.string().optional(),
  }).optional(),
});

export const SignalSyncMessageSchema = z.object({
  sentMessage: SignalDataMessageSchema.optional(),
});

export const SignalReceiptMessageSchema = z.object({
  when: z.number(),
  isDelivery: z.boolean().optional(),
  isRead: z.boolean().optional(),
  timestamps: z.array(z.number()).optional(),
});

export const SignalTypingMessageSchema = z.object({
  action: z.enum(['STARTED', 'STOPPED']),
  timestamp: z.number(),
  groupId: z.string().optional(),
});

export const SignalEnvelopeSchema = z.object({
  source: z.string().optional(),
  sourceNumber: z.string().optional(),
  sourceUuid: z.string().optional(),
  sourceName: z.string().optional(),
  sourceDevice: z.number().optional(),
  timestamp: z.number(),
  dataMessage: SignalDataMessageSchema.optional(),
  syncMessage: SignalSyncMessageSchema.optional(),
  receiptMessage: SignalReceiptMessageSchema.optional(),
  typingMessage: SignalTypingMessageSchema.optional(),
});

export type SignalEnvelope = z.infer<typeof SignalEnvelopeSchema>;
export type SignalDataMessage = z.infer<typeof SignalDataMessageSchema>;
export type SignalAttachment = z.infer<typeof SignalAttachmentSchema>;

// ── SSE Event ────────────────────────────────────────────────

export const SignalSSEEventSchema = z.object({
  envelope: SignalEnvelopeSchema,
  account: z.string(),
});

export type SignalSSEEvent = z.infer<typeof SignalSSEEventSchema>;

/**
 * Parse and validate a signal-cli SSE event.
 */
export function parseSignalEvent(raw: string): SignalSSEEvent | null {
  try {
    const parsed = JSON.parse(raw);
    const result = SignalSSEEventSchema.safeParse(parsed);
    if (!result.success) {
      return null;
    }
    return result.data;
  } catch {
    return null;
  }
}
