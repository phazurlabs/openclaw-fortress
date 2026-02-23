/**
 * Tests for Signal File Delivery tool.
 * Validates path security, size checks, and attachment encoding.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { handleSendFileViaSignal, type SignalFileDeliveryContext, type SendAttachmentFn } from '../../src/tools/signalFileDelivery.js';

// Mock auditLogger
vi.mock('../../src/security/auditLogger.js', () => ({
  auditWarn: vi.fn(),
  auditCritical: vi.fn(),
  auditInfo: vi.fn(),
  auditError: vi.fn(),
  audit: vi.fn(),
}));

// Mock file security policy
vi.mock('../../src/tools/fileSecurityPolicy.js', () => ({
  validateFilePath: vi.fn((path: string) => {
    if (path.includes('..')) return { ok: false, reason: 'Path traversal (..) detected' };
    if (path.includes('/etc/')) return { ok: false, reason: 'Path is outside allowed directories' };
    if (path.includes('valid-file')) return { ok: true, resolvedPath: `/Users/test/Desktop/${path}` };
    if (path.includes('large-file')) return { ok: true, resolvedPath: `/Users/test/Desktop/${path}` };
    if (path.includes('missing-file')) return { ok: true, resolvedPath: `/Users/test/Desktop/${path}` };
    return { ok: true, resolvedPath: path };
  }),
  MAX_FILE_SIZE_BYTES: 10_485_760,
}));

// Mock fs/promises
vi.mock('node:fs/promises', () => ({
  readFile: vi.fn(async (path: string) => {
    if (path.includes('missing-file')) throw Object.assign(new Error('ENOENT'), { code: 'ENOENT' });
    if (path.includes('large-file')) return Buffer.alloc(20_000_000); // 20MB
    return Buffer.from('test file content');
  }),
  stat: vi.fn(async (path: string) => {
    if (path.includes('missing-file')) throw Object.assign(new Error('ENOENT'), { code: 'ENOENT' });
    if (path.includes('large-file')) return { size: 20_000_000 };
    return { size: 17 }; // "test file content".length
  }),
}));

describe('Signal File Delivery', () => {
  let mockSendAttachment: SendAttachmentFn;
  let context: SignalFileDeliveryContext;

  beforeEach(() => {
    mockSendAttachment = vi.fn(async () => {});
    context = {
      sendAttachment: mockSendAttachment,
      contactId: '+12025551234',
      channel: 'signal',
    };
  });

  it('should reject paths with traversal', async () => {
    const result = await handleSendFileViaSignal({ path: '../../../etc/passwd' }, context);
    expect(result).toContain('Error');
    expect(result).toContain('traversal');
  });

  it('should reject paths outside allowed directories', async () => {
    const result = await handleSendFileViaSignal({ path: '/etc/shadow' }, context);
    expect(result).toContain('Error');
    expect(result).toContain('outside allowed');
  });

  it('should reject files exceeding size limit', async () => {
    const result = await handleSendFileViaSignal({ path: 'large-file.txt' }, context);
    expect(result).toContain('Error');
    expect(result).toContain('too large');
  });

  it('should send a valid file via Signal', async () => {
    const result = await handleSendFileViaSignal(
      { path: 'valid-file.txt', caption: 'Here you go' },
      context,
    );
    expect(result).toContain('sent via Signal');
    expect(result).toContain('valid-file.txt');
    expect(mockSendAttachment).toHaveBeenCalledTimes(1);

    const callArgs = vi.mocked(mockSendAttachment).mock.calls[0];
    expect(callArgs[2]).toBe('valid-file.txt'); // filename
    expect(callArgs[3]).toBe('text/plain');     // contentType
    expect(callArgs[4]).toBe('Here you go');    // caption
  });

  it('should return fallback when no Signal context is available', async () => {
    const result = await handleSendFileViaSignal({ path: 'valid-file.txt' }, undefined);
    expect(result).toContain('Signal delivery is not available');
    expect(result).toContain('valid-file.txt');
  });

  it('should handle missing file gracefully', async () => {
    const result = await handleSendFileViaSignal({ path: 'missing-file.txt' }, context);
    expect(result).toContain('Error');
    expect(result).toContain('not found');
  });

  it('should require path parameter', async () => {
    const result = await handleSendFileViaSignal({}, context);
    expect(result).toContain('Error');
    expect(result).toContain('path is required');
  });
});
