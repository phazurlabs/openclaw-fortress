/**
 * E-05: Input Validation
 * Signal message field validation, attachment MIME gating.
 */
import { auditWarn } from './auditLogger.js';

const MAX_MESSAGE_LENGTH = 10_000; // 10K chars
const MAX_ATTACHMENTS = 5;
const MAX_ATTACHMENT_SIZE = 10 * 1024 * 1024; // 10MB

const ALLOWED_MIME_TYPES = new Set([
  'image/jpeg',
  'image/png',
  'image/gif',
  'image/webp',
  'application/pdf',
  'text/plain',
  'audio/mpeg',
  'audio/ogg',
]);

const BLOCKED_EXTENSIONS = new Set([
  '.exe', '.bat', '.cmd', '.scr', '.pif', '.com',
  '.js', '.vbs', '.wsf', '.ps1', '.sh', '.bash',
  '.dll', '.sys', '.msi', '.jar', '.app',
]);

export interface ValidationResult {
  valid: boolean;
  errors: string[];
}

/**
 * Validate an incoming message's text field.
 */
export function validateMessageText(text: string): ValidationResult {
  const errors: string[] = [];

  if (typeof text !== 'string') {
    errors.push('Message text must be a string');
    return { valid: false, errors };
  }

  if (text.length > MAX_MESSAGE_LENGTH) {
    errors.push(`Message exceeds max length (${MAX_MESSAGE_LENGTH} chars)`);
  }

  // Check for null bytes
  if (text.includes('\0')) {
    errors.push('Message contains null bytes');
  }

  // Check for control characters (except newline, tab)
  const controlChars = text.match(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g);
  if (controlChars) {
    errors.push('Message contains invalid control characters');
  }

  return { valid: errors.length === 0, errors };
}

/**
 * Validate attachment MIME type and size.
 */
export function validateAttachment(
  contentType: string,
  filename?: string,
  size?: number,
): ValidationResult {
  const errors: string[] = [];

  // MIME type check
  if (!ALLOWED_MIME_TYPES.has(contentType)) {
    errors.push(`Blocked MIME type: ${contentType}`);
    auditWarn('blocked_mime_type', { details: { contentType } });
  }

  // Extension check
  if (filename) {
    const ext = filename.slice(filename.lastIndexOf('.')).toLowerCase();
    if (BLOCKED_EXTENSIONS.has(ext)) {
      errors.push(`Blocked file extension: ${ext}`);
      auditWarn('blocked_extension', { details: { filename, ext } });
    }
  }

  // Size check
  if (size !== undefined && size > MAX_ATTACHMENT_SIZE) {
    errors.push(`Attachment too large: ${size} bytes (max ${MAX_ATTACHMENT_SIZE})`);
  }

  return { valid: errors.length === 0, errors };
}

/**
 * Validate an array of attachments.
 */
export function validateAttachments(
  attachments: Array<{ contentType: string; filename?: string; size?: number }>,
): ValidationResult {
  const errors: string[] = [];

  if (attachments.length > MAX_ATTACHMENTS) {
    errors.push(`Too many attachments: ${attachments.length} (max ${MAX_ATTACHMENTS})`);
  }

  for (const att of attachments) {
    const result = validateAttachment(att.contentType, att.filename, att.size);
    errors.push(...result.errors);
  }

  return { valid: errors.length === 0, errors };
}
