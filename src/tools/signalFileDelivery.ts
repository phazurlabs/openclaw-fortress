/**
 * Signal File Delivery
 * Sends a file from the server to a Signal contact as an attachment.
 * Reuses file sandbox validation and Signal REST API.
 */
import { readFile, stat } from 'node:fs/promises';
import { basename } from 'node:path';
import { validateFilePath, MAX_FILE_SIZE_BYTES } from './fileSecurityPolicy.js';
import { auditInfo, auditError } from '../security/auditLogger.js';

/**
 * Callback type for sending a file attachment via Signal.
 * Provided by the Signal channel when wiring the tool executor.
 */
export type SendAttachmentFn = (
  filePath: string,
  base64Data: string,
  filename: string,
  contentType: string,
  caption?: string,
) => Promise<void>;

export interface SignalFileDeliveryContext {
  sendAttachment?: SendAttachmentFn;
  contactId?: string;
  channel?: string;
}

/**
 * Handle the fortress_send_file_via_signal tool call.
 * Validates the path, reads the file, and triggers the send callback.
 */
export async function handleSendFileViaSignal(
  input: Record<string, unknown>,
  context?: SignalFileDeliveryContext,
): Promise<string> {
  const path = String(input['path'] ?? '');
  const caption = input['caption'] ? String(input['caption']) : undefined;

  if (!path) return 'Error: path is required';

  // Validate path against sandbox
  const validation = validateFilePath(path);
  if (!validation.ok) return `Error: ${validation.reason}`;

  // Check if Signal delivery context is available
  if (!context?.sendAttachment) {
    // File exists but can't be sent — return path for user reference
    auditInfo('file_delivery_no_signal', { details: { path: validation.resolvedPath } });
    return `File is at ${validation.resolvedPath} but Signal delivery is not available in this session. The file can be accessed on the server.`;
  }

  try {
    // Check file size
    const stats = await stat(validation.resolvedPath);
    if (stats.size > MAX_FILE_SIZE_BYTES) {
      return `Error: File is too large (${stats.size} bytes). Maximum for Signal delivery: ${MAX_FILE_SIZE_BYTES} bytes`;
    }

    // Read file and encode
    const buffer = await readFile(validation.resolvedPath);
    const base64Data = buffer.toString('base64');
    const filename = basename(validation.resolvedPath);
    const contentType = inferContentType(filename);

    // Send via Signal
    await context.sendAttachment(
      validation.resolvedPath,
      base64Data,
      filename,
      contentType,
      caption,
    );

    auditInfo('file_delivered_via_signal', {
      contactId: context.contactId,
      details: {
        path: validation.resolvedPath,
        filename,
        size: stats.size,
        contentType,
      },
    });

    return `File sent via Signal: ${filename} (${stats.size} bytes)${caption ? ` — "${caption}"` : ''}`;
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    auditError('file_delivery_failed', {
      contactId: context.contactId,
      details: { path: validation.resolvedPath, error: msg },
    });
    if (msg.includes('ENOENT')) return `Error: File not found: ${validation.resolvedPath}`;
    return `Error sending file via Signal: ${msg}`;
  }
}

/**
 * Infer MIME content type from filename extension.
 */
function inferContentType(filename: string): string {
  const ext = filename.split('.').pop()?.toLowerCase();
  switch (ext) {
    case 'pdf': return 'application/pdf';
    case 'txt': return 'text/plain';
    case 'md': return 'text/plain';
    case 'json': return 'application/json';
    case 'csv': return 'text/csv';
    case 'png': return 'image/png';
    case 'jpg': case 'jpeg': return 'image/jpeg';
    case 'gif': return 'image/gif';
    case 'webp': return 'image/webp';
    default: return 'application/octet-stream';
  }
}
