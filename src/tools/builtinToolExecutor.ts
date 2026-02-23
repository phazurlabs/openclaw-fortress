/**
 * Built-in Tool Executor
 * Implements 7 file tools with sandboxed security.
 */
import { readFile, writeFile, readdir, mkdir, stat } from 'node:fs/promises';
import { mkdirSync } from 'node:fs';
import { resolve, dirname, basename } from 'node:path';
import { homedir } from 'node:os';
import PDFDocument from 'pdfkit';
import { validateFilePath, ensureOutputDir, MAX_FILE_SIZE_BYTES } from './fileSecurityPolicy.js';
import { isBuiltinTool } from './builtinTools.js';
import { handleSendFileViaSignal, type SignalFileDeliveryContext } from './signalFileDelivery.js';
import { auditInfo, auditError } from '../security/auditLogger.js';
import type { ToolExecutor } from '../core/agent.js';

export type ToolExecutorWithContext = (
  name: string,
  input: Record<string, unknown>,
  context?: SignalFileDeliveryContext,
) => Promise<string>;

const home = homedir();

/**
 * Create a ToolExecutor for built-in file tools.
 * Optionally accepts a SignalFileDeliveryContext for the send-file tool.
 */
export function createBuiltinToolExecutor(
  signalContext?: SignalFileDeliveryContext,
): ToolExecutor {
  // Ensure output directory exists at startup
  ensureOutputDir();

  return async (name: string, input: Record<string, unknown>): Promise<string> => {
    if (!isBuiltinTool(name)) {
      throw new Error(`Unknown built-in tool: ${name}`);
    }

    switch (name) {
      case 'fortress_write_file':
        return handleWriteFile(input);
      case 'fortress_read_file':
        return handleReadFile(input);
      case 'fortress_list_directory':
        return handleListDirectory(input);
      case 'fortress_create_directory':
        return handleCreateDirectory(input);
      case 'fortress_generate_pdf':
        return handleGeneratePdf(input);
      case 'fortress_save_to_desktop':
        return handleSaveToDesktop(input);
      case 'fortress_send_file_via_signal':
        return handleSendFileViaSignal(input, signalContext);
      default:
        throw new Error(`Unhandled built-in tool: ${name}`);
    }
  };
}

// ── Tool Implementations ──────────────────────────────────────────

async function handleWriteFile(input: Record<string, unknown>): Promise<string> {
  const path = String(input['path'] ?? '');
  const content = String(input['content'] ?? '');

  if (!path) return 'Error: path is required';

  const validation = validateFilePath(path);
  if (!validation.ok) return `Error: ${validation.reason}`;

  // Check content size
  if (Buffer.byteLength(content, 'utf-8') > MAX_FILE_SIZE_BYTES) {
    return `Error: Content exceeds maximum file size of ${MAX_FILE_SIZE_BYTES} bytes`;
  }

  // Ensure parent directory exists
  mkdirSync(dirname(validation.resolvedPath), { recursive: true });

  await writeFile(validation.resolvedPath, content, 'utf-8');
  auditInfo('file_tool_write', { details: { path: validation.resolvedPath, bytes: Buffer.byteLength(content, 'utf-8') } });
  return `File written successfully: ${validation.resolvedPath}`;
}

async function handleReadFile(input: Record<string, unknown>): Promise<string> {
  const path = String(input['path'] ?? '');

  if (!path) return 'Error: path is required';

  const validation = validateFilePath(path);
  if (!validation.ok) return `Error: ${validation.reason}`;

  try {
    const stats = await stat(validation.resolvedPath);
    if (stats.size > MAX_FILE_SIZE_BYTES) {
      return `Error: File is too large (${stats.size} bytes). Maximum: ${MAX_FILE_SIZE_BYTES} bytes`;
    }

    const content = await readFile(validation.resolvedPath, 'utf-8');
    auditInfo('file_tool_read', { details: { path: validation.resolvedPath, bytes: stats.size } });
    return content;
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    if (msg.includes('ENOENT')) return `Error: File not found: ${validation.resolvedPath}`;
    return `Error reading file: ${msg}`;
  }
}

async function handleListDirectory(input: Record<string, unknown>): Promise<string> {
  const path = String(input['path'] ?? '');

  if (!path) return 'Error: path is required';

  const validation = validateFilePath(path);
  if (!validation.ok) return `Error: ${validation.reason}`;

  try {
    const entries = await readdir(validation.resolvedPath, { withFileTypes: true });
    if (entries.length === 0) return `Directory is empty: ${validation.resolvedPath}`;

    const lines = entries.map(entry => {
      const type = entry.isDirectory() ? '[DIR] ' : '      ';
      return `${type}${entry.name}`;
    });

    auditInfo('file_tool_list', { details: { path: validation.resolvedPath, count: entries.length } });
    return `Contents of ${validation.resolvedPath}:\n${lines.join('\n')}`;
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    if (msg.includes('ENOENT')) return `Error: Directory not found: ${validation.resolvedPath}`;
    if (msg.includes('ENOTDIR')) return `Error: Not a directory: ${validation.resolvedPath}`;
    return `Error listing directory: ${msg}`;
  }
}

async function handleCreateDirectory(input: Record<string, unknown>): Promise<string> {
  const path = String(input['path'] ?? '');

  if (!path) return 'Error: path is required';

  const validation = validateFilePath(path);
  if (!validation.ok) return `Error: ${validation.reason}`;

  await mkdir(validation.resolvedPath, { recursive: true });
  auditInfo('file_tool_mkdir', { details: { path: validation.resolvedPath } });
  return `Directory created: ${validation.resolvedPath}`;
}

async function handleGeneratePdf(input: Record<string, unknown>): Promise<string> {
  const title = String(input['title'] ?? '');
  const content = String(input['content'] ?? '');
  let outputPath = input['outputPath'] ? String(input['outputPath']) : '';

  if (!title) return 'Error: title is required';
  if (!content) return 'Error: content is required';

  // Default output path
  if (!outputPath) {
    const safeName = title.replace(/[^a-zA-Z0-9._-\s]/g, '').replace(/\s+/g, '_');
    outputPath = resolve(home, '.openclaw', 'output', `${safeName}.pdf`);
  }

  const validation = validateFilePath(outputPath);
  if (!validation.ok) return `Error: ${validation.reason}`;

  // Ensure parent directory exists
  mkdirSync(dirname(validation.resolvedPath), { recursive: true });

  try {
    await generatePdfFile(title, content, validation.resolvedPath);
    auditInfo('file_tool_pdf', { details: { path: validation.resolvedPath, title } });
    return `PDF generated successfully: ${validation.resolvedPath}`;
  } catch (err) {
    auditError('file_tool_pdf_failed', { details: { error: String(err) } });
    return `Error generating PDF: ${err instanceof Error ? err.message : String(err)}`;
  }
}

async function handleSaveToDesktop(input: Record<string, unknown>): Promise<string> {
  const filename = String(input['filename'] ?? '');
  const content = String(input['content'] ?? '');

  if (!filename) return 'Error: filename is required';
  if (filename.includes('/') || filename.includes('\\')) return 'Error: filename must not contain path separators';

  const desktopPath = resolve(home, 'Desktop', filename);
  return handleWriteFile({ path: desktopPath, content });
}

// ── PDF Generation ────────────────────────────────────────────────

function generatePdfFile(title: string, content: string, outputPath: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const doc = new PDFDocument({
      size: 'A4',
      margins: { top: 72, bottom: 72, left: 72, right: 72 },
      info: { Title: title, Creator: 'OpenClaw Fortress' },
    });

    const chunks: Buffer[] = [];
    doc.on('data', (chunk: Buffer) => chunks.push(chunk));
    doc.on('end', async () => {
      try {
        const buffer = Buffer.concat(chunks);
        const { writeFile: writeFileAsync } = await import('node:fs/promises');
        await writeFileAsync(outputPath, buffer);
        resolve();
      } catch (err) {
        reject(err);
      }
    });
    doc.on('error', reject);

    // Title
    doc.fontSize(24).font('Helvetica-Bold').text(title, { align: 'center' });
    doc.moveDown(1.5);

    // Parse lightweight markdown and render
    const lines = content.split('\n');
    for (const line of lines) {
      renderMarkdownLine(doc, line);
    }

    doc.end();
  });
}

function renderMarkdownLine(doc: PDFKit.PDFDocument, line: string): void {
  const trimmed = line.trimEnd();

  // Headings
  if (trimmed.startsWith('### ')) {
    doc.fontSize(14).font('Helvetica-Bold').text(trimmed.slice(4));
    doc.moveDown(0.3);
    doc.fontSize(11).font('Helvetica');
    return;
  }
  if (trimmed.startsWith('## ')) {
    doc.fontSize(16).font('Helvetica-Bold').text(trimmed.slice(3));
    doc.moveDown(0.4);
    doc.fontSize(11).font('Helvetica');
    return;
  }
  if (trimmed.startsWith('# ')) {
    doc.fontSize(20).font('Helvetica-Bold').text(trimmed.slice(2));
    doc.moveDown(0.5);
    doc.fontSize(11).font('Helvetica');
    return;
  }

  // Bullet lists
  if (trimmed.startsWith('- ') || trimmed.startsWith('* ')) {
    const text = trimmed.slice(2);
    doc.fontSize(11).font('Helvetica').text(`  \u2022  ${renderInlineFormatting(text)}`);
    doc.moveDown(0.2);
    return;
  }

  // Empty line
  if (trimmed === '') {
    doc.moveDown(0.5);
    return;
  }

  // Regular paragraph with inline formatting
  doc.fontSize(11).font('Helvetica').text(renderInlineFormatting(trimmed));
  doc.moveDown(0.2);
}

function renderInlineFormatting(text: string): string {
  // Strip bold/italic markers — PDFKit doesn't support inline mixed fonts easily
  // so we just render the text without the markers
  return text
    .replace(/\*\*(.+?)\*\*/g, '$1')
    .replace(/\*(.+?)\*/g, '$1');
}
