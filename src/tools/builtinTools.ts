/**
 * Built-in Tool Definitions
 * 7 file tools for the Anthropic tool_use API.
 */
import type { ToolDefinition } from '../types/index.js';

const TOOL_PREFIX = 'fortress_';

export const BUILTIN_TOOL_NAMES = [
  `${TOOL_PREFIX}write_file`,
  `${TOOL_PREFIX}read_file`,
  `${TOOL_PREFIX}list_directory`,
  `${TOOL_PREFIX}create_directory`,
  `${TOOL_PREFIX}generate_pdf`,
  `${TOOL_PREFIX}save_to_desktop`,
  `${TOOL_PREFIX}send_file_via_signal`,
] as const;

export type BuiltinToolName = (typeof BUILTIN_TOOL_NAMES)[number];

export function isBuiltinTool(name: string): name is BuiltinToolName {
  return (BUILTIN_TOOL_NAMES as readonly string[]).includes(name);
}

const builtinToolDefinitions: ToolDefinition[] = [
  {
    name: 'fortress_write_file',
    description:
      'Write text content to a file. Allowed directories: ~/Desktop, ~/Documents, ~/Downloads, ~/.openclaw/output/. Creates parent directories automatically.',
    input_schema: {
      type: 'object',
      properties: {
        path: {
          type: 'string',
          description:
            'File path to write to. Use ~/Desktop/filename.txt, ~/Documents/filename.txt, etc.',
        },
        content: {
          type: 'string',
          description: 'The text content to write to the file.',
        },
      },
      required: ['path', 'content'],
    },
  },
  {
    name: 'fortress_read_file',
    description:
      'Read a file from allowed directories (~/Desktop, ~/Documents, ~/Downloads, ~/.openclaw/output/) and return its content as text.',
    input_schema: {
      type: 'object',
      properties: {
        path: {
          type: 'string',
          description: 'File path to read from.',
        },
      },
      required: ['path'],
    },
  },
  {
    name: 'fortress_list_directory',
    description:
      'List files and directories in an allowed directory (~/Desktop, ~/Documents, ~/Downloads, ~/.openclaw/output/).',
    input_schema: {
      type: 'object',
      properties: {
        path: {
          type: 'string',
          description: 'Directory path to list.',
        },
      },
      required: ['path'],
    },
  },
  {
    name: 'fortress_create_directory',
    description:
      'Create a directory (and parent directories) inside an allowed directory.',
    input_schema: {
      type: 'object',
      properties: {
        path: {
          type: 'string',
          description: 'Directory path to create.',
        },
      },
      required: ['path'],
    },
  },
  {
    name: 'fortress_generate_pdf',
    description:
      'Generate a PDF document with a title and text/markdown content. Supports headings (# ## ###), bold (**text**), italic (*text*), and bullet lists (- item). Saves to ~/.openclaw/output/ by default.',
    input_schema: {
      type: 'object',
      properties: {
        title: {
          type: 'string',
          description: 'Title of the PDF document.',
        },
        content: {
          type: 'string',
          description:
            'Text or lightweight markdown content for the PDF body.',
        },
        outputPath: {
          type: 'string',
          description:
            'Optional output file path. Defaults to ~/.openclaw/output/{title}.pdf if not provided.',
        },
      },
      required: ['title', 'content'],
    },
  },
  {
    name: 'fortress_save_to_desktop',
    description:
      'Save content directly to the user\'s ~/Desktop with a given filename. A convenience shortcut for writing files to the Desktop.',
    input_schema: {
      type: 'object',
      properties: {
        filename: {
          type: 'string',
          description:
            'The filename (e.g., "report.txt", "notes.md"). Will be saved to ~/Desktop/.',
        },
        content: {
          type: 'string',
          description: 'The text content to save.',
        },
      },
      required: ['filename', 'content'],
    },
  },
  {
    name: 'fortress_send_file_via_signal',
    description:
      'Send a file from the server to the current Signal contact as an attachment. The file must be in an allowed directory (~/Desktop, ~/Documents, ~/Downloads, ~/.openclaw/output/). Maximum file size: 10MB.',
    input_schema: {
      type: 'object',
      properties: {
        path: {
          type: 'string',
          description:
            'Path to the file to send. Must be in an allowed directory.',
        },
        caption: {
          type: 'string',
          description:
            'Optional caption to include with the attachment.',
        },
      },
      required: ['path'],
    },
  },
];

/**
 * Get all built-in tool definitions.
 */
export function getBuiltinToolDefinitions(): ToolDefinition[] {
  return [...builtinToolDefinitions];
}
