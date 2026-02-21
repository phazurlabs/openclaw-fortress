/**
 * G-02: Path Security
 * Session ID validation, directory jail checks, null byte blocking.
 */
import { resolve, relative, normalize } from 'node:path';

// Session IDs: alphanumeric + hyphens only, 8-128 chars
const SESSION_ID_REGEX = /^[a-zA-Z0-9-]{8,128}$/;

/**
 * Validate a session ID is safe for filesystem use.
 */
export function isValidSessionId(id: string): boolean {
  if (!SESSION_ID_REGEX.test(id)) return false;
  if (id.includes('..')) return false;
  if (id.includes('\0')) return false;
  return true;
}

/**
 * Check that a resolved path is inside the jail directory.
 * Prevents path traversal attacks.
 */
export function isInsideJail(targetPath: string, jailDir: string): boolean {
  const resolvedTarget = resolve(normalize(targetPath));
  const resolvedJail = resolve(normalize(jailDir));

  // Ensure target starts with jail path
  const rel = relative(resolvedJail, resolvedTarget);
  if (rel.startsWith('..') || resolve(resolvedJail, rel) !== resolvedTarget) {
    return false;
  }
  return true;
}

/**
 * Block null bytes in any user-supplied string (path, session id, etc).
 */
export function containsNullByte(input: string): boolean {
  return input.includes('\0');
}

/**
 * Sanitize a path segment (filename or session ID) for safe filesystem use.
 * Removes anything that's not alphanumeric, hyphen, underscore, or period.
 */
export function sanitizePathSegment(segment: string): string {
  return segment.replace(/[^a-zA-Z0-9._-]/g, '');
}

/**
 * Full path validation: check for null bytes, traversal, and jail escape.
 */
export function validatePath(
  userInput: string,
  jailDir: string,
): { ok: boolean; resolved?: string; reason?: string } {
  if (containsNullByte(userInput)) {
    return { ok: false, reason: 'Null byte in path' };
  }

  if (userInput.includes('..')) {
    return { ok: false, reason: 'Path traversal detected' };
  }

  const resolved = resolve(jailDir, userInput);
  if (!isInsideJail(resolved, jailDir)) {
    return { ok: false, reason: 'Path escapes jail directory' };
  }

  return { ok: true, resolved };
}
