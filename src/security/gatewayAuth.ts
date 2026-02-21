/**
 * G-01: Gateway Auth
 * Timing-safe token verification, entropy check, rate limiting.
 */
import { timingSafeEqual, randomBytes, createHash } from 'node:crypto';
import { auditWarn, auditCritical } from './auditLogger.js';

const MIN_TOKEN_ENTROPY_BYTES = 16; // 128-bit minimum

// Simple sliding-window rate limiter
const rateLimitMap = new Map<string, number[]>();
const RATE_WINDOW_MS = 60_000;
const MAX_REQUESTS_PER_WINDOW = 60;

/**
 * Check if a gateway token has sufficient entropy (>= 32 hex chars = 128 bits).
 */
export function checkTokenEntropy(token: string): boolean {
  // Must be hex or base64 with at least MIN_TOKEN_ENTROPY_BYTES bytes
  const hexBytes = token.replace(/[^0-9a-fA-F]/g, '').length / 2;
  return hexBytes >= MIN_TOKEN_ENTROPY_BYTES;
}

/**
 * Timing-safe token comparison.
 */
export function verifyToken(provided: string, expected: string): boolean {
  if (!provided || !expected) return false;

  const providedBuf = Buffer.from(provided, 'utf-8');
  const expectedBuf = Buffer.from(expected, 'utf-8');

  if (providedBuf.length !== expectedBuf.length) {
    // Constant-time: hash both to same length before comparing
    const h1 = Buffer.from(createHash('sha256').update(providedBuf).digest());
    const h2 = Buffer.from(createHash('sha256').update(expectedBuf).digest());
    return timingSafeEqual(h1, h2) && providedBuf.length === expectedBuf.length;
  }

  return timingSafeEqual(providedBuf, expectedBuf);
}

/**
 * Rate limit check by IP.
 * Returns true if allowed, false if rate limited.
 */
export function checkRateLimit(ip: string, maxRequests = MAX_REQUESTS_PER_WINDOW): boolean {
  const now = Date.now();
  let timestamps = rateLimitMap.get(ip) ?? [];

  // Prune expired entries
  timestamps = timestamps.filter(t => now - t < RATE_WINDOW_MS);

  if (timestamps.length >= maxRequests) {
    auditWarn('rate_limit_exceeded', { details: { ip } });
    return false;
  }

  timestamps.push(now);
  rateLimitMap.set(ip, timestamps);
  return true;
}

/**
 * Reset rate limit state (for testing).
 */
export function resetRateLimits(): void {
  rateLimitMap.clear();
}

/**
 * Generate a cryptographically secure gateway token.
 */
export function generateToken(bytes = 32): string {
  return randomBytes(bytes).toString('hex');
}

/**
 * Authenticate an incoming WS/HTTP request.
 */
export function authenticateRequest(
  providedToken: string | undefined,
  expectedToken: string | undefined,
  ip: string,
): { ok: boolean; reason?: string } {
  if (!expectedToken) {
    // No token configured = open gateway (warn)
    auditWarn('gateway_no_token_configured');
    return { ok: true };
  }

  if (!providedToken) {
    auditCritical('gateway_auth_missing_token', { details: { ip } });
    return { ok: false, reason: 'Missing authentication token' };
  }

  if (!checkRateLimit(ip)) {
    return { ok: false, reason: 'Rate limited' };
  }

  if (!verifyToken(providedToken, expectedToken)) {
    auditCritical('gateway_auth_failed', { details: { ip } });
    return { ok: false, reason: 'Invalid authentication token' };
  }

  return { ok: true };
}
