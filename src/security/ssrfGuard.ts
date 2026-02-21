/**
 * G-03: SSRF Guard
 * Private IP blocking, DNS rebinding prevention, scheme blocking.
 */
import { auditCritical } from './auditLogger.js';

const ALLOWED_SCHEMES = new Set(['http:', 'https:']);

// Private / reserved IPv4 ranges
const PRIVATE_RANGES = [
  { start: ip4ToNum('10.0.0.0'), end: ip4ToNum('10.255.255.255') },
  { start: ip4ToNum('172.16.0.0'), end: ip4ToNum('172.31.255.255') },
  { start: ip4ToNum('192.168.0.0'), end: ip4ToNum('192.168.255.255') },
  { start: ip4ToNum('127.0.0.0'), end: ip4ToNum('127.255.255.255') },
  { start: ip4ToNum('169.254.0.0'), end: ip4ToNum('169.254.255.255') }, // link-local
  { start: ip4ToNum('0.0.0.0'), end: ip4ToNum('0.255.255.255') },
];

function ip4ToNum(ip: string): number {
  const parts = ip.split('.').map(Number);
  return ((parts[0]! << 24) | (parts[1]! << 16) | (parts[2]! << 8) | parts[3]!) >>> 0;
}

/**
 * Check if an IPv4 address is in a private/reserved range.
 */
export function isPrivateIP(ip: string): boolean {
  // IPv6 loopback
  if (ip === '::1' || ip === '::ffff:127.0.0.1') return true;

  // Check IPv4
  const num = ip4ToNum(ip);
  return PRIVATE_RANGES.some(r => num >= r.start && num <= r.end);
}

/**
 * Validate a URL is safe to fetch (not SSRF).
 */
export function validateURL(
  urlString: string,
  opts?: { allowPrivate?: boolean },
): { ok: boolean; reason?: string; parsed?: URL } {
  let parsed: URL;
  try {
    parsed = new URL(urlString);
  } catch {
    return { ok: false, reason: 'Invalid URL' };
  }

  // Scheme check
  if (!ALLOWED_SCHEMES.has(parsed.protocol)) {
    auditCritical('ssrf_blocked_scheme', { details: { url: urlString, scheme: parsed.protocol } });
    return { ok: false, reason: `Blocked scheme: ${parsed.protocol}` };
  }

  // Block credentials in URL
  if (parsed.username || parsed.password) {
    return { ok: false, reason: 'Credentials in URL not allowed' };
  }

  // Hostname checks
  const hostname = parsed.hostname;

  // Block DNS rebinding via numeric IP check
  if (!opts?.allowPrivate && isIPAddress(hostname)) {
    if (isPrivateIP(hostname)) {
      auditCritical('ssrf_blocked_private_ip', { details: { url: urlString, ip: hostname } });
      return { ok: false, reason: `Private IP blocked: ${hostname}` };
    }
  }

  // Block common DNS rebinding hostnames
  const lower = hostname.toLowerCase();
  if (lower === 'localhost' || lower.endsWith('.local') || lower.endsWith('.internal')) {
    if (!opts?.allowPrivate) {
      auditCritical('ssrf_blocked_hostname', { details: { url: urlString, hostname } });
      return { ok: false, reason: `Blocked hostname: ${hostname}` };
    }
  }

  return { ok: true, parsed };
}

function isIPAddress(hostname: string): boolean {
  // IPv4
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) return true;
  // IPv6 (bracketed in URL, but URL parser strips brackets)
  if (hostname.includes(':')) return true;
  return false;
}
