/**
 * S-02: Signal Allowlist
 * DM allowlist enforcement, silent drop, rate limiting.
 */
import { auditWarn, auditInfo } from './auditLogger.js';

// Rate limit state per contact
const contactRates = new Map<string, number[]>();

export interface AllowlistConfig {
  allowedNumbers: string[];
  allowedGroups: string[];
  rateLimitPerMinute: number;
}

/**
 * Check if a phone number is on the DM allowlist.
 * Empty allowlist = allow all (open mode).
 */
export function isNumberAllowed(number: string, allowedNumbers: string[]): boolean {
  if (allowedNumbers.length === 0) return true; // open mode
  return allowedNumbers.includes(number);
}

/**
 * Check if a group ID is on the group allowlist.
 */
export function isGroupAllowed(groupId: string, allowedGroups: string[]): boolean {
  if (allowedGroups.length === 0) return true;
  return allowedGroups.includes(groupId);
}

/**
 * Full allowlist check for an incoming message.
 * Returns { allowed, reason } — messages that fail are silently dropped.
 */
export function checkAllowlist(
  sender: string,
  groupId: string | undefined,
  config: AllowlistConfig,
): { allowed: boolean; reason?: string } {
  // Group message check
  if (groupId) {
    if (!isGroupAllowed(groupId, config.allowedGroups)) {
      auditWarn('signal_group_blocked', { details: { groupId } });
      return { allowed: false, reason: 'Group not in allowlist' };
    }
  }

  // DM allowlist check
  if (!isNumberAllowed(sender, config.allowedNumbers)) {
    auditWarn('signal_number_blocked', { contactId: sender });
    return { allowed: false, reason: 'Number not in allowlist' };
  }

  // Rate limit check
  if (!checkContactRateLimit(sender, config.rateLimitPerMinute)) {
    auditWarn('signal_rate_limited', { contactId: sender });
    return { allowed: false, reason: 'Rate limited' };
  }

  return { allowed: true };
}

/**
 * Per-contact rate limiting (sliding window).
 */
function checkContactRateLimit(contactId: string, maxPerMinute: number): boolean {
  const now = Date.now();
  let timestamps = contactRates.get(contactId) ?? [];
  timestamps = timestamps.filter(t => now - t < 60_000);

  if (timestamps.length >= maxPerMinute) {
    return false;
  }

  timestamps.push(now);
  contactRates.set(contactId, timestamps);
  return true;
}

/**
 * Reset rate limits (for testing).
 */
export function resetContactRateLimits(): void {
  contactRates.clear();
}
