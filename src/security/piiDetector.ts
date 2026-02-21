/**
 * P-02: PII Detector
 * Detect PII (phone, SSN, CC, email, gov ID) in text and redact.
 */

export interface PIIMatch {
  type: PIIType;
  value: string;
  start: number;
  end: number;
}

export type PIIType = 'phone' | 'ssn' | 'credit_card' | 'email' | 'gov_id';

const PII_PATTERNS: Array<{ type: PIIType; pattern: RegExp }> = [
  // US phone numbers: +1XXXXXXXXXX, (XXX) XXX-XXXX, XXX-XXX-XXXX
  { type: 'phone', pattern: /\+1\d{10}|\(\d{3}\)\s?\d{3}[-.]?\d{4}|\b\d{3}[-.]?\d{3}[-.]?\d{4}\b/g },
  // SSN: XXX-XX-XXXX
  { type: 'ssn', pattern: /\b\d{3}-\d{2}-\d{4}\b/g },
  // Credit card: 16 digits with optional separators
  { type: 'credit_card', pattern: /\b(?:\d{4}[-\s]?){3}\d{4}\b/g },
  // Email
  { type: 'email', pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g },
  // Generic Gov ID (passport-like patterns)
  { type: 'gov_id', pattern: /\b[A-Z]{1,2}\d{6,9}\b/g },
];

/**
 * Scan text for PII matches.
 */
export function detectPII(text: string): PIIMatch[] {
  const matches: PIIMatch[] = [];

  for (const { type, pattern } of PII_PATTERNS) {
    // Reset lastIndex for global patterns
    const regex = new RegExp(pattern.source, pattern.flags);
    let match: RegExpExecArray | null;
    while ((match = regex.exec(text)) !== null) {
      matches.push({
        type,
        value: match[0],
        start: match.index,
        end: match.index + match[0].length,
      });
    }
  }

  return matches.sort((a, b) => a.start - b.start);
}

/**
 * Redact all PII in text with [REDACTED:type].
 */
export function redactPII(text: string): string {
  const matches = detectPII(text);
  if (matches.length === 0) return text;

  let result = '';
  let lastEnd = 0;

  for (const m of matches) {
    // Skip overlapping matches
    if (m.start < lastEnd) continue;
    result += text.slice(lastEnd, m.start);
    result += `[REDACTED:${m.type}]`;
    lastEnd = m.end;
  }

  result += text.slice(lastEnd);
  return result;
}

/**
 * Check if text contains any PII.
 */
export function containsPII(text: string): boolean {
  return detectPII(text).length > 0;
}
