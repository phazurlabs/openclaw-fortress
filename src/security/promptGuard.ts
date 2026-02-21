/**
 * A-01: Prompt Guard
 * 13+ injection patterns detection, PII-safe logging, session suspension.
 */
import { auditCritical, auditWarn } from './auditLogger.js';
import { redactPII } from './piiDetector.js';

export interface PromptGuardResult {
  safe: boolean;
  patterns: string[];
  action: 'allow' | 'warn' | 'block' | 'suspend';
}

// Injection patterns — ordered by severity
const INJECTION_PATTERNS: Array<{ name: string; pattern: RegExp; severity: 'warn' | 'block' | 'suspend' }> = [
  // System prompt extraction
  { name: 'system_prompt_extract', pattern: /(?:ignore|forget|disregard)\s+(?:all\s+)?(?:previous|prior|above|system)\s+(?:instructions?|prompts?|rules?)/i, severity: 'suspend' },
  { name: 'reveal_instructions', pattern: /(?:reveal|show|display|print|output|repeat)\s+(?:your|the|system)\s+(?:instructions?|prompts?|rules?|guidelines?)/i, severity: 'block' },
  // Role manipulation
  { name: 'role_override', pattern: /you\s+are\s+(?:now|no\s+longer)\s+/i, severity: 'block' },
  { name: 'jailbreak_dan', pattern: /\b(?:DAN|do\s+anything\s+now|STAN|DUDE|developer\s+mode)\b/i, severity: 'suspend' },
  // Delimiter injection
  { name: 'delimiter_injection', pattern: /(?:```system|<\|system\|>|<\|im_start\|>|\[SYSTEM\]|###\s*System)/i, severity: 'suspend' },
  // Output manipulation
  { name: 'output_format_hijack', pattern: /(?:respond\s+only\s+with|your\s+(?:first|only)\s+word\s+(?:must|should)\s+be)/i, severity: 'warn' },
  // Data exfiltration
  { name: 'data_exfil', pattern: /(?:encode|convert|translate)\s+(?:the\s+)?(?:system|instructions?|prompt)\s+(?:to|into|as)\s+(?:base64|hex|binary|rot13)/i, severity: 'suspend' },
  // Payload injection
  { name: 'code_injection', pattern: /(?:eval|exec|import|require|__proto__|constructor\s*\[)/i, severity: 'block' },
  { name: 'sql_injection', pattern: /(?:;\s*DROP\s|UNION\s+SELECT|OR\s+1\s*=\s*1|'\s*OR\s*')/i, severity: 'block' },
  { name: 'xss_injection', pattern: /<script[\s>]|javascript:|on(?:load|error|click)\s*=/i, severity: 'block' },
  // Recursive prompt
  { name: 'recursive_prompt', pattern: /(?:repeat\s+this\s+(?:message|prompt)\s+(?:\d+|forever|infinitely))/i, severity: 'block' },
  // Token smuggling
  { name: 'token_smuggling', pattern: /(?:ignore\s+safety|bypass\s+(?:filter|content|safety))/i, severity: 'suspend' },
  // Markdown/formatting exploit
  { name: 'markdown_exploit', pattern: /!\[(?:.*?)\]\((?:https?|ftp|data):\/\/(?:.*?)\)/i, severity: 'warn' },
];

/**
 * Scan input text against all injection patterns.
 */
export function scanPrompt(text: string): PromptGuardResult {
  const matches: string[] = [];
  let maxSeverity: 'allow' | 'warn' | 'block' | 'suspend' = 'allow';

  for (const { name, pattern, severity } of INJECTION_PATTERNS) {
    if (pattern.test(text)) {
      matches.push(name);
      if (severityRank(severity) > severityRank(maxSeverity)) {
        maxSeverity = severity;
      }
    }
  }

  if (matches.length > 0) {
    const safeText = redactPII(text.slice(0, 200));
    if (maxSeverity === 'suspend' || maxSeverity === 'block') {
      auditCritical('prompt_injection_detected', {
        details: { patterns: matches, severity: maxSeverity, preview: safeText },
      });
    } else {
      auditWarn('prompt_injection_warning', {
        details: { patterns: matches, severity: maxSeverity, preview: safeText },
      });
    }
  }

  return {
    safe: matches.length === 0,
    patterns: matches,
    action: maxSeverity,
  };
}

function severityRank(s: string): number {
  switch (s) {
    case 'suspend': return 3;
    case 'block': return 2;
    case 'warn': return 1;
    default: return 0;
  }
}
