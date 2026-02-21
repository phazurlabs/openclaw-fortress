/**
 * S-01: Signal Daemon Guard
 * Loopback assertion, health check, process isolation guard.
 */
import { auditCritical, auditInfo, auditWarn } from './auditLogger.js';

/**
 * Assert that the signal-cli API URL is on loopback only.
 */
export function assertLoopback(apiUrl: string): boolean {
  try {
    const url = new URL(apiUrl);
    const hostname = url.hostname;
    const loopbacks = ['127.0.0.1', 'localhost', '::1', '[::1]'];
    if (!loopbacks.includes(hostname)) {
      auditCritical('signal_daemon_not_loopback', {
        details: { hostname, apiUrl },
      });
      return false;
    }
    return true;
  } catch {
    auditCritical('signal_daemon_invalid_url', { details: { apiUrl } });
    return false;
  }
}

/**
 * Health check the signal-cli daemon.
 */
export async function checkDaemonHealth(apiUrl: string): Promise<{
  healthy: boolean;
  version?: string;
  error?: string;
}> {
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 5000);

    const resp = await fetch(`${apiUrl}/v1/about`, {
      signal: controller.signal,
    });
    clearTimeout(timeout);

    if (!resp.ok) {
      return { healthy: false, error: `HTTP ${resp.status}` };
    }

    const data = await resp.json() as Record<string, unknown>;
    auditInfo('signal_daemon_healthy', { details: { version: data['version'] } });
    return { healthy: true, version: String(data['version'] ?? 'unknown') };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    auditWarn('signal_daemon_unhealthy', { details: { error: msg } });
    return { healthy: false, error: msg };
  }
}

/**
 * Check that signal-cli is not running as root.
 */
export function checkNotRoot(): boolean {
  if (typeof process.getuid === 'function' && process.getuid() === 0) {
    auditCritical('signal_running_as_root');
    return false;
  }
  return true;
}
