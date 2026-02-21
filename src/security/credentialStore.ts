/**
 * P-04: Credential Store
 * OS keychain with env var fallback.
 * Uses keytar for macOS Keychain / Linux libsecret / Windows Credential Vault.
 * Falls back to env vars if keytar is unavailable.
 */

const SERVICE_NAME = 'openclaw-fortress';

let keytarModule: typeof import('keytar') | null = null;
let keytarFailed = false;

async function getKeytar(): Promise<typeof import('keytar') | null> {
  if (keytarFailed) return null;
  if (keytarModule) return keytarModule;

  try {
    keytarModule = await import('keytar');
    return keytarModule;
  } catch {
    keytarFailed = true;
    return null;
  }
}

/**
 * Store a credential in the OS keychain, falling back to env var.
 */
export async function setCredential(key: string, value: string): Promise<'keychain' | 'memory'> {
  const keytar = await getKeytar();
  if (keytar) {
    await keytar.setPassword(SERVICE_NAME, key, value);
    return 'keychain';
  }
  // Fallback: store in process env (ephemeral)
  process.env[`OPENCLAW_CRED_${key.toUpperCase()}`] = value;
  return 'memory';
}

/**
 * Retrieve a credential from keychain or env var.
 */
export async function getCredential(key: string, envFallback?: string): Promise<string | null> {
  const keytar = await getKeytar();
  if (keytar) {
    const val = await keytar.getPassword(SERVICE_NAME, key);
    if (val) return val;
  }

  // Env var fallback chain
  const envVal = process.env[`OPENCLAW_CRED_${key.toUpperCase()}`]
    ?? (envFallback ? process.env[envFallback] : undefined);

  return envVal ?? null;
}

/**
 * Delete a credential from keychain.
 */
export async function deleteCredential(key: string): Promise<boolean> {
  const keytar = await getKeytar();
  if (keytar) {
    return keytar.deletePassword(SERVICE_NAME, key);
  }
  delete process.env[`OPENCLAW_CRED_${key.toUpperCase()}`];
  return true;
}

/**
 * Check if keytar (OS keychain) is available.
 */
export async function isKeychainAvailable(): Promise<boolean> {
  return (await getKeytar()) !== null;
}
