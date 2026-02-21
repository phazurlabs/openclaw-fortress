/**
 * P-03: Encrypted Store
 * AES-256-GCM encrypt/decrypt with HKDF key derivation
 */
import {
  createCipheriv,
  createDecipheriv,
  randomBytes,
  hkdfSync,
} from 'node:crypto';
import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12; // 96 bits for GCM
const TAG_LENGTH = 16;
const SALT_LENGTH = 16;

/**
 * Derive a 256-bit key from master key using HKDF.
 */
function deriveKey(masterKey: string, salt: Buffer, info: string): Buffer {
  return Buffer.from(
    hkdfSync('sha256', masterKey, salt, info, 32),
  );
}

/**
 * Encrypt plaintext with AES-256-GCM.
 * Returns: salt(16) + iv(12) + tag(16) + ciphertext
 */
export function encrypt(plaintext: string, masterKey: string, info = 'openclaw-store'): Buffer {
  const salt = randomBytes(SALT_LENGTH);
  const key = deriveKey(masterKey, salt, info);
  const iv = randomBytes(IV_LENGTH);

  const cipher = createCipheriv(ALGORITHM, key, iv);
  const encrypted = Buffer.concat([
    cipher.update(plaintext, 'utf8'),
    cipher.final(),
  ]);
  const tag = cipher.getAuthTag();

  return Buffer.concat([salt, iv, tag, encrypted]);
}

/**
 * Decrypt AES-256-GCM ciphertext.
 */
export function decrypt(data: Buffer, masterKey: string, info = 'openclaw-store'): string {
  if (data.length < SALT_LENGTH + IV_LENGTH + TAG_LENGTH) {
    throw new Error('Encrypted data too short — possible tampering');
  }

  const salt = data.subarray(0, SALT_LENGTH);
  const iv = data.subarray(SALT_LENGTH, SALT_LENGTH + IV_LENGTH);
  const tag = data.subarray(SALT_LENGTH + IV_LENGTH, SALT_LENGTH + IV_LENGTH + TAG_LENGTH);
  const ciphertext = data.subarray(SALT_LENGTH + IV_LENGTH + TAG_LENGTH);

  const key = deriveKey(masterKey, salt, info);
  const decipher = createDecipheriv(ALGORITHM, key, iv);
  decipher.setAuthTag(tag);

  try {
    const decrypted = Buffer.concat([
      decipher.update(ciphertext),
      decipher.final(),
    ]);
    return decrypted.toString('utf8');
  } catch {
    throw new Error('Decryption failed — wrong key or tampered data');
  }
}

/**
 * Write encrypted JSON to a file.
 */
export function writeEncryptedJSON(filePath: string, data: unknown, masterKey: string): void {
  const dir = dirname(filePath);
  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true, mode: 0o700 });
  }
  const json = JSON.stringify(data, null, 2);
  const encrypted = encrypt(json, masterKey);
  writeFileSync(filePath, encrypted, { mode: 0o600 });
}

/**
 * Read encrypted JSON from a file.
 */
export function readEncryptedJSON<T = unknown>(filePath: string, masterKey: string): T {
  if (!existsSync(filePath)) {
    throw new Error(`Encrypted file not found: ${filePath}`);
  }
  const data = readFileSync(filePath);
  const json = decrypt(data, masterKey);
  return JSON.parse(json) as T;
}
