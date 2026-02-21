/**
 * Tests for P-03: Encrypted Store
 * encrypt/decrypt roundtrip, tamper detection, writeEncryptedJSON/readEncryptedJSON
 */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  encrypt,
  decrypt,
  writeEncryptedJSON,
  readEncryptedJSON,
} from '../../src/security/encryptedStore.js';

describe('encryptedStore', () => {
  const masterKey = 'test-master-key-for-encryption-32chars!';
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), 'openclaw-test-'));
  });

  afterEach(() => {
    if (existsSync(tmpDir)) {
      rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  // ── encrypt / decrypt roundtrip ─────────────────────────────

  describe('encrypt / decrypt roundtrip', () => {
    it('should encrypt and decrypt a simple string', () => {
      const plaintext = 'Hello, World!';
      const encrypted = encrypt(plaintext, masterKey);
      const decrypted = decrypt(encrypted, masterKey);
      expect(decrypted).toBe(plaintext);
    });

    it('should encrypt and decrypt an empty string', () => {
      const plaintext = '';
      const encrypted = encrypt(plaintext, masterKey);
      const decrypted = decrypt(encrypted, masterKey);
      expect(decrypted).toBe(plaintext);
    });

    it('should encrypt and decrypt a long string', () => {
      const plaintext = 'x'.repeat(10000);
      const encrypted = encrypt(plaintext, masterKey);
      const decrypted = decrypt(encrypted, masterKey);
      expect(decrypted).toBe(plaintext);
    });

    it('should encrypt and decrypt unicode content', () => {
      const plaintext = 'Hello \u{1F600} \u4F60\u597D \u00E9\u00E8\u00EA \u0410\u0411\u0412';
      const encrypted = encrypt(plaintext, masterKey);
      const decrypted = decrypt(encrypted, masterKey);
      expect(decrypted).toBe(plaintext);
    });

    it('should encrypt and decrypt JSON strings', () => {
      const data = { name: 'Test', value: 42, nested: { arr: [1, 2, 3] } };
      const plaintext = JSON.stringify(data);
      const encrypted = encrypt(plaintext, masterKey);
      const decrypted = decrypt(encrypted, masterKey);
      expect(JSON.parse(decrypted)).toEqual(data);
    });

    it('should produce different ciphertext for same plaintext (random IV/salt)', () => {
      const plaintext = 'same input';
      const enc1 = encrypt(plaintext, masterKey);
      const enc2 = encrypt(plaintext, masterKey);
      expect(enc1.equals(enc2)).toBe(false);
    });

    it('should return a Buffer from encrypt', () => {
      const encrypted = encrypt('test', masterKey);
      expect(Buffer.isBuffer(encrypted)).toBe(true);
    });

    it('encrypted output should be at least salt(16) + iv(12) + tag(16) = 44 bytes', () => {
      const encrypted = encrypt('', masterKey);
      expect(encrypted.length).toBeGreaterThanOrEqual(44);
    });
  });

  // ── Tamper detection ────────────────────────────────────────

  describe('tamper detection', () => {
    it('should throw on wrong key', () => {
      const encrypted = encrypt('secret data', masterKey);
      expect(() => decrypt(encrypted, 'wrong-key-entirely')).toThrow();
    });

    it('should throw when ciphertext is tampered', () => {
      const encrypted = encrypt('secret data', masterKey);
      // Tamper with a byte in the ciphertext area (after salt+iv+tag = 44 bytes)
      if (encrypted.length > 44) {
        encrypted[44] = (encrypted[44]! ^ 0xff);
      }
      expect(() => decrypt(encrypted, masterKey)).toThrow();
    });

    it('should throw when auth tag is tampered', () => {
      const encrypted = encrypt('secret data', masterKey);
      // Auth tag is at bytes 28..44 (after salt=16 and iv=12)
      encrypted[28] = (encrypted[28]! ^ 0xff);
      expect(() => decrypt(encrypted, masterKey)).toThrow();
    });

    it('should throw for data too short', () => {
      const tooShort = Buffer.alloc(10);
      expect(() => decrypt(tooShort, masterKey)).toThrow('Encrypted data too short');
    });

    it('should throw for empty buffer', () => {
      expect(() => decrypt(Buffer.alloc(0), masterKey)).toThrow('Encrypted data too short');
    });

    it('should use custom info parameter for key derivation', () => {
      const encrypted = encrypt('test', masterKey, 'custom-info');
      // Should decrypt with same info
      const decrypted = decrypt(encrypted, masterKey, 'custom-info');
      expect(decrypted).toBe('test');
      // Should fail with different info
      expect(() => decrypt(encrypted, masterKey, 'wrong-info')).toThrow();
    });
  });

  // ── writeEncryptedJSON / readEncryptedJSON ──────────────────

  describe('writeEncryptedJSON / readEncryptedJSON', () => {
    it('should write and read back a JSON object', () => {
      const data = { key: 'value', count: 42 };
      const filePath = join(tmpDir, 'test.enc');
      writeEncryptedJSON(filePath, data, masterKey);
      const result = readEncryptedJSON<typeof data>(filePath, masterKey);
      expect(result).toEqual(data);
    });

    it('should write and read back an array', () => {
      const data = [1, 'two', { three: 3 }];
      const filePath = join(tmpDir, 'array.enc');
      writeEncryptedJSON(filePath, data, masterKey);
      const result = readEncryptedJSON<typeof data>(filePath, masterKey);
      expect(result).toEqual(data);
    });

    it('should write and read back nested objects', () => {
      const data = {
        users: [
          { id: 1, name: 'Alice' },
          { id: 2, name: 'Bob' },
        ],
        metadata: { version: '1.0' },
      };
      const filePath = join(tmpDir, 'nested.enc');
      writeEncryptedJSON(filePath, data, masterKey);
      const result = readEncryptedJSON(filePath, masterKey);
      expect(result).toEqual(data);
    });

    it('should create directories if they do not exist', () => {
      const nestedDir = join(tmpDir, 'sub', 'dir');
      const filePath = join(nestedDir, 'deep.enc');
      writeEncryptedJSON(filePath, { test: true }, masterKey);
      expect(existsSync(filePath)).toBe(true);
      const result = readEncryptedJSON(filePath, masterKey);
      expect(result).toEqual({ test: true });
    });

    it('should throw if file does not exist on read', () => {
      const filePath = join(tmpDir, 'nonexistent.enc');
      expect(() => readEncryptedJSON(filePath, masterKey)).toThrow('Encrypted file not found');
    });

    it('should fail to read with wrong key', () => {
      const filePath = join(tmpDir, 'wrongkey.enc');
      writeEncryptedJSON(filePath, { secret: true }, masterKey);
      expect(() => readEncryptedJSON(filePath, 'wrong-key')).toThrow();
    });

    it('should overwrite existing file', () => {
      const filePath = join(tmpDir, 'overwrite.enc');
      writeEncryptedJSON(filePath, { version: 1 }, masterKey);
      writeEncryptedJSON(filePath, { version: 2 }, masterKey);
      const result = readEncryptedJSON<{ version: number }>(filePath, masterKey);
      expect(result.version).toBe(2);
    });

    it('should handle null value', () => {
      const filePath = join(tmpDir, 'null.enc');
      writeEncryptedJSON(filePath, null, masterKey);
      const result = readEncryptedJSON(filePath, masterKey);
      expect(result).toBeNull();
    });

    it('should handle boolean values', () => {
      const filePath = join(tmpDir, 'bool.enc');
      writeEncryptedJSON(filePath, true, masterKey);
      const result = readEncryptedJSON(filePath, masterKey);
      expect(result).toBe(true);
    });
  });
});
