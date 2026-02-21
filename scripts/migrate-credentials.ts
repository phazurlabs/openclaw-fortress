/**
 * =============================================================================
 * migrate-credentials.ts — Credential Migration to OS Keychain
 * =============================================================================
 * Migrates plaintext credentials from .env files to the operating system's
 * native keychain/credential store using the `keytar` library.
 *
 * Supported credential stores:
 *   - macOS:   Keychain Access
 *   - Linux:   libsecret (GNOME Keyring / KWallet)
 *   - Windows: Windows Credential Manager
 *
 * How it works:
 *   1. Reads the .env file from the project root (or specified path)
 *   2. Filters for variables prefixed with OPENCLAW_
 *   3. Stores each variable in the OS keychain under the service "openclaw-fortress"
 *   4. Optionally redacts the .env file after successful migration
 *
 * Usage:
 *   npx tsx scripts/migrate-credentials.ts
 *   npx tsx scripts/migrate-credentials.ts --env-file /path/to/.env
 *   npx tsx scripts/migrate-credentials.ts --dry-run
 *   npx tsx scripts/migrate-credentials.ts --redact
 *
 * Prerequisites:
 *   npm install keytar
 * =============================================================================
 */

import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Keychain service name used for all OpenClaw credentials */
const KEYCHAIN_SERVICE = "openclaw-fortress";

/** Prefix for environment variables that should be migrated */
const ENV_PREFIX = "OPENCLAW_";

/** Placeholder value written to .env after redaction */
const REDACTED_PLACEHOLDER = "MIGRATED_TO_KEYCHAIN";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface CredentialEntry {
  key: string;
  value: string;
  lineNumber: number;
}

interface MigrationResult {
  key: string;
  success: boolean;
  error?: string;
}

interface CliOptions {
  envFile: string;
  dryRun: boolean;
  redact: boolean;
  verbose: boolean;
  list: boolean;
  restore: boolean;
}

// ---------------------------------------------------------------------------
// Color helpers (no dependencies)
// ---------------------------------------------------------------------------

const colors = {
  red: (s: string) => `\x1b[31m${s}\x1b[0m`,
  green: (s: string) => `\x1b[32m${s}\x1b[0m`,
  yellow: (s: string) => `\x1b[33m${s}\x1b[0m`,
  cyan: (s: string) => `\x1b[36m${s}\x1b[0m`,
  dim: (s: string) => `\x1b[2m${s}\x1b[0m`,
};

const info = (msg: string) => console.log(`${colors.cyan("[INFO]")}  ${msg}`);
const ok = (msg: string) => console.log(`${colors.green("[ OK ]")}  ${msg}`);
const warn = (msg: string) => console.log(`${colors.yellow("[WARN]")}  ${msg}`);
const fail = (msg: string) => console.error(`${colors.red("[ERR ]")}  ${msg}`);

// ---------------------------------------------------------------------------
// Keytar dynamic import (may not be installed)
// ---------------------------------------------------------------------------

interface KeytarModule {
  setPassword(service: string, account: string, password: string): Promise<void>;
  getPassword(service: string, account: string): Promise<string | null>;
  deletePassword(service: string, account: string): Promise<boolean>;
  findCredentials(service: string): Promise<Array<{ account: string; password: string }>>;
}

async function loadKeytar(): Promise<KeytarModule> {
  try {
    // Dynamic import to allow graceful failure if not installed
    const keytar = await import("keytar");
    return keytar.default ?? keytar;
  } catch {
    fail("The 'keytar' package is not installed.");
    fail("Install it with: npm install keytar");
    console.error("");
    info("keytar provides native OS keychain integration:");
    console.error("  macOS   -> Keychain Access");
    console.error("  Linux   -> libsecret (GNOME Keyring / KWallet)");
    console.error("  Windows -> Windows Credential Manager");
    process.exit(1);
  }
}

// ---------------------------------------------------------------------------
// .env file parsing
// ---------------------------------------------------------------------------

/**
 * Parse a .env file and extract OPENCLAW_ prefixed credentials.
 * Handles:
 *   - Comments (lines starting with #)
 *   - Empty lines
 *   - Quoted values (single and double quotes)
 *   - Inline comments
 *   - Whitespace around = sign
 */
function parseEnvFile(filePath: string): CredentialEntry[] {
  if (!existsSync(filePath)) {
    fail(`Environment file not found: ${filePath}`);
    process.exit(1);
  }

  const content = readFileSync(filePath, "utf-8");
  const lines = content.split("\n");
  const credentials: CredentialEntry[] = [];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!.trim();

    // Skip empty lines and comments
    if (!line || line.startsWith("#")) continue;

    // Match KEY=VALUE pattern
    const match = line.match(/^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/);
    if (!match) continue;

    const key = match[1]!;
    let value = match[2]!;

    // Only process OPENCLAW_ prefixed variables
    if (!key.startsWith(ENV_PREFIX)) continue;

    // Skip already-migrated values
    if (value === REDACTED_PLACEHOLDER) {
      info(`Skipping already-migrated: ${key}`);
      continue;
    }

    // Remove surrounding quotes
    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1);
    }

    // Remove inline comments (only for unquoted values)
    const commentIdx = value.indexOf(" #");
    if (commentIdx !== -1) {
      value = value.slice(0, commentIdx).trim();
    }

    // Skip empty values
    if (!value) {
      warn(`Skipping empty value: ${key}`);
      continue;
    }

    credentials.push({ key, value, lineNumber: i + 1 });
  }

  return credentials;
}

// ---------------------------------------------------------------------------
// Redact .env file (replace values with placeholder)
// ---------------------------------------------------------------------------

function redactEnvFile(filePath: string, migratedKeys: Set<string>): void {
  const content = readFileSync(filePath, "utf-8");
  const lines = content.split("\n");

  const redactedLines = lines.map((line) => {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) return line;

    const match = trimmed.match(/^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/);
    if (!match) return line;

    const key = match[1]!;
    if (migratedKeys.has(key)) {
      return `${key}=${REDACTED_PLACEHOLDER}`;
    }
    return line;
  });

  writeFileSync(filePath, redactedLines.join("\n"), "utf-8");
}

// ---------------------------------------------------------------------------
// CLI argument parsing
// ---------------------------------------------------------------------------

function parseArgs(): CliOptions {
  const args = process.argv.slice(2);

  // Determine project root (directory containing this script's parent)
  const scriptDir = dirname(fileURLToPath(import.meta.url));
  const projectRoot = resolve(scriptDir, "..");

  const options: CliOptions = {
    envFile: resolve(projectRoot, ".env"),
    dryRun: false,
    redact: false,
    verbose: false,
    list: false,
    restore: false,
  };

  for (let i = 0; i < args.length; i++) {
    switch (args[i]) {
      case "--env-file":
        options.envFile = resolve(args[++i] ?? "");
        break;
      case "--dry-run":
        options.dryRun = true;
        break;
      case "--redact":
        options.redact = true;
        break;
      case "--verbose":
      case "-v":
        options.verbose = true;
        break;
      case "--list":
        options.list = true;
        break;
      case "--restore":
        options.restore = true;
        break;
      case "--help":
      case "-h":
        printUsage();
        process.exit(0);
        break;
      default:
        fail(`Unknown argument: ${args[i]}`);
        printUsage();
        process.exit(1);
    }
  }

  return options;
}

function printUsage(): void {
  console.log(`
Usage: npx tsx scripts/migrate-credentials.ts [OPTIONS]

Migrate OPENCLAW_ credentials from .env to OS keychain.

Options:
  --env-file <path>   Path to .env file (default: <project-root>/.env)
  --dry-run           Show what would be migrated without making changes
  --redact            Replace migrated values in .env with placeholder
  --verbose, -v       Show detailed output
  --list              List all credentials currently in the keychain
  --restore           Restore credentials from keychain back to .env
  -h, --help          Show this help message

Examples:
  npx tsx scripts/migrate-credentials.ts                    # Migrate all
  npx tsx scripts/migrate-credentials.ts --dry-run          # Preview only
  npx tsx scripts/migrate-credentials.ts --redact           # Migrate and redact .env
  npx tsx scripts/migrate-credentials.ts --list             # List stored credentials
`);
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

/**
 * List all credentials stored in the keychain for this service.
 */
async function listCredentials(keytar: KeytarModule): Promise<void> {
  info(`Listing credentials in keychain service: ${KEYCHAIN_SERVICE}`);
  console.log("");

  const creds = await keytar.findCredentials(KEYCHAIN_SERVICE);

  if (creds.length === 0) {
    warn("No credentials found in keychain.");
    return;
  }

  for (const cred of creds) {
    const masked = cred.password.slice(0, 4) + "..." + cred.password.slice(-4);
    console.log(`  ${colors.cyan(cred.account)} = ${colors.dim(masked)}`);
  }

  console.log("");
  info(`Total: ${creds.length} credential(s)`);
}

/**
 * Restore credentials from keychain back to a .env file.
 */
async function restoreCredentials(
  keytar: KeytarModule,
  envFile: string,
): Promise<void> {
  info("Restoring credentials from keychain to .env...");

  const creds = await keytar.findCredentials(KEYCHAIN_SERVICE);

  if (creds.length === 0) {
    warn("No credentials found in keychain. Nothing to restore.");
    return;
  }

  let content = "";
  if (existsSync(envFile)) {
    content = readFileSync(envFile, "utf-8");
  }

  const lines = content ? content.split("\n") : [];
  const existingKeys = new Set<string>();

  // Update existing lines
  const updatedLines = lines.map((line) => {
    const match = line.trim().match(/^([A-Za-z_][A-Za-z0-9_]*)\s*=/);
    if (!match) return line;
    const key = match[1]!;
    existingKeys.add(key);
    const cred = creds.find((c) => c.account === key);
    if (cred) {
      ok(`Restored: ${key}`);
      return `${key}=${cred.password}`;
    }
    return line;
  });

  // Append new keys not already in .env
  for (const cred of creds) {
    if (!existingKeys.has(cred.account)) {
      updatedLines.push(`${cred.account}=${cred.password}`);
      ok(`Added: ${cred.account}`);
    }
  }

  writeFileSync(envFile, updatedLines.join("\n"), "utf-8");
  ok(`Credentials restored to: ${envFile}`);
}

/**
 * Main migration: .env -> keychain
 */
async function migrateCredentials(
  keytar: KeytarModule,
  options: CliOptions,
): Promise<void> {
  info(`Reading credentials from: ${options.envFile}`);
  console.log("");

  const credentials = parseEnvFile(options.envFile);

  if (credentials.length === 0) {
    warn(`No ${ENV_PREFIX}* credentials found in ${options.envFile}`);
    return;
  }

  info(`Found ${credentials.length} credential(s) to migrate:`);
  for (const cred of credentials) {
    const masked = cred.value.slice(0, 4) + "..." + (cred.value.length > 8 ? cred.value.slice(-4) : "");
    console.log(`  Line ${cred.lineNumber}: ${colors.cyan(cred.key)} = ${colors.dim(masked)}`);
  }
  console.log("");

  if (options.dryRun) {
    warn("DRY RUN — no changes will be made.");
    console.log("");
    info("The following credentials would be migrated:");
    for (const cred of credentials) {
      console.log(`  ${KEYCHAIN_SERVICE} / ${cred.key}`);
    }
    if (options.redact) {
      console.log("");
      info("The following .env values would be redacted:");
      for (const cred of credentials) {
        console.log(`  ${cred.key}=${REDACTED_PLACEHOLDER}`);
      }
    }
    return;
  }

  // Perform migration
  const results: MigrationResult[] = [];
  const migratedKeys = new Set<string>();

  for (const cred of credentials) {
    try {
      info(`Migrating: ${cred.key} -> keychain...`);
      await keytar.setPassword(KEYCHAIN_SERVICE, cred.key, cred.value);
      ok(`Stored in keychain: ${cred.key}`);
      results.push({ key: cred.key, success: true });
      migratedKeys.add(cred.key);

      // Verify round-trip
      if (options.verbose) {
        const retrieved = await keytar.getPassword(KEYCHAIN_SERVICE, cred.key);
        if (retrieved === cred.value) {
          ok(`Verified round-trip: ${cred.key}`);
        } else {
          fail(`Round-trip verification failed: ${cred.key}`);
          results[results.length - 1]!.success = false;
          results[results.length - 1]!.error = "Round-trip verification failed";
          migratedKeys.delete(cred.key);
        }
      }
    } catch (error) {
      const msg = error instanceof Error ? error.message : String(error);
      fail(`Failed to migrate ${cred.key}: ${msg}`);
      results.push({ key: cred.key, success: false, error: msg });
    }
  }

  // Redact .env if requested
  if (options.redact && migratedKeys.size > 0) {
    console.log("");
    info("Redacting migrated values in .env...");
    redactEnvFile(options.envFile, migratedKeys);
    ok(`Redacted ${migratedKeys.size} value(s) in ${options.envFile}`);
  }

  // Summary
  console.log("");
  console.log("=============================================");
  const succeeded = results.filter((r) => r.success).length;
  const failed = results.filter((r) => !r.success).length;

  if (failed === 0) {
    ok(`Migration complete: ${succeeded}/${results.length} credentials stored in keychain.`);
  } else {
    warn(`Migration partially complete: ${succeeded} succeeded, ${failed} failed.`);
    for (const r of results.filter((r) => !r.success)) {
      fail(`  ${r.key}: ${r.error}`);
    }
  }

  console.log("");
  info("To access credentials in code:");
  console.log(`  import keytar from 'keytar';`);
  console.log(`  const value = await keytar.getPassword('${KEYCHAIN_SERVICE}', 'OPENCLAW_API_KEY');`);
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

async function main(): Promise<void> {
  console.log("=============================================");
  console.log("  OpenClaw Fortress — Credential Migration");
  console.log("=============================================");
  console.log("");

  const options = parseArgs();
  const keytar = await loadKeytar();

  if (options.list) {
    await listCredentials(keytar);
  } else if (options.restore) {
    await restoreCredentials(keytar, options.envFile);
  } else {
    await migrateCredentials(keytar, options);
  }
}

main().catch((error) => {
  fail(`Unexpected error: ${error instanceof Error ? error.message : String(error)}`);
  process.exit(1);
});
