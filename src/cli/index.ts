#!/usr/bin/env node
/**
 * OpenClaw Fortress CLI
 * Main entry point for all commands.
 */
import { loadConfig, ensureOpenClawDir } from '../core/config.js';
import { initAuditLog } from '../security/auditLogger.js';
import { startCommand } from './commands/start.js';
import { doctorCommand } from './commands/doctor.js';
import { signalVerifyCommand } from './commands/signalVerify.js';
import { signalEraseCommand } from './commands/signalErase.js';
import { auditViewCommand } from './commands/auditView.js';
import { rotateKeyCommand } from './commands/rotateKey.js';

const USAGE = `
OpenClaw Fortress — AI Agent Platform with Security Hardening

Usage:
  openclaw start                    Start gateway + all channels
  openclaw doctor                   Run security health check (22 controls)
  openclaw signal verify-contacts   Manage Signal safety numbers
  openclaw signal erase-contact     GDPR erasure for a Signal contact
  openclaw security audit           View audit log
  openclaw security rotate-key      Rotate encryption keys

Options:
  --help, -h    Show this help
  --version     Show version
`.trim();

async function main(): Promise<void> {
  const args = process.argv.slice(2);

  if (args.includes('--help') || args.includes('-h') || args.length === 0) {
    console.log(USAGE);
    process.exit(0);
  }

  if (args.includes('--version')) {
    console.log('openclaw-fortress v1.0.0');
    process.exit(0);
  }

  // Ensure base directory exists
  ensureOpenClawDir();

  // Load config and init audit
  const config = loadConfig();
  initAuditLog(config.security.auditLogPath);

  const command = args[0];
  const subcommand = args[1];

  try {
    switch (command) {
      case 'start':
        await startCommand(config);
        break;

      case 'doctor':
        await doctorCommand(config);
        break;

      case 'signal':
        if (subcommand === 'verify-contacts') {
          await signalVerifyCommand(config);
        } else if (subcommand === 'erase-contact') {
          await signalEraseCommand(config, args[2]);
        } else {
          console.error(`Unknown signal subcommand: ${subcommand}`);
          process.exit(1);
        }
        break;

      case 'security':
        if (subcommand === 'audit') {
          await auditViewCommand(config);
        } else if (subcommand === 'rotate-key') {
          await rotateKeyCommand(config);
        } else {
          console.error(`Unknown security subcommand: ${subcommand}`);
          process.exit(1);
        }
        break;

      default:
        console.error(`Unknown command: ${command}`);
        console.log(USAGE);
        process.exit(1);
    }
  } catch (err) {
    console.error(`Fatal error: ${err instanceof Error ? err.message : err}`);
    process.exit(1);
  }
}

main();
