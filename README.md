
<div align="center">

```

    ███████╗ ██████╗ ██████╗ ████████╗██████╗ ███████╗███████╗███████╗
    ██╔════╝██╔═══██╗██╔══██╗╚══██╔══╝██╔══██╗██╔════╝██╔════╝██╔════╝
    █████╗  ██║   ██║██████╔╝   ██║   ██████╔╝█████╗  ███████╗███████╗
    ██╔══╝  ██║   ██║██╔══██╗   ██║   ██╔══██╗██╔══╝  ╚════██║╚════██║
    ██║     ╚██████╔╝██║  ██║   ██║   ██║  ██║███████╗███████║███████║
    ╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝

    ┌──────────────────────────────────────────────────────────────┐
    │                                                              │
    │   ◈  22 Security Controls Armed                             │
    │   ◈  377 Tests Passing                                      │
    │   ◈  3 Channels — Signal · Discord · WebChat                │
    │   ◈  Powered by Anthropic Claude                            │
    │                                                              │
    └──────────────────────────────────────────────────────────────┘

                     by  P H A Z U R  L A B S

```

**Deploy an AI agent you can actually trust.**<br>
**One platform. Three channels. Twenty-two security controls. Zero compromises.**

<br>

[![Tests](https://img.shields.io/badge/tests-377%20passing-brightgreen?style=for-the-badge)](#tests)
[![Security](https://img.shields.io/badge/security-22%2F22%20controls-blue?style=for-the-badge)](#security)
[![TypeScript](https://img.shields.io/badge/typescript-strict-blue?style=for-the-badge)](#tech-stack)
[![License](https://img.shields.io/badge/license-MIT-gray?style=for-the-badge)](#license)

<br>

[Why Fortress?](#why-fortress) · [Get Started](#get-started) · [How It Works](#how-it-works) · [Security](#security) · [Channels](#channels) · [Architecture](#architecture) · [CLI](#cli) · [Tests](#tests) · [Configuration](#configuration)

<br>
</div>

---

<br>

## Why Fortress?

Most AI agent frameworks ship fast and patch later. Fortress ships secure from line one.

The problem is simple. You want to deploy an AI agent on Signal, Discord, or the web. You want it to handle real conversations with real people. But every message carries risk — prompt injection, PII leakage, unauthorized access, session hijacking, SSRF, path traversal. The attack surface is enormous. And most frameworks ignore it entirely.

Fortress doesn't.

Every message that enters the system passes through six layers of security before it reaches the LLM and six more before the response leaves. PII is detected, redacted, and hashed. Sessions are cryptographically bound. Inputs are validated with Zod schemas. Prompt injections are caught by 13 pattern detectors. Credentials live in your OS keychain, not in plaintext files. Audit logs scrub sensitive data automatically. And a single command — `npm run doctor` — tells you if any of the 22 controls are misconfigured.

This is what "secure by default" actually looks like.

<br>

### Who is this for?

- **Teams deploying AI assistants** on private messaging channels who need security guarantees, not security theater
- **Developers building on Claude** who want a production-ready foundation instead of a weekend prototype
- **Organizations with compliance requirements** (GDPR, CCPA, HIPAA-adjacent) who need audit trails, data minimization, and right-to-erasure built in
- **Security engineers** who want to see how 22 controls are implemented, tested, and verified in a single codebase

### What makes it different?

| Most AI Frameworks | Fortress |
|---|---|
| Auth is a TODO comment | Timing-safe token verification with entropy checks |
| PII flows freely to the LLM | PII detected, redacted, and HMAC-hashed before it leaves the process |
| Sessions are a UUID in memory | Crypto-random IDs with channel binding, rotation, and expiry |
| Config is a JSON file with secrets | Secrets in OS keychain, config validated with Zod, env vars resolved at runtime |
| "Security" means HTTPS | 22 controls across 6 layers, verified by a single command |
| No audit trail | Structured JSONL audit log with automatic PII scrubbing |
| Prompt injection? What's that? | 13 pattern detectors covering extraction, jailbreaks, delimiters, exfiltration, XSS, SQLi |

<br>

---

<br>

## Get Started

### Prerequisites

| Requirement | Version | Notes |
|---|---|---|
| **Node.js** | 20+ | `node --version` to check |
| **npm** | 10+ | Ships with Node.js |
| **Anthropic API Key** | — | Get one at [console.anthropic.com](https://console.anthropic.com) |
| **signal-cli** | 0.13+ | Optional. Only needed for the Signal channel |
| **Discord Bot Token** | — | Optional. Only needed for the Discord channel |

### Installation

**Step 1 — Clone and install**

```bash
git clone https://github.com/phazurlabs/openclaw-fortress.git
cd openclaw-fortress
npm install
```

**Step 2 — Generate your secrets**

Every secret is generated with `openssl rand`. No weak defaults. No shared keys.

```bash
bash scripts/generate-secrets.sh > .env
```

This creates your `.env` file with cryptographically random values for:
- `OPENCLAW_ENCRYPTION_KEY` — AES-256-GCM master key for encrypted storage
- `OPENCLAW_PII_HMAC_SECRET` — HMAC key for hashing phone numbers and PII
- `OPENCLAW_SESSION_SECRET` — Session signing key
- `OPENCLAW_GATEWAY_TOKEN` — Gateway authentication token

**Step 3 — Add your Anthropic API key**

Open `.env` and set your key:

```bash
ANTHROPIC_API_KEY=sk-ant-your-key-here
```

**Step 4 — Verify your setup**

```bash
npm run doctor
```

You'll see all 22 security controls checked. Green means configured. Yellow means optional. Red means fix it before you go live.

**Step 5 — Start**

```bash
npm start
```

Open **http://localhost:18789** in your browser. Type a message. You're talking to Claude through Fortress.

<br>

---

<br>

## How It Works

A message enters the system. Here's what happens to it.

```
                    ┌──────────────────────────────────────────────┐
                    │              INCOMING MESSAGE                 │
                    └──────────────┬───────────────────────────────┘
                                   │
                    ┌──────────────▼───────────────────────────────┐
                    │  CHANNEL ADAPTER                             │
                    │  Signal SSE  ·  Discord.js  ·  WebSocket     │
                    └──────────────┬───────────────────────────────┘
                                   │
              ┌────────────────────▼────────────────────┐
              │         SECURITY PIPELINE               │
              │                                         │
              │  1. Allowlist Check (S-02)              │
              │     Is this sender permitted?            │
              │                                         │
              │  2. Rate Limiting (G-01)                │
              │     Too many requests? Drop.            │
              │                                         │
              │  3. Safety Number Verification (S-03)   │
              │     Has the identity key changed?        │
              │                                         │
              │  4. Input Validation (E-05)             │
              │     Schema-valid? MIME-safe?             │
              │                                         │
              │  5. PII Detection (P-02)                │
              │     Scan for phones, SSNs, emails, CCs  │
              │                                         │
              │  6. Prompt Injection Guard (A-01)       │
              │     13 patterns. Block or suspend.       │
              │                                         │
              └────────────────────┬────────────────────┘
                                   │
              ┌────────────────────▼────────────────────┐
              │         AGENT RUNTIME                   │
              │                                         │
              │  Session Management (A-03)              │
              │  Conversation History (trimmed)         │
              │  Data Minimization (E-02)               │
              │  Tool/Skill Execution (A-04)            │
              │                                         │
              └────────────────────┬────────────────────┘
                                   │
              ┌────────────────────▼────────────────────┐
              │         ANTHROPIC CLAUDE                │
              │                                         │
              │  System prompt as `system` param        │
              │  Messages as structured array           │
              │  Tool definitions from verified skills  │
              │  Retry with exponential backoff         │
              │                                         │
              └────────────────────┬────────────────────┘
                                   │
              ┌────────────────────▼────────────────────┐
              │         RESPONSE                        │
              │                                         │
              │  Route back through channel adapter     │
              │  Audit log entry (PII-scrubbed)         │
              │  Session state updated                  │
              │                                         │
              └────────────────────────────────────────┘
```

Every step writes to the audit log. Every audit entry has PII automatically scrubbed. The log is structured JSONL — one JSON object per line — so you can pipe it into any monitoring tool you already use.

<br>

---

<br>

## Security

Six layers. Twenty-two controls. One command to verify them all.

<br>

### Layer A — PII & Cryptographic Foundation

The base layer. Nothing else works without this.

| Control | What It Does | Why It Matters |
|---|---|---|
| **P-01** PII HMAC Hashing | SHA-256 HMAC hashes phone numbers for storage and logging | Phone numbers never appear in plaintext in logs or databases |
| **P-02** PII Detection | Regex engine scans for phones, SSNs, credit cards, emails, gov IDs | Catches PII before it reaches the LLM or audit log |
| **P-03** Encrypted Store | AES-256-GCM with HKDF key derivation, random IV per operation | Sessions, consent records, and transcripts are encrypted at rest |
| **P-04** Credential Store | OS keychain via keytar (macOS Keychain, Linux libsecret) | Secrets stay in the OS secure enclave, not in environment variables |

### Layer B — Signal Protocol Hardening

Signal is the most sensitive channel. It gets its own layer.

| Control | What It Does | Why It Matters |
|---|---|---|
| **S-01** Daemon Guard | Asserts signal-cli binds to `127.0.0.1` only | Prevents the Signal daemon from being exposed to the network |
| **S-02** Allowlist | Per-number DM allowlist + per-contact rate limiting | Only authorized contacts can interact with your agent |
| **S-03** Safety Numbers | Tracks identity key fingerprints, suspends on change | Detects potential MITM attacks on the Signal protocol |
| **S-04** Schema Validation | Zod schemas for every signal-cli SSE event field | Malformed events from the daemon are rejected, not processed |

### Layer C — Gateway & Network Security

The gateway is the front door. These controls decide who gets in.

| Control | What It Does | Why It Matters |
|---|---|---|
| **G-01** Gateway Auth | Timing-safe token comparison + entropy validation + rate limiting | Prevents brute force and timing attacks on the gateway token |
| **G-02** Path Security | Session ID validation, directory jail checks, null byte blocking | Prevents path traversal attacks against agent workspaces |
| **G-03** SSRF Guard | Blocks private IPs, DNS rebinding, dangerous URL schemes | Skills and tools can't be tricked into hitting internal services |
| **G-04** Security Headers | CSP, HSTS, X-Frame-Options, X-Content-Type-Options via Helmet | WebChat UI is hardened against clickjacking, XSS, and MIME sniffing |

### Layer D — Application Security

These protect the agent runtime itself.

| Control | What It Does | Why It Matters |
|---|---|---|
| **A-01** Prompt Guard | 13 pattern detectors: jailbreaks, extraction, delimiters, exfil, SQLi, XSS | Catches prompt injection before the message reaches Claude |
| **A-02** Audit Logger | Structured JSONL with automatic PII scrubbing and CRITICAL alerting | Every security-relevant event is logged. PII never leaks into logs. |
| **A-03** Session Manager | Crypto-random IDs, channel+contact binding, rotation, expiry | Sessions can't be hijacked, replayed, or transferred between channels |
| **A-04** Skill Integrity | SHA-256 hash of every skill entry point, verified on each execution | Tampered skill files are detected and blocked before they run |

### Layer E — Privacy & Compliance

GDPR, CCPA, and privacy-by-design. Not afterthoughts — foundations.

| Control | What It Does | Why It Matters |
|---|---|---|
| **E-01** Consent Store | Per-contact consent tracking, encrypted at rest | You know who consented to what, and when |
| **E-02** Data Minimization | Strips metadata before sending to LLM, prunes conversation history | The LLM only sees what it needs. Nothing more. |
| **E-03** Right to Erasure | GDPR Article 17 — one command destroys all data for a contact | `openclaw signal erase-contact +15551234567` and they're gone |
| **E-04** Retention Policy | Configurable TTLs for sessions, transcripts, and audit logs | Data expires automatically. No manual cleanup. No forgotten files. |
| **E-05** Input Validation | Message length limits, MIME type gating, control character blocking | Malformed input is rejected at the boundary, not in the agent |

### Layer F — Operations

One command. Twenty-two checks. Pass or fail.

| Control | What It Does | Why It Matters |
|---|---|---|
| **F-01** Security Doctor | Unified health check across all 22 controls | `npm run doctor` tells you exactly what's configured and what isn't |

<br>

### Run the doctor

```bash
npm run doctor
```

```
  OpenClaw Fortress — Security Doctor

  ─────────────────────────────────────────

  ✓ P-01 PII HMAC Secret        PASS  Configured with sufficient entropy
  ✓ P-02 PII Detection          PASS  Enabled
  ✓ P-03 Encryption Key         PASS  AES-256 key configured
  ✓ P-04 Credential Store       PASS  OS keychain available
  ✓ S-01 Signal Daemon Guard    PASS  Loopback only
  ✓ S-02 Signal Allowlist       PASS  4 numbers
  ✓ S-03 Safety Numbers         PASS  Tracking active
  ✓ S-04 Signal Schema          PASS  Zod validation active
  ✓ G-01 Gateway Auth           PASS  Token configured with sufficient entropy
  ✓ G-02 Path Security          PASS  Jail checks + null byte blocking active
  ✓ G-03 SSRF Guard             PASS  Private IP + DNS rebinding protection active
  ✓ G-04 Security Headers       PASS  CSP + HSTS + X-Frame-Options active
  ✓ A-01 Prompt Guard           PASS  13+ injection patterns active
  ✓ A-02 Audit Logger           PASS  Logging to ~/.openclaw/audit.jsonl
  ✓ A-03 Session Manager        PASS  Max age: 86400s
  ✓ A-04 Skill Integrity        PASS  SHA256 verification on execution
  ✓ E-01 PII Consent            PASS  Encrypted consent store ready
  ✓ E-02 Data Minimization      PASS  LLM metadata stripping active
  ✓ E-03 Right to Erasure       PASS  GDPR Art. 17 erasure ready
  ✓ E-04 Retention Policy       PASS  90-day retention
  ✓ E-05 Input Validation       PASS  Message + attachment validation active
  ✓ F-01 Process Isolation      PASS  Not running as root

  ─────────────────────────────────────────
  Results: 22 PASS  0 WARN  0 FAIL  0 SKIP
  Score: 22/22 checks passed
```

Green across the board. That's the goal.

<br>

---

<br>

## Channels

Fortress ships with three channel adapters. Enable the ones you need.

<br>

### Signal

The most private messaging protocol in the world. Fortress treats it that way.

**How it connects:** Fortress talks to [signal-cli](https://github.com/AsamK/signal-cli) running as a local daemon. Messages arrive via Server-Sent Events (SSE). Responses go back via the signal-cli REST API. The connection never leaves `127.0.0.1`.

**What's protected:**
- Only numbers on your allowlist can message the agent. Everyone else is silently dropped.
- Per-contact rate limiting prevents abuse (default: 30 messages/minute).
- Safety number changes trigger an automatic suspension. The contact is blocked until you manually verify them with `openclaw signal verify-contacts --clear`.
- Every SSE event from signal-cli is validated against a Zod schema. Malformed events are rejected.
- Attachments are MIME-gated: only images, PDFs, and plain text pass through.

**Setup:**

```bash
# 1. Install signal-cli
# See: https://github.com/AsamK/signal-cli#installation

# 2. Register your phone number
signal-cli -a +15551234567 register

# 3. Start the daemon on loopback only
signal-cli -a +15551234567 daemon --http=127.0.0.1:8080

# 4. Enable in config
# Set signal.enabled = true in ~/.openclaw/openclaw.json
# Add allowed numbers to signal.allowedNumbers
```

<br>

### Discord

Mention the bot in a channel or DM it directly. It responds in-thread.

**How it connects:** Standard Discord.js bot with Gateway Intents for guilds, messages, and DMs. The bot only responds when mentioned by name or messaged directly — it never eavesdrops on general conversation.

**What's protected:**
- Server and channel allowlists control where the bot listens
- Messages over 2,000 characters are automatically chunked
- Bot ignores its own messages and other bots

**Setup:**

```bash
# 1. Create a bot at https://discord.com/developers/applications
# 2. Enable MESSAGE CONTENT intent
# 3. Set DISCORD_BOT_TOKEN in .env
# 4. Enable in config
# Set discord.enabled = true in ~/.openclaw/openclaw.json
# Add allowed channels/servers to the allowlists
```

<br>

### WebChat

A built-in chat interface. Dark theme. No build step. No dependencies.

**How it connects:** The gateway serves an HTML page at the root URL. The page opens a WebSocket connection to `/ws` on the same port. Messages flow over the socket in real time.

**What's protected:**
- CSP headers prevent script injection
- CORS is locked to a single origin
- WebSocket connections are authenticated with the gateway token
- Each connection gets a unique session ID, cryptographically generated

**Setup:** Nothing. It's on by default. Start the gateway and open `http://localhost:18789`.

<br>

---

<br>

## Architecture

```
openclaw-fortress/
│
├── src/
│   ├── core/                         Core platform
│   │   ├── gateway.ts                 WebSocket + HTTP server
│   │   ├── agent.ts                   Per-contact agent runtime
│   │   ├── agentManager.ts            Agent lifecycle coordinator
│   │   ├── llm.ts                     Anthropic Claude SDK wrapper
│   │   ├── config.ts                  Config loader with Zod validation
│   │   └── stateManager.ts            Encrypted state persistence
│   │
│   ├── channels/                     Channel adapters
│   │   ├── signal.ts                  Signal via signal-cli SSE + REST
│   │   ├── discord.ts                 Discord.js bot
│   │   └── webchat.ts                 Built-in dark-themed chat UI
│   │
│   ├── security/                     22 security modules
│   │   ├── piiUtils.ts                P-01  HMAC hashing + masking
│   │   ├── piiDetector.ts             P-02  PII pattern detection
│   │   ├── encryptedStore.ts          P-03  AES-256-GCM storage
│   │   ├── credentialStore.ts         P-04  OS keychain integration
│   │   ├── signalDaemonGuard.ts       S-01  Loopback assertion
│   │   ├── signalAllowlist.ts         S-02  Number/group allowlists
│   │   ├── signalSafetyNumbers.ts     S-03  Identity key tracking
│   │   ├── signalSchema.ts            S-04  Zod event validation
│   │   ├── gatewayAuth.ts             G-01  Token auth + rate limiting
│   │   ├── pathSecurity.ts            G-02  Path traversal prevention
│   │   ├── ssrfGuard.ts               G-03  SSRF protection
│   │   ├── securityHeaders.ts         G-04  HTTP security headers
│   │   ├── promptGuard.ts             A-01  Injection detection (13+)
│   │   ├── auditLogger.ts             A-02  Structured audit logging
│   │   ├── sessionManager.ts          A-03  Crypto session management
│   │   ├── skillIntegrity.ts          A-04  SHA-256 skill verification
│   │   ├── piiConsent.ts              E-01  Consent tracking
│   │   ├── dataMinimization.ts        E-02  Metadata stripping
│   │   ├── rightToErasure.ts          E-03  GDPR erasure
│   │   ├── retentionPolicy.ts         E-04  TTL enforcement
│   │   └── inputValidation.ts         E-05  Input boundary validation
│   │
│   ├── skills/                       Extensible skill system
│   │   ├── skillLoader.ts             Discovery + manifest parsing
│   │   └── skillRunner.ts             Execution with integrity checks
│   │
│   ├── cli/                          Command-line interface
│   │   ├── index.ts                   Entry point + routing
│   │   ├── securityDoctor.ts          F-01  22-check health command
│   │   └── commands/                  Individual commands
│   │
│   └── types/                        Shared type definitions
│       └── index.ts                   Interfaces + Zod schemas
│
├── scripts/                          Infrastructure automation
│   ├── generate-secrets.sh            Cryptographic secret generation
│   ├── firewall-setup.sh              pf (macOS) / UFW (Linux) rules
│   ├── setup-signal-service.sh        signal-cli systemd service
│   ├── signal-cli.service             Hardened systemd unit file
│   ├── signal-health-check.sh         Daemon health verification
│   ├── verify-signal-cli.sh           Binary SHA-256 integrity check
│   ├── verify-firewall.sh             Port accessibility testing
│   └── migrate-credentials.ts         Plaintext → keychain migration
│
├── tests/                            13 test suites, 377 tests
├── config/                           Reference configuration
├── .env.example                      Documented environment template
└── .gitignore                        .env excluded by default
```

<br>

### Design Principles

**Loopback by default.** The gateway binds to `127.0.0.1`, not `0.0.0.0`. If you want to expose it, you make that choice explicitly.

**Secrets never in config.** Configuration goes in `~/.openclaw/openclaw.json`. Secrets go in `.env` or the OS keychain. They are resolved at runtime and never serialized together.

**System prompt stays clean.** The system prompt is always passed as Claude's `system` parameter, never injected into the user message array. This matters for prompt injection resistance.

**Every module is independent.** You can use the PII detector without the audit logger. You can use the session manager without the gateway. Each security module exports clean functions with no hidden global state.

**Fail closed.** If the allowlist can't be checked, the message is dropped. If the safety number can't be verified, the contact is suspended. If the skill hash doesn't match, execution is blocked. The default answer is no.

<br>

---

<br>

## CLI

Six commands. Each one does exactly what the name says.

```bash
# Start the gateway and all enabled channels
openclaw start

# Run all 22 security checks
openclaw doctor

# List Signal contacts and their safety number status
openclaw signal verify-contacts

# Clear a safety number suspension after manual verification
openclaw signal verify-contacts --clear +15551234567

# Permanently delete all data for a contact (GDPR Article 17)
openclaw signal erase-contact +15551234567

# View the last 50 audit log entries
openclaw security audit

# View the last 200 entries
openclaw security audit --tail 200

# Generate new encryption keys (prints to stdout, you update .env)
openclaw security rotate-key
```

<br>

---

<br>

## Tests

377 tests across 13 files. They run in about one second.

```bash
npm test
```

```
 ✓ tests/security/piiUtils.test.ts          35 tests  ·  hashing, masking, E.164 validation
 ✓ tests/security/gatewayAuth.test.ts        33 tests  ·  timing-safe auth, entropy, rate limits
 ✓ tests/security/pathSecurity.test.ts       43 tests  ·  jail checks, null bytes, traversal
 ✓ tests/security/ssrfGuard.test.ts          31 tests  ·  private IPs, DNS rebinding, schemes
 ✓ tests/security/promptGuard.test.ts        52 tests  ·  all 13 injection patterns
 ✓ tests/security/signalAllowlist.test.ts    17 tests  ·  allowlist, rate limiting, silent drop
 ✓ tests/security/encryptedStore.test.ts     23 tests  ·  AES-256-GCM roundtrip, tamper detection
 ✓ tests/security/auditLogger.test.ts        20 tests  ·  JSONL format, PII scrubbing, severity
 ✓ tests/security/piiDetector.test.ts        35 tests  ·  phone, SSN, CC, email, gov ID detection
 ✓ tests/security/sessionManager.test.ts     31 tests  ·  binding, rotation, expiry, pruning
 ✓ tests/core/gateway.test.ts                 9 tests  ·  instantiation, config, connections
 ✓ tests/core/agent.test.ts                  19 tests  ·  lifecycle, tool execution, history trim
 ✓ tests/channels/signal.test.ts             29 tests  ·  schema parsing, allowlist integration

 13 files  ·  377 tests  ·  all passing
```

Run the type checker too:

```bash
npm run typecheck
```

Zero errors. Strict mode. No `any` types.

<br>

---

<br>

## Configuration

Fortress uses two configuration sources. They are intentionally separate.

### Environment Variables (`.env`)

Secrets and credentials. Never committed to git.

```bash
# Generate all secrets with strong randomness
bash scripts/generate-secrets.sh > .env
```

| Variable | Purpose |
|---|---|
| `ANTHROPIC_API_KEY` | Your Anthropic API key |
| `OPENCLAW_GATEWAY_TOKEN` | Gateway authentication token |
| `OPENCLAW_ENCRYPTION_KEY` | AES-256-GCM master key |
| `OPENCLAW_PII_HMAC_SECRET` | PII hashing HMAC key |
| `OPENCLAW_SESSION_SECRET` | Session signing secret |
| `DISCORD_BOT_TOKEN` | Discord bot token (optional) |

### Config File (`~/.openclaw/openclaw.json`)

Behavior and settings. Safe to version or share.

```bash
cp config/openclaw.example.json ~/.openclaw/openclaw.json
```

```json
{
  "gateway": { "host": "127.0.0.1", "port": 18789 },
  "llm": { "model": "claude-sonnet-4-20250514", "maxTokens": 4096 },
  "channels": {
    "signal": { "enabled": true, "allowedNumbers": ["+15551234567"] },
    "discord": { "enabled": false },
    "webchat": { "enabled": true }
  },
  "security": {
    "promptGuardEnabled": true,
    "retentionDays": 90,
    "maxSessionAge": 86400
  }
}
```

<br>

---

<br>

## Tech Stack

| Technology | Role | Why This One |
|---|---|---|
| **TypeScript** | Language | Strict mode catches bugs at compile time, not in production |
| **Anthropic Claude** | LLM | System prompts as a first-class parameter. Best-in-class safety. |
| **Zod v4** | Validation | Every config, every input, every event — schema-validated |
| **Express** | HTTP Server | Battle-tested. Helmet integration. One import. |
| **ws** | WebSocket | Lightweight. No framework overhead. |
| **Helmet** | Security Headers | CSP, HSTS, X-Frame-Options — configured once |
| **signal-cli** | Signal Protocol | REST + SSE interface to the Signal network |
| **Discord.js** | Discord API | Full gateway support with intents and slash commands |
| **Vitest** | Testing | 377 tests in ~1 second. Native ESM. |

<br>

---

<br>

## Infrastructure Scripts

For hardening the host machine. Optional but recommended for production.

| Script | What It Does |
|---|---|
| `scripts/generate-secrets.sh` | Generate all env vars with `openssl rand` |
| `scripts/firewall-setup.sh` | Configure pf (macOS) or UFW (Linux) to restrict port access |
| `scripts/setup-signal-service.sh` | Create `signal-svc` user and directories on Linux |
| `scripts/signal-cli.service` | Hardened systemd unit with 20+ security directives |
| `scripts/signal-health-check.sh` | Verify daemon is running and bound to loopback |
| `scripts/verify-signal-cli.sh` | SHA-256 integrity check on the signal-cli binary |
| `scripts/verify-firewall.sh` | Test that ports are NOT accessible from external IPs |
| `scripts/migrate-credentials.ts` | Move plaintext `.env` secrets into the OS keychain |

<br>

---

<br>

## Contributing

Open an issue before you write code. Describe the problem. We'll agree on the approach. Then open a PR.

Every PR must pass three checks:

```bash
npm run typecheck    # Zero type errors
npm test             # 377+ tests passing
npm run doctor       # 22 security controls green
```

Don't add features without tests. Don't weaken security controls. Don't use `any`.

<br>

---

<br>

## License

MIT — use it, fork it, ship it.

<br>

---

<br>

<div align="center">

```
    ┌──────────────────────────────────────────────┐
    │                                              │
    │    Built by Phazur Labs                      │
    │    github.com/phazurlabs                     │
    │                                              │
    │    Security is not a feature.                │
    │    It's the foundation.                      │
    │                                              │
    └──────────────────────────────────────────────┘
```

</div>
