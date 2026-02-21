
<div align="center">

```
                                ╔═══════════════════════════╗
                                ║                           ║
    ██████╗ ██████╗ ███████╗    ║   ┌─────────────────────┐ ║
   ██╔═══██╗██╔══██╗██╔════╝    ║   │  ◈  SECURED  ◈     │ ║
   ██║   ██║██████╔╝█████╗      ║   │  22 CONTROLS ARMED  │ ║
   ██║   ██║██╔═══╝ ██╔══╝      ║   │  377 TESTS PASSING  │ ║
   ╚██████╔╝██║     ██║         ║   └─────────────────────┘ ║
    ╚═════╝ ╚═╝     ╚═╝         ║                           ║
                                ╚═══════════════════════════╝
     O P E N C L A W   F O R T R E S S
```

**An AI agent that talks. On Signal. On Discord. On the web.**<br>
**Hardened with 22 security controls. Built to be trusted.**

[![Tests](https://img.shields.io/badge/tests-377%20passing-brightgreen?style=flat-square)](#tests)
[![Security](https://img.shields.io/badge/security-22%2F22%20controls-blue?style=flat-square)](#security)
[![TypeScript](https://img.shields.io/badge/typescript-strict-blue?style=flat-square)](#)
[![License](https://img.shields.io/badge/license-MIT-gray?style=flat-square)](#license)

[Get Started](#get-started) · [Security](#security) · [Channels](#channels) · [Architecture](#architecture) · [CLI](#cli)

</div>

---

## What is this?

One AI agent. Three channels. Zero compromises on security.

OpenClaw Fortress connects Anthropic Claude to **Signal**, **Discord**, and a built-in **WebChat** UI. Every message passes through 22 security controls before it reaches the model or your users.

It was built for people who want AI agents they can actually trust.

---

## Get Started

Five commands. That's it.

```bash
git clone https://github.com/phazurlabs/openclaw-fortress.git
cd openclaw-fortress
npm install
bash scripts/generate-secrets.sh > .env
```

Add your Anthropic key to `.env`:

```bash
ANTHROPIC_API_KEY=sk-ant-your-key-here
```

Start it:

```bash
npm start
```

Open your browser to **http://localhost:18789**. You're live.

---

## Security

Every message. Every request. Every byte. Checked.

```
 ✓ P-01 PII HMAC hashing           ✓ G-01 Timing-safe gateway auth
 ✓ P-02 PII detection & redaction   ✓ G-02 Path traversal jail
 ✓ P-03 AES-256-GCM encryption      ✓ G-03 SSRF guard
 ✓ P-04 OS keychain credentials      ✓ G-04 Security headers (CSP, HSTS)
 ✓ S-01 Signal daemon loopback      ✓ A-01 Prompt injection guard (13+)
 ✓ S-02 DM allowlist + rate limit   ✓ A-02 Structured audit logger
 ✓ S-03 Safety number tracking      ✓ A-03 Crypto session manager
 ✓ S-04 Zod schema validation       ✓ A-04 Skill integrity (SHA256)
 ✓ E-01 PII consent store           ✓ E-04 Retention policy
 ✓ E-02 Data minimization           ✓ E-05 Input validation
 ✓ E-03 GDPR Art. 17 erasure        ✓ F-01 Security doctor (22 checks)
```

Run the doctor anytime:

```bash
npm run doctor
```

It checks all 22 controls and tells you what's wrong. Green means go. Red means fix it.

---

## Channels

### Signal

Private. Encrypted. The gold standard.

```bash
# Start signal-cli daemon first
signal-cli -a +15551234567 daemon --http=127.0.0.1:8080

# Enable in ~/.openclaw/openclaw.json
# Set allowedNumbers for who can talk to your agent
```

Messages arrive via SSE. Responses go back via REST. Allowlists keep strangers out. Safety number changes suspend the contact until you verify them manually.

### Discord

Mention the bot or DM it. It responds in-thread.

```bash
# Set DISCORD_BOT_TOKEN in .env
# Enable in config, set allowedChannels / allowedServers
```

### WebChat

Ships with a dark-themed chat UI. No build step. No framework. Just HTML.

Open **http://localhost:18789** after starting. That's your chat.

---

## Architecture

```
openclaw-fortress/
│
├── src/
│   ├── core/               Gateway, agent, LLM client, state
│   ├── channels/            Signal, WebChat, Discord
│   ├── security/            22 security modules (Layers A–F)
│   ├── skills/              Skill loader + runner
│   ├── cli/                 CLI commands
│   └── types/               TypeScript types + Zod schemas
│
├── scripts/                 Firewall, systemd, verification
├── tests/                   13 test suites, 377 tests
└── config/                  Reference configuration
```

The gateway binds to `127.0.0.1` by default. Not `0.0.0.0`. That's intentional.

Messages flow like this:

```
Channel → Allowlist → Input Validation → Prompt Guard → Agent → LLM → Response
                                            ↓
                                      Audit Logger
```

Every step is a module. Every module is tested. Every test passes.

---

## CLI

```bash
openclaw start                      # Launch everything
openclaw doctor                     # 22-check security audit
openclaw signal verify-contacts     # Safety number management
openclaw signal erase-contact NUM   # GDPR Article 17 erasure
openclaw security audit             # View the audit log
openclaw security rotate-key        # Generate new encryption keys
```

---

## Tests

377 tests. 13 files. All green.

```bash
npm test
```

```
 ✓ tests/security/piiUtils.test.ts          35 tests
 ✓ tests/security/gatewayAuth.test.ts        33 tests
 ✓ tests/security/pathSecurity.test.ts       43 tests
 ✓ tests/security/ssrfGuard.test.ts          31 tests
 ✓ tests/security/promptGuard.test.ts        52 tests
 ✓ tests/security/signalAllowlist.test.ts    17 tests
 ✓ tests/security/encryptedStore.test.ts     23 tests
 ✓ tests/security/auditLogger.test.ts        20 tests
 ✓ tests/security/piiDetector.test.ts        35 tests
 ✓ tests/security/sessionManager.test.ts     31 tests
 ✓ tests/core/gateway.test.ts                 9 tests
 ✓ tests/core/agent.test.ts                  19 tests
 ✓ tests/channels/signal.test.ts             29 tests
```

---

## Configuration

```bash
cp config/openclaw.example.json ~/.openclaw/openclaw.json
```

Secrets live in `.env`. Config lives in `~/.openclaw/openclaw.json`. They stay separate on purpose.

See [`.env.example`](.env.example) for every variable and what it does.

---

## Tech Stack

| What | Why |
|------|-----|
| **TypeScript** | Strict mode. No `any`. |
| **Anthropic Claude** | The LLM. System prompts stay as `system` params. |
| **Zod** | Every input validated. Every config parsed. |
| **Express + WS** | Gateway serves HTTP and WebSocket on one port. |
| **Helmet** | CSP, HSTS, X-Frame-Options. Set once. |
| **Vitest** | Fast. 377 tests in ~1 second. |
| **signal-cli** | Signal protocol over REST + SSE. |
| **Discord.js** | Mention-based + DM conversations. |

---

## Requirements

- Node.js 20+
- An [Anthropic API key](https://console.anthropic.com)
- signal-cli (optional, for Signal channel)
- Discord bot token (optional, for Discord channel)

---

## Contributing

Open an issue first. Then a PR. Keep it simple.

Tests must pass. Types must check. Security doctor must stay green.

```bash
npm run typecheck && npm test && npm run doctor
```

---

## License

MIT

---

<div align="center">
<br>

**Built by [Phazur Labs](https://github.com/phazurlabs)**

*Security is not a feature. It's the foundation.*

<br>
</div>
