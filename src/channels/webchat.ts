/**
 * 1.6: WebChat Channel
 * Express server serving a minimal chat UI with WebSocket.
 */
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { Express } from 'express';
import { auditInfo } from '../security/auditLogger.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

/**
 * Mount the WebChat UI routes on the Express app.
 * The WebSocket handling is done by the Gateway.
 */
export function mountWebChatUI(app: Express): void {
  // Serve the chat UI at root
  app.get('/', (_req, res) => {
    res.setHeader('Content-Type', 'text/html');
    res.send(getWebChatHTML());
  });

  auditInfo('webchat_ui_mounted');
}

function getWebChatHTML(): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>OpenClaw Fortress — Chat</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif;
      background: #0a0a0f;
      color: #e0e0e8;
      height: 100vh;
      display: flex;
      flex-direction: column;
    }
    header {
      background: #12121a;
      border-bottom: 1px solid #1e1e2e;
      padding: 16px 24px;
      display: flex;
      align-items: center;
      gap: 12px;
    }
    header .logo {
      width: 32px; height: 32px;
      background: linear-gradient(135deg, #6366f1, #8b5cf6);
      border-radius: 8px;
      display: flex; align-items: center; justify-content: center;
      font-weight: bold; font-size: 16px; color: white;
    }
    header h1 { font-size: 18px; font-weight: 600; }
    header .status {
      margin-left: auto;
      display: flex; align-items: center; gap: 6px;
      font-size: 13px; color: #888;
    }
    header .status .dot {
      width: 8px; height: 8px; border-radius: 50%;
      background: #22c55e;
    }
    header .status .dot.offline { background: #ef4444; }

    #messages {
      flex: 1;
      overflow-y: auto;
      padding: 24px;
      display: flex;
      flex-direction: column;
      gap: 16px;
    }
    .msg {
      max-width: 72%;
      padding: 12px 16px;
      border-radius: 16px;
      font-size: 15px;
      line-height: 1.5;
      word-wrap: break-word;
      white-space: pre-wrap;
    }
    .msg.user {
      align-self: flex-end;
      background: #6366f1;
      color: white;
      border-bottom-right-radius: 4px;
    }
    .msg.assistant {
      align-self: flex-start;
      background: #1e1e2e;
      color: #e0e0e8;
      border-bottom-left-radius: 4px;
    }
    .msg.system {
      align-self: center;
      background: transparent;
      color: #666;
      font-size: 13px;
    }

    #input-area {
      background: #12121a;
      border-top: 1px solid #1e1e2e;
      padding: 16px 24px;
      display: flex;
      gap: 12px;
    }
    #input-area input {
      flex: 1;
      background: #1e1e2e;
      border: 1px solid #2e2e3e;
      border-radius: 12px;
      padding: 12px 16px;
      color: #e0e0e8;
      font-size: 15px;
      outline: none;
    }
    #input-area input:focus { border-color: #6366f1; }
    #input-area button {
      background: #6366f1;
      color: white;
      border: none;
      border-radius: 12px;
      padding: 12px 24px;
      font-size: 15px;
      font-weight: 500;
      cursor: pointer;
      transition: background 0.2s;
    }
    #input-area button:hover { background: #5558e6; }
    #input-area button:disabled { background: #333; cursor: not-allowed; }
  </style>
</head>
<body>
  <header>
    <div class="logo">O</div>
    <h1>OpenClaw Fortress</h1>
    <div class="status">
      <div class="dot" id="status-dot"></div>
      <span id="status-text">Connecting...</span>
    </div>
  </header>

  <div id="messages">
    <div class="msg system">End-to-end encrypted session. Type a message to begin.</div>
  </div>

  <div id="input-area">
    <input type="text" id="msg-input" placeholder="Type a message..." autocomplete="off" />
    <button id="send-btn" disabled>Send</button>
  </div>

  <script>
    const messages = document.getElementById('messages');
    const input = document.getElementById('msg-input');
    const sendBtn = document.getElementById('send-btn');
    const statusDot = document.getElementById('status-dot');
    const statusText = document.getElementById('status-text');
    let ws;

    function connect() {
      const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
      ws = new WebSocket(proto + '//' + location.host + '/ws');

      ws.onopen = () => {
        statusDot.className = 'dot';
        statusText.textContent = 'Connected';
        sendBtn.disabled = false;
      };

      ws.onclose = () => {
        statusDot.className = 'dot offline';
        statusText.textContent = 'Disconnected';
        sendBtn.disabled = true;
        setTimeout(connect, 3000);
      };

      ws.onerror = () => {
        statusDot.className = 'dot offline';
        statusText.textContent = 'Error';
      };

      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          if (data.type === 'message') {
            addMessage(data.text, 'assistant');
          } else if (data.type === 'error') {
            addMessage(data.text, 'system');
          }
        } catch (e) {
          console.error('Parse error:', e);
        }
      };
    }

    function addMessage(text, role) {
      const div = document.createElement('div');
      div.className = 'msg ' + role;
      div.textContent = text;
      messages.appendChild(div);
      messages.scrollTop = messages.scrollHeight;
    }

    function send() {
      const text = input.value.trim();
      if (!text || !ws || ws.readyState !== WebSocket.OPEN) return;
      addMessage(text, 'user');
      ws.send(JSON.stringify({ text }));
      input.value = '';
    }

    sendBtn.addEventListener('click', send);
    input.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') send();
    });

    connect();
  </script>
</body>
</html>`;
}
