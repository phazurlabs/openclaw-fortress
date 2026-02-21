/**
 * 1.2: Gateway Server
 * WebSocket server with HTTP, auth, health endpoint.
 */
import { createServer, type Server as HTTPServer, type IncomingMessage } from 'node:http';
import { WebSocketServer, WebSocket, type RawData } from 'ws';
import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import type { OpenClawConfig, IncomingMessage as OCMessage, ChannelType } from '../types/index.js';
import { authenticateRequest } from '../security/gatewayAuth.js';
import { getHelmetConfig, getCorsConfig, additionalSecurityHeaders } from '../security/securityHeaders.js';
import { auditInfo, auditWarn, auditError } from '../security/auditLogger.js';

export type MessageHandler = (msg: OCMessage) => Promise<string>;

export interface GatewayOptions {
  config: OpenClawConfig;
  onMessage: MessageHandler;
}

export class Gateway {
  private app = express();
  private httpServer: HTTPServer;
  private wss: WebSocketServer;
  private config: OpenClawConfig;
  private onMessage: MessageHandler;
  private connections = new Map<string, WebSocket>();

  constructor(opts: GatewayOptions) {
    this.config = opts.config;
    this.onMessage = opts.onMessage;

    // Express middleware
    const corsOrigin = this.config.channels.webchat?.corsOrigin ?? 'http://localhost:18789';
    this.app.use(helmet(getHelmetConfig()));
    this.app.use(cors(getCorsConfig(corsOrigin)));
    this.app.use(additionalSecurityHeaders());

    // Health endpoint
    this.app.get('/health', (_req, res) => {
      res.json({
        status: 'ok',
        version: this.config.version,
        uptime: process.uptime(),
        connections: this.connections.size,
      });
    });

    // Create HTTP server from express
    this.httpServer = createServer(this.app);

    // WebSocket server on same HTTP server
    this.wss = new WebSocketServer({
      server: this.httpServer,
      path: '/ws',
      verifyClient: (info, cb) => {
        const ip = info.req.socket.remoteAddress ?? 'unknown';
        const token = this.extractToken(info.req);
        const auth = authenticateRequest(token, this.config.security.gatewayToken, ip);
        if (!auth.ok) {
          auditWarn('ws_connection_rejected', { details: { ip, reason: auth.reason } });
          cb(false, 401, auth.reason);
        } else {
          cb(true);
        }
      },
    });

    this.wss.on('connection', (ws, req) => {
      const connId = crypto.randomUUID();
      const ip = req.socket.remoteAddress ?? 'unknown';
      this.connections.set(connId, ws);
      auditInfo('ws_connected', { details: { connId, ip } });

      ws.on('message', async (data: RawData) => {
        try {
          const parsed = JSON.parse(data.toString());
          const msg: OCMessage = {
            channel: 'webchat' as ChannelType,
            contactId: connId,
            text: parsed.text ?? '',
            timestamp: Date.now(),
          };
          const response = await this.onMessage(msg);
          if (ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({ type: 'message', text: response }));
          }
        } catch (err) {
          auditError('ws_message_error', { details: { connId, error: String(err) } });
          if (ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({ type: 'error', text: 'Failed to process message' }));
          }
        }
      });

      ws.on('close', () => {
        this.connections.delete(connId);
        auditInfo('ws_disconnected', { details: { connId } });
      });

      ws.on('error', (err) => {
        auditError('ws_error', { details: { connId, error: String(err) } });
      });
    });
  }

  /**
   * Get the Express app for mounting additional routes (e.g., webchat UI).
   */
  get expressApp() {
    return this.app;
  }

  /**
   * Start the gateway server.
   */
  async start(): Promise<void> {
    const { host, port } = this.config.gateway;
    return new Promise((resolve, reject) => {
      this.httpServer.listen(port, host, () => {
        auditInfo('gateway_started', { details: { host, port } });
        console.log(`[Gateway] Listening on ${host}:${port}`);
        resolve();
      });
      this.httpServer.on('error', reject);
    });
  }

  /**
   * Stop the gateway server.
   */
  async stop(): Promise<void> {
    // Close all WS connections
    for (const [id, ws] of this.connections) {
      ws.close(1001, 'Server shutting down');
      this.connections.delete(id);
    }
    this.wss.close();
    return new Promise((resolve) => {
      this.httpServer.close(() => {
        auditInfo('gateway_stopped');
        resolve();
      });
    });
  }

  /**
   * Send a message to a specific WebSocket connection.
   */
  sendToConnection(connId: string, text: string): boolean {
    const ws = this.connections.get(connId);
    if (!ws || ws.readyState !== WebSocket.OPEN) return false;
    ws.send(JSON.stringify({ type: 'message', text }));
    return true;
  }

  private extractToken(req: IncomingMessage): string | undefined {
    const auth = req.headers['authorization'];
    if (auth?.startsWith('Bearer ')) return auth.slice(7);
    const url = new URL(req.url ?? '/', `http://${req.headers.host}`);
    return url.searchParams.get('token') ?? undefined;
  }
}
