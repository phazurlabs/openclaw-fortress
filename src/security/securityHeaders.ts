/**
 * G-04: Security Headers
 * CSP, X-Frame-Options, helmet config, CORS.
 */
import type { RequestHandler } from 'express';

/**
 * Get helmet configuration for the gateway.
 * CSP is applied per-route with a nonce for the WebChat inline script.
 */
export function getHelmetConfig() {
  return {
    contentSecurityPolicy: false, // applied per-route via cspMiddleware
    crossOriginEmbedderPolicy: false, // needed for WS
    crossOriginOpenerPolicy: { policy: 'same-origin' as const },
    crossOriginResourcePolicy: { policy: 'same-origin' as const },
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' as const },
    hsts: { maxAge: 31536000, includeSubDomains: true },
    xContentTypeOptions: true as const,
    xDnsPrefetchControl: { allow: false },
    xDownloadOptions: true as const,
    xFrameOptions: { action: 'deny' as const },
    xPermittedCrossDomainPolicies: { permittedPolicies: 'none' as const },
    xPoweredBy: false,
    xXssProtection: true as const,
  };
}

/**
 * CSP middleware that generates a per-request nonce.
 * The nonce is stored on res.locals.cspNonce for use in HTML templates.
 */
export function cspMiddleware(): RequestHandler {
  return (_req, res, next) => {
    const nonce = crypto.randomUUID().replace(/-/g, '');
    res.locals['cspNonce'] = nonce;
    res.setHeader('Content-Security-Policy', [
      `default-src 'self'`,
      `script-src 'nonce-${nonce}'`,
      `style-src 'self' 'unsafe-inline'`,
      `img-src 'self' data:`,
      `connect-src 'self' ws://localhost:* wss://localhost:* ws://127.0.0.1:* wss://127.0.0.1:*`,
      `font-src 'self'`,
      `object-src 'none'`,
      `media-src 'none'`,
      `frame-src 'none'`,
      `base-uri 'self'`,
      `form-action 'self'`,
      `frame-ancestors 'none'`,
    ].join('; '));
    next();
  };
}

/**
 * Get CORS configuration.
 */
export function getCorsConfig(origin: string) {
  return {
    origin,
    methods: ['GET', 'POST'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true,
    maxAge: 86400,
  };
}

/**
 * Additional security headers as Express middleware.
 */
export function additionalSecurityHeaders(): RequestHandler {
  return (_req, res, next) => {
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
    res.setHeader('X-Request-Id', crypto.randomUUID());
    next();
  };
}
