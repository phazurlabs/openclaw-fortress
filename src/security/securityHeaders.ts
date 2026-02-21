/**
 * G-04: Security Headers
 * CSP, X-Frame-Options, helmet config, CORS.
 */
import type { RequestHandler } from 'express';

/**
 * Get helmet configuration for the gateway.
 */
export function getHelmetConfig() {
  return {
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"], // needed for inline chat styles
        imgSrc: ["'self'", 'data:'],
        connectSrc: ["'self'", 'ws://localhost:*', 'wss://localhost:*'],
        fontSrc: ["'self'"],
        objectSrc: ["'none'"],
        mediaSrc: ["'none'"],
        frameSrc: ["'none'"],
        baseUri: ["'self'"],
        formAction: ["'self'"],
        frameAncestors: ["'none'"],
      },
    },
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
