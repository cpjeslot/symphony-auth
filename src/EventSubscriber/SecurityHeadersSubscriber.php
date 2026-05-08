<?php

declare(strict_types=1);

namespace App\EventSubscriber;

use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpKernel\Event\ResponseEvent;
use Symfony\Component\HttpKernel\KernelEvents;

/**
 * SecurityHeadersSubscriber — Adds security headers to all HTTP responses.
 *
 * Implements defense-in-depth at the HTTP level:
 * - Content Security Policy (CSP): prevents XSS
 * - X-Frame-Options: prevents clickjacking
 * - X-Content-Type-Options: prevents MIME sniffing
 * - Referrer-Policy: controls referrer information leakage
 * - Permissions-Policy: disables unused browser features
 * - Strict-Transport-Security (HSTS): enforces HTTPS in production
 *
 * Note: In production, HSTS should also be set at the nginx/Apache level.
 * Helmet.js equivalent for PHP/Symfony.
 */
class SecurityHeadersSubscriber implements EventSubscriberInterface
{
    public function __construct(
        private readonly string $appEnv,
    ) {}

    public static function getSubscribedEvents(): array
    {
        return [
            KernelEvents::RESPONSE => ['onKernelResponse', -100],  // Low priority (runs last)
        ];
    }

    /**
     * Add security headers to every response.
     */
    public function onKernelResponse(ResponseEvent $event): void
    {
        if (!$event->isMainRequest()) {
            return;
        }

        $response = $event->getResponse();

        // ── Content Security Policy ────────────────────────────────────────────
        // Restricts sources of scripts, styles, images, fonts, etc.
        // Adjust 'script-src' and 'style-src' based on your CDN/inline needs.
        $csp = implode('; ', [
            "default-src 'self'",
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net",  // Bootstrap JS
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com",
            "font-src 'self' https://fonts.gstatic.com https://cdn.jsdelivr.net",
            "img-src 'self' data: https:",
            "connect-src 'self'",
            "frame-src 'none'",
            "object-src 'none'",
            "base-uri 'self'",
            "form-action 'self'",
            "upgrade-insecure-requests",
        ]);

        $response->headers->set('Content-Security-Policy', $csp);

        // ── X-Frame-Options ────────────────────────────────────────────────────
        // Prevents the page from being embedded in iframes (clickjacking defense)
        $response->headers->set('X-Frame-Options', 'DENY');

        // ── X-Content-Type-Options ─────────────────────────────────────────────
        // Prevents browsers from MIME-sniffing the content type
        $response->headers->set('X-Content-Type-Options', 'nosniff');

        // ── Referrer-Policy ───────────────────────────────────────────────────
        // Controls how much referrer information is included in requests
        $response->headers->set('Referrer-Policy', 'strict-origin-when-cross-origin');

        // ── Permissions-Policy ────────────────────────────────────────────────
        // Disables access to browser features the app doesn't use
        $response->headers->set('Permissions-Policy', implode(', ', [
            'camera=()',
            'microphone=()',
            'geolocation=()',
            'payment=()',
            'usb=()',
            'magnetometer=()',
            'accelerometer=()',
        ]));

        // ── Strict-Transport-Security (HSTS) ──────────────────────────────────
        // Enforce HTTPS for 1 year in production
        // WARNING: Only enable in production with valid SSL certificate
        if ($this->appEnv === 'prod' && $response->isSuccessful()) {
            $response->headers->set(
                'Strict-Transport-Security',
                'max-age=31536000; includeSubDomains; preload'
            );
        }

        // ── Remove server information headers ─────────────────────────────────
        // Prevents server fingerprinting
        $response->headers->remove('X-Powered-By');
        $response->headers->remove('Server');
    }
}
