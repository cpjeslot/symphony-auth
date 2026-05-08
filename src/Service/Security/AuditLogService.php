<?php

declare(strict_types=1);

namespace App\Service\Security;

use App\Entity\SecurityAuditLog;
use App\Entity\User;
use App\Enum\AuditEventType;
use App\Repository\SecurityAuditLogRepository;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\RequestStack;

/**
 * AuditLogService — Central service for recording security events.
 *
 * All security-relevant actions in the application should be recorded
 * through this service to maintain a complete audit trail.
 *
 * Design principles:
 * - Non-blocking: errors in audit logging should never break the main flow
 * - Structured: all events use standardized AuditEventType enum
 * - Contextual: additional metadata stored as JSONB
 * - Masked: sensitive data (passwords, tokens) must never be logged
 */
class AuditLogService
{
    public function __construct(
        private readonly SecurityAuditLogRepository $auditLogRepository,
        private readonly RequestStack $requestStack,
        private readonly LoggerInterface $auditLogger,    // 'audit' monolog channel
    ) {}

    /**
     * Record a security event in the audit log.
     *
     * @param array<string, mixed> $context Additional event context (no sensitive data)
     */
    public function log(
        AuditEventType $eventType,
        ?User $user = null,
        ?string $description = null,
        array $context = [],
        ?string $entityType = null,
        ?string $entityId = null,
    ): void {
        try {
            $request = $this->requestStack->getCurrentRequest();
            $ipAddress = $request?->getClientIp();
            $userAgent = $request?->headers->get('User-Agent');

            $log = new SecurityAuditLog();
            $log->setEventType($eventType);
            $log->setUser($user);
            $log->setDescription($description);
            $log->setIpAddress($ipAddress);
            $log->setUserAgent($userAgent);
            $log->setContext($this->sanitizeContext($context));
            $log->setEntityType($entityType);
            $log->setEntityId($entityId);

            $this->auditLogRepository->save($log);

            // Also write to structured security log file via Monolog
            $this->auditLogger->info($eventType->value, [
                'user_id' => $user?->getId()?->toString(),
                'event' => $eventType->value,
                'severity' => $eventType->severity(),
                'ip' => $ipAddress,
                'description' => $description,
                'context' => $context,
            ]);
        } catch (\Throwable $e) {
            // CRITICAL: Audit log failure must never break the main application flow.
            // Log the error but do not re-throw.
            $this->auditLogger->error('Failed to write audit log entry', [
                'event_type' => $eventType->value,
                'error' => $e->getMessage(),
            ]);
        }
    }

    /**
     * Convenience shorthand methods for common events.
     */
    public function logLoginSuccess(User $user, ?string $method = 'email'): void
    {
        $this->log(
            AuditEventType::LoginSuccess,
            $user,
            "Successful login via {$method}",
            ['auth_method' => $method]
        );
    }

    public function logLoginFailure(
        ?User $user,
        string $identifier,
        string $reason,
    ): void {
        $this->log(
            AuditEventType::LoginFailure,
            $user,
            "Login failure: {$reason}",
            [
                // Mask identifier for privacy — only log domain part of email
                'identifier_masked' => $this->maskIdentifier($identifier),
                'reason' => $reason,
            ]
        );
    }

    public function logOtpSent(User $user): void
    {
        $this->log(AuditEventType::OtpSent, $user, '2FA OTP sent via email');
    }

    public function logOtpVerified(User $user): void
    {
        $this->log(AuditEventType::OtpVerifySuccess, $user, '2FA OTP verification successful');
    }

    public function logOtpFailed(User $user, int $attemptsRemaining): void
    {
        $this->log(
            AuditEventType::OtpVerifyFailure,
            $user,
            'OTP verification failed',
            ['attempts_remaining' => $attemptsRemaining]
        );
    }

    public function logPasswordChanged(User $user): void
    {
        $this->log(AuditEventType::PasswordChanged, $user, 'Password changed successfully');
    }

    public function logPasswordResetRequested(User $user): void
    {
        $this->log(AuditEventType::PasswordResetRequested, $user, 'Password reset link requested');
    }

    public function logSocialLogin(User $user, string $provider): void
    {
        $this->log(
            AuditEventType::SocialLoginSuccess,
            $user,
            "Social login via {$provider}",
            ['provider' => $provider]
        );
    }

    public function logAccountLocked(User $user, int $failedAttempts): void
    {
        $this->log(
            AuditEventType::LoginLockedOut,
            $user,
            'Account temporarily locked due to failed login attempts',
            ['failed_attempts' => $failedAttempts]
        );
    }

    public function logTwoFactorEnabled(User $user): void
    {
        $this->log(AuditEventType::TwoFactorEnabled, $user, '2FA enabled by user');
    }

    public function logTwoFactorDisabled(User $user): void
    {
        $this->log(AuditEventType::TwoFactorDisabled, $user, '2FA disabled by user');
    }

    /**
     * Sanitize context array to remove any sensitive data before storage.
     *
     * @param array<string, mixed> $context
     * @return array<string, mixed>
     */
    private function sanitizeContext(array $context): array
    {
        // List of keys that should NEVER appear in audit logs
        $sensitiveKeys = ['password', 'token', 'otp', 'hash', 'secret', 'key', 'credential'];

        foreach ($sensitiveKeys as $sensitiveKey) {
            foreach (array_keys($context) as $key) {
                if (str_contains(strtolower((string) $key), $sensitiveKey)) {
                    $context[$key] = '[REDACTED]';
                }
            }
        }

        return $context;
    }

    /**
     * Mask an identifier (email/phone) for privacy-safe logging.
     *
     * Examples:
     *   john.doe@example.com → j***@example.com
     *   +14155552671 → +1***2671
     */
    private function maskIdentifier(string $identifier): string
    {
        if (str_contains($identifier, '@')) {
            [$local, $domain] = explode('@', $identifier, 2);
            $maskedLocal = substr($local, 0, 1) . str_repeat('*', max(3, strlen($local) - 1));

            return $maskedLocal . '@' . $domain;
        }

        // Phone number masking
        if (strlen($identifier) > 6) {
            return substr($identifier, 0, 3) . str_repeat('*', strlen($identifier) - 6) . substr($identifier, -3);
        }

        return '***';
    }
}
