<?php

declare(strict_types=1);

namespace App\Service\Auth;

use App\Entity\EmailVerificationToken;
use App\Entity\User;
use App\Enum\AccountStatus;
use App\Enum\AuditEventType;
use App\Repository\EmailVerificationTokenRepository;
use App\Repository\UserRepository;
use App\Service\Security\AuditLogService;
use Psr\Log\LoggerInterface;

/**
 * EmailVerificationService — Handles email address verification flow.
 *
 * Security design:
 * - Token stored as SHA-256 hash (never plaintext)
 * - Tokens are single-use (marked used after verification)
 * - Expired tokens are rejected
 * - Same response for invalid vs expired token (prevents enumeration)
 */
class EmailVerificationService
{
    public function __construct(
        private readonly EmailVerificationTokenRepository $tokenRepository,
        private readonly UserRepository $userRepository,
        private readonly AuditLogService $auditLog,
        private readonly LoggerInterface $logger,
    ) {}

    /**
     * Verify an email address using the provided token.
     *
     * SECURITY: Always respond with the same generic message whether the
     * token is invalid, expired, or doesn't exist — prevent enumeration.
     *
     * @return bool True if verification succeeded
     */
    public function verifyEmail(string $plainToken): bool
    {
        // Hash the received token to compare with stored hash
        $tokenHash = hash('sha256', $plainToken);

        $tokenRecord = $this->tokenRepository->findValidByTokenHash($tokenHash);

        if ($tokenRecord === null) {
            $this->logger->warning('Email verification attempted with invalid/expired token');
            return false;
        }

        $user = $tokenRecord->getUser();

        if ($user === null) {
            return false;
        }

        // Mark token as used (prevents replay)
        $tokenRecord->markAsUsed();
        $this->tokenRepository->save($tokenRecord);

        // Activate the user's email
        $user->setEmailVerified(true);

        // If account was pending verification, activate it
        if ($user->getAccountStatus() === AccountStatus::PendingVerification) {
            $user->setAccountStatus(AccountStatus::Active);
        }

        $this->userRepository->save($user);

        $this->auditLog->log(
            AuditEventType::EmailVerified,
            $user,
            'Email address verified successfully',
        );

        $this->logger->info('Email verified successfully', [
            'user_id' => $user->getId()?->toString(),
        ]);

        return true;
    }
}
