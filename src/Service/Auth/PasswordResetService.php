<?php

declare(strict_types=1);

namespace App\Service\Auth;

use App\Entity\PasswordResetToken;
use App\Entity\User;
use App\Enum\AuditEventType;
use App\Repository\PasswordResetTokenRepository;
use App\Repository\UserRepository;
use App\Service\Security\AuditLogService;
use Doctrine\ORM\EntityManagerInterface;
use Psr\Log\LoggerInterface;
use Symfony\Component\Mailer\MailerInterface;
use Symfony\Component\Mime\Email;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;

/**
 * PasswordResetService — Handles the complete forgot password / reset flow.
 *
 * Security design:
 * - Enumeration attack protection: identical response whether email exists or not
 * - Token = 32 bytes CSPRNG, SHA-256 hashed for storage
 * - Tokens are single-use and time-limited (default 2 hours)
 * - Old tokens invalidated before issuing new ones
 * - Rate limiting applied at controller level (password_reset_limiter)
 * - New password is re-hashed with Argon2id
 */
class PasswordResetService
{
    public function __construct(
        private readonly PasswordResetTokenRepository $tokenRepository,
        private readonly UserRepository $userRepository,
        private readonly EntityManagerInterface $entityManager,
        private readonly UserPasswordHasherInterface $passwordHasher,
        private readonly MailerInterface $mailer,
        private readonly AuditLogService $auditLog,
        private readonly UrlGeneratorInterface $urlGenerator,
        private readonly LoggerInterface $logger,
        private readonly string $mailerFromAddress,
        private readonly string $mailerFromName,
        private readonly int $passwordResetExpiry = 7200, // 2 hours
    ) {}

    /**
     * Initiate password reset flow for a given email address.
     *
     * SECURITY: This method MUST return without any indication of whether
     * the email exists in the system. This prevents account enumeration.
     */
    public function initiateReset(string $email, ?string $ipAddress = null): void
    {
        // Normalize email for lookup
        $email = mb_strtolower(trim($email));

        // Always log and proceed, even if user not found
        $this->logger->info('Password reset initiated', ['ip' => $ipAddress]);

        $user = $this->userRepository->findByEmail($email);

        if ($user === null) {
            // SECURITY: Simulate a delay to prevent timing attacks that could
            // reveal whether the email exists (timing side-channel)
            usleep(random_int(100000, 300000)); // 0.1–0.3 second random delay
            return;
        }

        if (!$user->isActive()) {
            // Account is not active — still return silently (enumeration prevention)
            return;
        }

        // Invalidate any existing reset tokens for this user
        $this->tokenRepository->invalidateUserTokens($user);

        // Generate cryptographically secure token
        $plainToken = bin2hex(random_bytes(32));         // 64-char hex string
        $tokenHash = hash('sha256', $plainToken);        // SHA-256 for storage
        $expiresAt = new \DateTimeImmutable("+{$this->passwordResetExpiry} seconds");

        $resetToken = new PasswordResetToken();
        $resetToken->setUser($user);
        $resetToken->setTokenHash($tokenHash);
        $resetToken->setExpiresAt($expiresAt);
        $resetToken->setRequestIp($ipAddress);

        $this->tokenRepository->save($resetToken);

        // Send reset email
        try {
            $this->sendResetEmail($user, $plainToken);
        } catch (\Throwable $e) {
            $this->logger->error('Failed to send password reset email', [
                'user_id' => $user->getId()?->toString(),
                'error' => $e->getMessage(),
            ]);
        }

        $this->auditLog->logPasswordResetRequested($user);
    }

    /**
     * Complete the password reset using the submitted token and new password.
     *
     * @throws \InvalidArgumentException If token is invalid, expired, or used
     */
    public function resetPassword(string $plainToken, string $newPassword): void
    {
        $tokenHash = hash('sha256', $plainToken);

        $tokenRecord = $this->tokenRepository->findValidByTokenHash($tokenHash);

        if ($tokenRecord === null) {
            throw new \InvalidArgumentException(
                'This password reset link is invalid or has expired. Please request a new one.'
            );
        }

        $user = $tokenRecord->getUser();

        if ($user === null || !$user->isActive()) {
            throw new \InvalidArgumentException('Invalid password reset request.');
        }

        // Wrap in transaction
        $this->entityManager->wrapInTransaction(function () use ($tokenRecord, $user, $newPassword): void {
            // Mark token as used (prevents replay)
            $tokenRecord->markAsUsed();
            $this->entityManager->persist($tokenRecord);

            // Hash new password
            $hashedPassword = $this->passwordHasher->hashPassword($user, $newPassword);
            $user->setPasswordHash($hashedPassword);
            $user->resetFailedLoginAttempts();           // Clear any lockout

            $this->entityManager->persist($user);
            $this->entityManager->flush();
        });

        $this->auditLog->log(
            AuditEventType::PasswordResetCompleted,
            $user,
            'Password reset completed successfully',
        );
        $this->auditLog->logPasswordChanged($user);

        $this->logger->info('Password reset completed', [
            'user_id' => $user->getId()?->toString(),
        ]);
    }

    /**
     * Send password reset email.
     */
    private function sendResetEmail(User $user, string $plainToken): void
    {
        $expiryMinutes = (int) ceil($this->passwordResetExpiry / 60);

        $resetUrl = $this->urlGenerator->generate(
            'app_password_reset',
            ['token' => $plainToken],
            UrlGeneratorInterface::ABSOLUTE_URL
        );

        $email = (new Email())
            ->from("{$this->mailerFromName} <{$this->mailerFromAddress}>")
            ->to((string) $user->getEmail())
            ->subject('Reset your password')
            ->text(
                "Hello {$user->getFirstName()},\n\n"
                . "A password reset was requested for your account.\n\n"
                . "Reset link: {$resetUrl}\n\n"
                . "This link expires in {$expiryMinutes} minutes.\n\n"
                . "If you did not request this, you can safely ignore this email.\n"
                . "Your account is not at risk."
            )
            ->html($this->buildResetEmailHtml(
                $user->getFirstName() ?? 'User',
                $resetUrl,
                $expiryMinutes
            ));

        $this->mailer->send($email);
    }

    private function buildResetEmailHtml(string $firstName, string $resetUrl, int $expiryMinutes): string
    {
        return <<<HTML
<!DOCTYPE html>
<html>
<body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; background: #f5f5f5;">
<div style="background: white; border-radius: 8px; padding: 40px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);">
    <h2 style="color: #1a1a2e;">Reset Your Password</h2>
    <p style="color: #555;">Hello {$firstName},</p>
    <p style="color: #555;">We received a request to reset your password. Click below to choose a new password.</p>
    <div style="text-align: center; margin: 30px 0;">
        <a href="{$resetUrl}" 
           style="background: #e74c3c; color: white; padding: 14px 32px; text-decoration: none; border-radius: 6px; font-size: 16px; font-weight: bold;">
            Reset My Password
        </a>
    </div>
    <p style="color: #555; font-size: 14px;">This link expires in <strong>{$expiryMinutes} minutes</strong>.</p>
    <p style="color: #aaa; font-size: 12px;">If you did not request a password reset, please ignore this email. Your account is safe.</p>
</div>
</body>
</html>
HTML;
    }
}
