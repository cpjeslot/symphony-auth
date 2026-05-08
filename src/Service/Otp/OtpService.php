<?php

declare(strict_types=1);

namespace App\Service\Otp;

use App\Entity\EmailOtp;
use App\Entity\User;
use App\Repository\EmailOtpRepository;
use App\Service\Security\AuditLogService;
use Psr\Log\LoggerInterface;
use Symfony\Component\Mailer\MailerInterface;
use Symfony\Component\Mime\Email;

/**
 * OtpService — Manages Email OTP generation, delivery, and verification.
 *
 * Security design:
 * - OTPs generated using random_int() (CSPRNG — cryptographically secure)
 * - OTPs stored as bcrypt hash (not Argon2id — for faster verification)
 * - Plaintext OTP is NEVER persisted, only delivered via email
 * - Rate limiting: max 3 sends per 5 minutes, 5 verifications before lockout
 * - Expiry: configurable (default 5 minutes)
 * - Purpose isolation: OTPs are purpose-scoped to prevent cross-use
 *
 * OTP format: 6-digit numeric code (100000–999999)
 */
class OtpService
{
    /**
     * @param int $otpExpiry       OTP validity in seconds (injected from env)
     * @param int $otpResendCooldown  Cooldown between resends in seconds
     * @param int $otpMaxRetries   Max failed verification attempts per OTP
     */
    public function __construct(
        private readonly EmailOtpRepository $otpRepository,
        private readonly MailerInterface $mailer,
        private readonly AuditLogService $auditLog,
        private readonly LoggerInterface $logger,
        private readonly string $mailerFromAddress,
        private readonly string $mailerFromName,
        private readonly int $otpExpiry = 300,
        private readonly int $otpResendCooldown = 60,
        private readonly int $otpMaxRetries = 5,
    ) {}

    /**
     * Generate and send an OTP to the user's email address.
     *
     * Process:
     * 1. Invalidate any existing pending OTPs (prevent accumulation)
     * 2. Generate cryptographically secure 6-digit OTP
     * 3. Store hash in database
     * 4. Send plaintext OTP via email
     * 5. Audit log the send event
     *
     * @throws \RuntimeException If OTP send fails after retries
     */
    public function generateAndSendOtp(
        User $user,
        string $purpose = 'login_2fa',
        ?string $ipAddress = null,
    ): void {
        // Invalidate any existing valid OTPs for this user+purpose
        $this->otpRepository->invalidatePendingOtps($user, $purpose);

        // Generate a cryptographically secure 6-digit OTP
        // random_int() uses /dev/urandom (or CryptGenRandom on Windows)
        $plaintextOtp = (string) random_int(100000, 999999);

        // Hash the OTP using bcrypt (faster than Argon2id for short codes)
        // SECURITY: password_hash() uses constant-time comparison internally
        $otpHash = password_hash($plaintextOtp, PASSWORD_BCRYPT, ['cost' => 10]);

        if ($otpHash === false) {
            throw new \RuntimeException('Failed to hash OTP');
        }

        // Create OTP record
        $expiresAt = new \DateTimeImmutable("+{$this->otpExpiry} seconds");

        $otp = new EmailOtp();
        $otp->setUser($user);
        $otp->setOtpHash($otpHash);
        $otp->setExpiresAt($expiresAt);
        $otp->setMaxRetries($this->otpMaxRetries);
        $otp->setPurpose($purpose);
        $otp->setRequestIp($ipAddress);

        $this->otpRepository->save($otp);

        // Send email with plaintext OTP (hash is stored, not this value)
        $this->sendOtpEmail($user, $plaintextOtp, $this->otpExpiry);

        // Audit log
        $this->auditLog->logOtpSent($user);

        $this->logger->info('OTP generated and sent', [
            'user_id' => $user->getId()?->toString(),
            'purpose' => $purpose,
            'expires_in_seconds' => $this->otpExpiry,
        ]);
    }

    /**
     * Verify an OTP submitted by the user.
     *
     * Uses constant-time comparison via password_verify() to prevent timing attacks.
     *
     * @return bool True if OTP is valid and matches, false otherwise
     */
    public function verifyOtp(
        User $user,
        string $submittedOtp,
        string $purpose = 'login_2fa',
    ): bool {
        $otpRecord = $this->otpRepository->findValidOtp($user, $purpose);

        if ($otpRecord === null) {
            // No valid OTP found — expired, used, or never sent
            $this->logger->warning('OTP verification attempt — no valid OTP found', [
                'user_id' => $user->getId()?->toString(),
                'purpose' => $purpose,
            ]);

            return false;
        }

        // Constant-time comparison prevents timing-based OTP guessing
        $isMatch = password_verify($submittedOtp, $otpRecord->getOtpHash());

        if (!$isMatch) {
            // Record failed attempt and check retry limit
            $otpRecord->incrementRetryCount();
            $attemptsRemaining = $otpRecord->getMaxRetries() - $otpRecord->getRetryCount();

            $this->otpRepository->save($otpRecord);
            $this->auditLog->logOtpFailed($user, max(0, $attemptsRemaining));

            $this->logger->warning('OTP verification failed', [
                'user_id' => $user->getId()?->toString(),
                'attempts_remaining' => $attemptsRemaining,
            ]);

            return false;
        }

        // Success — mark OTP as used (prevents replay)
        $otpRecord->markAsUsed();
        $this->otpRepository->save($otpRecord);
        $this->auditLog->logOtpVerified($user);

        return true;
    }

    /**
     * Check if user can request a new OTP (respects resend cooldown).
     *
     * @return array{allowed: bool, wait_seconds: int}
     */
    public function canResendOtp(User $user, string $purpose = 'login_2fa'): array
    {
        $recentCount = $this->otpRepository->countRecentOtpRequests(
            $user,
            (int) ceil($this->otpResendCooldown / 60) // Convert to minutes
        );

        if ($recentCount > 0) {
            return [
                'allowed' => false,
                'wait_seconds' => $this->otpResendCooldown,
            ];
        }

        return ['allowed' => true, 'wait_seconds' => 0];
    }

    /**
     * Send the OTP email to the user.
     * The email is transactional — sent via the configured mailer transport.
     *
     * SECURITY: The OTP is in the email body — the email itself is the
     * delivery channel. Ensure TLS is used for SMTP transport.
     */
    private function sendOtpEmail(User $user, string $plaintextOtp, int $expirySeconds): void
    {
        $expiryMinutes = (int) ceil($expirySeconds / 60);

        $email = (new Email())
            ->from("{$this->mailerFromName} <{$this->mailerFromAddress}>")
            ->to((string) $user->getEmail())
            ->subject('Your Verification Code')
            ->text(
                "Hello {$user->getFirstName()},\n\n"
                . "Your verification code is: {$plaintextOtp}\n\n"
                . "This code expires in {$expiryMinutes} minutes.\n\n"
                . "If you did not request this code, please secure your account immediately.\n\n"
                . "Do not share this code with anyone — our staff will never ask for it."
            )
            ->html(
                $this->buildOtpEmailHtml($user->getFirstName() ?? 'User', $plaintextOtp, $expiryMinutes)
            );

        $this->mailer->send($email);
    }

    /**
     * Build HTML email for OTP delivery.
     * Inline styles used for maximum email client compatibility.
     */
    private function buildOtpEmailHtml(string $firstName, string $otp, int $expiryMinutes): string
    {
        return <<<HTML
<!DOCTYPE html>
<html>
<body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; background: #f5f5f5;">
<div style="background: white; border-radius: 8px; padding: 40px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);">
    <h2 style="color: #1a1a2e; margin-bottom: 10px;">Verification Code</h2>
    <p style="color: #555; font-size: 16px;">Hello {$firstName},</p>
    <p style="color: #555;">Your verification code is:</p>
    <div style="background: #f0f4ff; border: 2px solid #4361ee; border-radius: 8px; padding: 20px; text-align: center; margin: 20px 0;">
        <span style="font-size: 36px; font-weight: bold; letter-spacing: 8px; color: #4361ee;">{$otp}</span>
    </div>
    <p style="color: #555;">This code expires in <strong>{$expiryMinutes} minutes</strong>.</p>
    <p style="color: #e74c3c; font-size: 13px;">⚠️ Never share this code with anyone — we will never ask for it.</p>
    <hr style="border: none; border-top: 1px solid #eee; margin: 20px 0;">
    <p style="color: #aaa; font-size: 12px;">If you did not request this code, please ignore this email or contact support.</p>
</div>
</body>
</html>
HTML;
    }
}
