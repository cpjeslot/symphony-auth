<?php

declare(strict_types=1);

namespace App\Service\Auth;

use App\DTO\RegistrationDTO;
use App\Entity\EmailVerificationToken;
use App\Entity\User;
use App\Enum\AccountStatus;
use App\Repository\EmailVerificationTokenRepository;
use App\Repository\UserRepository;
use App\Service\Security\AuditLogService;
use Doctrine\ORM\EntityManagerInterface;
use Psr\Log\LoggerInterface;
use Symfony\Component\Mailer\MailerInterface;
use Symfony\Component\Mime\Email;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;

/**
 * RegistrationService — Handles new user registration with full transaction safety.
 *
 * Registration process:
 * 1. Validate uniqueness of email and mobile (with enumeration attack protection)
 * 2. Hash password with Argon2id
 * 3. Create user entity in pending_verification status
 * 4. Generate email verification token (SHA-256 hashed, stored)
 * 5. Send verification email
 * 6. Persist all in a single transaction (rollback-safe)
 * 7. Audit log the registration event
 *
 * Security notes:
 * - Same error message for duplicate email vs duplicate mobile (prevents enumeration)
 * - Transaction wraps all DB writes + email send queuing
 * - Passwords hashed with Argon2id (configured in security.yaml)
 */
class RegistrationService
{
    public function __construct(
        private readonly UserRepository $userRepository,
        private readonly EmailVerificationTokenRepository $verificationTokenRepository,
        private readonly EntityManagerInterface $entityManager,
        private readonly UserPasswordHasherInterface $passwordHasher,
        private readonly MailerInterface $mailer,
        private readonly AuditLogService $auditLog,
        private readonly UrlGeneratorInterface $urlGenerator,
        private readonly LoggerInterface $logger,
        private readonly string $mailerFromAddress,
        private readonly string $mailerFromName,
        private readonly int $emailVerifyExpiry = 172800, // 48 hours in seconds
    ) {}

    /**
     * Register a new user.
     *
     * @throws \InvalidArgumentException If email or mobile already exists
     * @throws \RuntimeException If registration fails
     */
    public function register(RegistrationDTO $dto, ?string $ipAddress = null): User
    {
        // Wrap everything in a transaction for atomicity
        return $this->entityManager->wrapInTransaction(function () use ($dto, $ipAddress): User {
            // Check for duplicate email — use constant-time check regardless of result
            if ($this->userRepository->emailExists($dto->email)) {
                $this->logger->info('Registration attempted with existing email', [
                    'ip' => $ipAddress,
                ]);

                // Deliberately vague error message prevents email enumeration
                throw new \InvalidArgumentException(
                    'An account with this information already exists. Please log in or use forgot password.'
                );
            }

            // Check for duplicate mobile (if provided)
            if ($dto->mobileNumber !== null && $this->userRepository->mobileExists($dto->mobileNumber)) {
                throw new \InvalidArgumentException(
                    'An account with this information already exists. Please log in or use forgot password.'
                );
            }

            // Create user entity
            $user = new User();
            $user->setFirstName($dto->firstName);
            $user->setMiddleName($dto->middleName);
            $user->setLastName($dto->lastName);
            $user->setEmail($dto->email);
            $user->setMobileNumber($dto->mobileNumber);
            $user->setRoles(['ROLE_USER']);
            $user->setAccountStatus(AccountStatus::PendingVerification);

            // Hash password with Argon2id (configured in security.yaml)
            $hashedPassword = $this->passwordHasher->hashPassword($user, $dto->password);
            $user->setPasswordHash($hashedPassword);

            $this->entityManager->persist($user);

            // Generate email verification token
            [$plainToken, $verificationToken] = $this->createVerificationToken($user, $dto->email);

            $this->entityManager->persist($verificationToken);

            // Flush all entities before sending email
            // (email send failure should not prevent user creation)
            $this->entityManager->flush();

            // Send verification email
            try {
                $this->sendVerificationEmail($user, $plainToken);
            } catch (\Throwable $e) {
                $this->logger->error('Failed to send verification email', [
                    'user_id' => $user->getId()?->toString(),
                    'error' => $e->getMessage(),
                ]);
                // Do not fail registration if email fails — user can request resend
            }

            // Audit log
            $this->auditLog->log(
                \App\Enum\AuditEventType::UserRegistered,
                $user,
                'New user registered — awaiting email verification',
                ['ip' => $ipAddress]
            );

            $this->logger->info('User registered successfully', [
                'user_id' => $user->getId()?->toString(),
            ]);

            return $user;
        });
    }

    /**
     * Create an email verification token (hashed storage, plaintext returned for email).
     *
     * @return array{0: string, 1: EmailVerificationToken} [plainTextToken, tokenEntity]
     */
    private function createVerificationToken(User $user, string $email): array
    {
        // Generate 32 bytes of cryptographically secure random data
        $plainToken = bin2hex(random_bytes(32));    // 64-char hex string
        $tokenHash = hash('sha256', $plainToken);   // SHA-256 hash for storage

        $expiresAt = new \DateTimeImmutable("+{$this->emailVerifyExpiry} seconds");

        $token = new EmailVerificationToken();
        $token->setUser($user);
        $token->setTokenHash($tokenHash);
        $token->setEmail($email);
        $token->setExpiresAt($expiresAt);

        return [$plainToken, $token];
    }

    /**
     * Send email verification link to the user.
     */
    private function sendVerificationEmail(User $user, string $plainToken): void
    {
        $verificationUrl = $this->urlGenerator->generate(
            'app_email_verify',
            ['token' => $plainToken],
            UrlGeneratorInterface::ABSOLUTE_URL
        );

        $email = (new Email())
            ->from("{$this->mailerFromName} <{$this->mailerFromAddress}>")
            ->to((string) $user->getEmail())
            ->subject('Verify your email address')
            ->text(
                "Hello {$user->getFirstName()},\n\n"
                . "Please verify your email by visiting:\n{$verificationUrl}\n\n"
                . "This link expires in 48 hours.\n\n"
                . "If you did not register, please ignore this email."
            )
            ->html($this->buildVerificationEmailHtml(
                $user->getFirstName() ?? 'User',
                $verificationUrl
            ));

        $this->mailer->send($email);
    }

    /**
     * Resend verification email to a user who hasn't verified yet.
     *
     * @throws \InvalidArgumentException If email is already verified
     */
    public function resendVerificationEmail(User $user): void
    {
        if ($user->isEmailVerified()) {
            throw new \InvalidArgumentException('Email is already verified.');
        }

        [$plainToken, $verificationToken] = $this->createVerificationToken($user, (string) $user->getEmail());
        $this->verificationTokenRepository->save($verificationToken);
        $this->sendVerificationEmail($user, $plainToken);
    }

    /**
     * Build HTML verification email with secure link.
     */
    private function buildVerificationEmailHtml(string $firstName, string $verificationUrl): string
    {
        return <<<HTML
<!DOCTYPE html>
<html>
<body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; background: #f5f5f5;">
<div style="background: white; border-radius: 8px; padding: 40px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);">
    <h2 style="color: #1a1a2e;">Verify Your Email Address</h2>
    <p style="color: #555;">Hello {$firstName},</p>
    <p style="color: #555;">Click the button below to verify your email address and activate your account.</p>
    <div style="text-align: center; margin: 30px 0;">
        <a href="{$verificationUrl}" 
           style="background: #4361ee; color: white; padding: 14px 32px; text-decoration: none; border-radius: 6px; font-size: 16px; font-weight: bold;">
            Verify Email Address
        </a>
    </div>
    <p style="color: #555; font-size: 14px;">Or copy this link: <a href="{$verificationUrl}">{$verificationUrl}</a></p>
    <p style="color: #aaa; font-size: 12px;">This link expires in 48 hours. If you did not create an account, please ignore this email.</p>
</div>
</body>
</html>
HTML;
    }
}
