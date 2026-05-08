<?php

declare(strict_types=1);

namespace App\Entity;

use App\Repository\EmailOtpRepository;
use Doctrine\DBAL\Types\Types;
use Doctrine\ORM\Mapping as ORM;
use Symfony\Component\Uid\Uuid;

/**
 * EmailOtp Entity — Stores secure Email OTP records for 2FA.
 *
 * Security design:
 * - OTP is stored as a hash (bcrypt/argon2id), never plaintext
 * - Each OTP has an expiry time (configurable, default 5 minutes)
 * - Retry counter prevents brute-force OTP guessing
 * - Used flag prevents token reuse after successful verification
 * - Old OTPs are soft-expired to maintain audit trail
 *
 * OTP generation uses cryptographically secure random_int() — NOT rand() or mt_rand().
 */
#[ORM\Entity(repositoryClass: EmailOtpRepository::class)]
#[ORM\Table(name: 'email_otps')]
#[ORM\Index(name: 'idx_otp_user', columns: ['user_id'])]
#[ORM\Index(name: 'idx_otp_expires', columns: ['expires_at'])]
#[ORM\HasLifecycleCallbacks]
class EmailOtp
{
    #[ORM\Id]
    #[ORM\Column(type: 'uuid', unique: true)]
    #[ORM\GeneratedValue(strategy: 'CUSTOM')]
    #[ORM\CustomIdGenerator(class: 'doctrine.uuid_generator')]
    private ?Uuid $id = null;

    #[ORM\ManyToOne(targetEntity: User::class, inversedBy: 'emailOtps')]
    #[ORM\JoinColumn(name: 'user_id', nullable: false, onDelete: 'CASCADE')]
    private ?User $user = null;

    /**
     * Hashed OTP value.
     * SECURITY: Store ONLY the hash — never log or store plaintext OTP.
     * Use password_hash() or Symfony's UserPasswordHasher for consistent hashing.
     */
    #[ORM\Column(length: 255)]
    private string $otpHash;

    /**
     * OTP expiry timestamp.
     * After this time, the OTP is invalid regardless of retry count.
     */
    #[ORM\Column(type: Types::DATETIME_IMMUTABLE)]
    private \DateTimeImmutable $expiresAt;

    /**
     * Number of failed verification attempts for this OTP.
     * When this exceeds the limit, the OTP is invalidated.
     */
    #[ORM\Column(options: ['default' => 0])]
    private int $retryCount = 0;

    /**
     * Maximum allowed retry attempts before OTP is invalidated.
     * Stored here so each OTP can have its own limit if needed.
     */
    #[ORM\Column(options: ['default' => 5])]
    private int $maxRetries = 5;

    /**
     * Whether this OTP has been successfully verified and used.
     * Once true, the OTP cannot be reused (prevents replay attacks).
     */
    #[ORM\Column(options: ['default' => false])]
    private bool $isUsed = false;

    /**
     * Purpose identifier (login_2fa, email_change, etc.).
     * Prevents cross-purpose OTP reuse attacks.
     */
    #[ORM\Column(length: 50, options: ['default' => 'login_2fa'])]
    private string $purpose = 'login_2fa';

    /**
     * IP address of the request that generated this OTP.
     * Used for security audit logging.
     */
    #[ORM\Column(length: 45, nullable: true)]
    private ?string $requestIp = null;

    #[ORM\Column(type: Types::DATETIME_IMMUTABLE)]
    private ?\DateTimeImmutable $createdAt = null;

    #[ORM\PrePersist]
    public function onPrePersist(): void
    {
        $this->createdAt = new \DateTimeImmutable();
    }

    /**
     * Check if this OTP has expired based on the current time.
     */
    public function isExpired(): bool
    {
        return $this->expiresAt <= new \DateTimeImmutable();
    }

    /**
     * Check if this OTP has exceeded its retry limit.
     */
    public function isRetryLimitExceeded(): bool
    {
        return $this->retryCount >= $this->maxRetries;
    }

    /**
     * Check if this OTP is still valid (not expired, not used, not locked).
     */
    public function isValid(): bool
    {
        return !$this->isExpired()
            && !$this->isUsed
            && !$this->isRetryLimitExceeded();
    }

    /**
     * Increment the retry counter on a failed verification attempt.
     */
    public function incrementRetryCount(): void
    {
        $this->retryCount++;
    }

    /**
     * Mark this OTP as used after successful verification.
     */
    public function markAsUsed(): void
    {
        $this->isUsed = true;
    }

    public function getId(): ?Uuid
    {
        return $this->id;
    }

    public function getUser(): ?User
    {
        return $this->user;
    }

    public function setUser(?User $user): static
    {
        $this->user = $user;
        return $this;
    }

    public function getOtpHash(): string
    {
        return $this->otpHash;
    }

    public function setOtpHash(string $otpHash): static
    {
        $this->otpHash = $otpHash;
        return $this;
    }

    public function getExpiresAt(): \DateTimeImmutable
    {
        return $this->expiresAt;
    }

    public function setExpiresAt(\DateTimeImmutable $expiresAt): static
    {
        $this->expiresAt = $expiresAt;
        return $this;
    }

    public function getRetryCount(): int
    {
        return $this->retryCount;
    }

    public function getMaxRetries(): int
    {
        return $this->maxRetries;
    }

    public function setMaxRetries(int $maxRetries): static
    {
        $this->maxRetries = $maxRetries;
        return $this;
    }

    public function isIsUsed(): bool
    {
        return $this->isUsed;
    }

    public function getPurpose(): string
    {
        return $this->purpose;
    }

    public function setPurpose(string $purpose): static
    {
        $this->purpose = $purpose;
        return $this;
    }

    public function getRequestIp(): ?string
    {
        return $this->requestIp;
    }

    public function setRequestIp(?string $requestIp): static
    {
        $this->requestIp = $requestIp;
        return $this;
    }

    public function getCreatedAt(): ?\DateTimeImmutable
    {
        return $this->createdAt;
    }
}
