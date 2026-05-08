<?php

declare(strict_types=1);

namespace App\Entity;

use App\Repository\PasswordResetTokenRepository;
use Doctrine\DBAL\Types\Types;
use Doctrine\ORM\Mapping as ORM;
use Symfony\Component\Uid\Uuid;

/**
 * PasswordResetToken Entity — Manages secure password reset tokens.
 *
 * Security design:
 * - Token is stored as a hash (SHA-256) to prevent database theft attacks
 * - Tokens expire after a configurable time (default 2 hours)
 * - Tokens are single-use (marked as used after redemption)
 * - Enumeration attack prevention: same response for valid/invalid emails
 * - Token is URL-safe base64-encoded random bytes (32 bytes = 256-bit entropy)
 */
#[ORM\Entity(repositoryClass: PasswordResetTokenRepository::class)]
#[ORM\Table(name: 'password_reset_tokens')]
#[ORM\Index(name: 'idx_prt_user', columns: ['user_id'])]
#[ORM\Index(name: 'idx_prt_expires', columns: ['expires_at'])]
#[ORM\HasLifecycleCallbacks]
class PasswordResetToken
{
    #[ORM\Id]
    #[ORM\Column(type: 'uuid', unique: true)]
    #[ORM\GeneratedValue(strategy: 'CUSTOM')]
    #[ORM\CustomIdGenerator(class: 'doctrine.uuid_generator')]
    private ?Uuid $id = null;

    #[ORM\ManyToOne(targetEntity: User::class)]
    #[ORM\JoinColumn(nullable: false, onDelete: 'CASCADE')]
    private ?User $user = null;

    /**
     * SHA-256 hash of the reset token.
     * The original token is sent via email and never stored here.
     * On redemption: hash the received token and compare to this value.
     */
    #[ORM\Column(length: 64, unique: true)]
    private string $tokenHash;

    /**
     * Token expiry timestamp.
     */
    #[ORM\Column(type: Types::DATETIME_IMMUTABLE)]
    private \DateTimeImmutable $expiresAt;

    /**
     * Whether this token has been used for a password reset.
     * Prevents token replay attacks.
     */
    #[ORM\Column(options: ['default' => false])]
    private bool $isUsed = false;

    /**
     * IP address that requested the password reset.
     */
    #[ORM\Column(length: 45, nullable: true)]
    private ?string $requestIp = null;

    #[ORM\Column(type: Types::DATETIME_IMMUTABLE)]
    private ?\DateTimeImmutable $createdAt = null;

    #[ORM\Column(type: Types::DATETIME_MUTABLE, nullable: true)]
    private ?\DateTimeInterface $usedAt = null;

    #[ORM\PrePersist]
    public function onPrePersist(): void
    {
        $this->createdAt = new \DateTimeImmutable();
    }

    public function isExpired(): bool
    {
        return $this->expiresAt <= new \DateTimeImmutable();
    }

    public function isValid(): bool
    {
        return !$this->isExpired() && !$this->isUsed;
    }

    /**
     * Mark the token as used (irreversible).
     */
    public function markAsUsed(): void
    {
        $this->isUsed = true;
        $this->usedAt = new \DateTime();
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

    public function getTokenHash(): string
    {
        return $this->tokenHash;
    }

    public function setTokenHash(string $tokenHash): static
    {
        $this->tokenHash = $tokenHash;
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

    public function isIsUsed(): bool
    {
        return $this->isUsed;
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

    public function getUsedAt(): ?\DateTimeInterface
    {
        return $this->usedAt;
    }
}
