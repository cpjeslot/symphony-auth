<?php

declare(strict_types=1);

namespace App\Entity;

use App\Repository\EmailVerificationTokenRepository;
use Doctrine\DBAL\Types\Types;
use Doctrine\ORM\Mapping as ORM;
use Symfony\Component\Uid\Uuid;

/**
 * EmailVerificationToken Entity — Manages email address verification tokens.
 *
 * Sent after registration or email change to confirm the user controls the address.
 * Security design mirrors PasswordResetToken (hash storage, expiry, single-use).
 */
#[ORM\Entity(repositoryClass: EmailVerificationTokenRepository::class)]
#[ORM\Table(name: 'email_verification_tokens')]
#[ORM\Index(name: 'idx_evt_user', columns: ['user_id'])]
#[ORM\HasLifecycleCallbacks]
class EmailVerificationToken
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
     * SHA-256 hash of the verification token.
     */
    #[ORM\Column(length: 64, unique: true)]
    private string $tokenHash;

    /**
     * The email address being verified.
     * Stored here so we know which address to mark verified on redemption.
     */
    #[ORM\Column(length: 254)]
    private string $email;

    #[ORM\Column(type: Types::DATETIME_IMMUTABLE)]
    private \DateTimeImmutable $expiresAt;

    #[ORM\Column(options: ['default' => false])]
    private bool $isUsed = false;

    #[ORM\Column(type: Types::DATETIME_IMMUTABLE)]
    private ?\DateTimeImmutable $createdAt = null;

    #[ORM\Column(type: Types::DATETIME_MUTABLE, nullable: true)]
    private ?\DateTimeInterface $verifiedAt = null;

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

    public function markAsUsed(): void
    {
        $this->isUsed = true;
        $this->verifiedAt = new \DateTime();
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

    public function getEmail(): string
    {
        return $this->email;
    }

    public function setEmail(string $email): static
    {
        $this->email = $email;
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

    public function getCreatedAt(): ?\DateTimeImmutable
    {
        return $this->createdAt;
    }

    public function getVerifiedAt(): ?\DateTimeInterface
    {
        return $this->verifiedAt;
    }
}
