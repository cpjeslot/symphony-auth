<?php

declare(strict_types=1);

namespace App\Entity;

use App\Repository\ActiveSessionRepository;
use Doctrine\DBAL\Types\Types;
use Doctrine\ORM\Mapping as ORM;
use Symfony\Component\Uid\Uuid;

/**
 * ActiveSession Entity — Tracks active user sessions.
 *
 * Allows users to view and revoke their own sessions (session management UI).
 * Allows admins to terminate any session.
 *
 * Session token is stored as a hash to prevent session hijacking via DB theft.
 */
#[ORM\Entity(repositoryClass: ActiveSessionRepository::class)]
#[ORM\Table(name: 'active_sessions')]
#[ORM\Index(name: 'idx_as_user', columns: ['user_id'])]
#[ORM\Index(name: 'idx_as_expires', columns: ['expires_at'])]
#[ORM\HasLifecycleCallbacks]
class ActiveSession
{
    #[ORM\Id]
    #[ORM\Column(type: 'uuid', unique: true)]
    #[ORM\GeneratedValue(strategy: 'CUSTOM')]
    #[ORM\CustomIdGenerator(class: 'doctrine.uuid_generator')]
    private ?Uuid $id = null;

    #[ORM\ManyToOne(targetEntity: User::class, inversedBy: 'activeSessions')]
    #[ORM\JoinColumn(nullable: false, onDelete: 'CASCADE')]
    private ?User $user = null;

    /**
     * SHA-256 hash of the session ID.
     * Never store the raw session ID — hash for security.
     */
    #[ORM\Column(length: 64, unique: true)]
    private string $sessionTokenHash;

    #[ORM\Column(length: 45, nullable: true)]
    private ?string $ipAddress = null;

    #[ORM\Column(length: 500, nullable: true)]
    private ?string $userAgent = null;

    /**
     * Human-friendly device description (e.g., "Chrome on Windows").
     * Derived from user-agent parsing.
     */
    #[ORM\Column(length: 200, nullable: true)]
    private ?string $deviceDescription = null;

    #[ORM\Column(type: Types::DATETIME_IMMUTABLE)]
    private \DateTimeImmutable $expiresAt;

    /**
     * Last activity timestamp — updated on each request.
     */
    #[ORM\Column(type: Types::DATETIME_MUTABLE)]
    private \DateTime $lastActivityAt;

    /**
     * Whether this session has been manually revoked.
     */
    #[ORM\Column(options: ['default' => false])]
    private bool $isRevoked = false;

    #[ORM\Column(type: Types::DATETIME_IMMUTABLE)]
    private ?\DateTimeImmutable $createdAt = null;

    #[ORM\PrePersist]
    public function onPrePersist(): void
    {
        $this->createdAt = new \DateTimeImmutable();
        $this->lastActivityAt = new \DateTime();
    }

    public function isExpired(): bool
    {
        return $this->expiresAt <= new \DateTimeImmutable();
    }

    public function isActive(): bool
    {
        return !$this->isRevoked && !$this->isExpired();
    }

    public function revoke(): void
    {
        $this->isRevoked = true;
    }

    public function updateLastActivity(): void
    {
        $this->lastActivityAt = new \DateTime();
    }

    public function getId(): ?Uuid { return $this->id; }

    public function getUser(): ?User { return $this->user; }

    public function setUser(?User $user): static
    {
        $this->user = $user;
        return $this;
    }

    public function getSessionTokenHash(): string { return $this->sessionTokenHash; }

    public function setSessionTokenHash(string $sessionTokenHash): static
    {
        $this->sessionTokenHash = $sessionTokenHash;
        return $this;
    }

    public function getIpAddress(): ?string { return $this->ipAddress; }

    public function setIpAddress(?string $ipAddress): static
    {
        $this->ipAddress = $ipAddress;
        return $this;
    }

    public function getUserAgent(): ?string { return $this->userAgent; }

    public function setUserAgent(?string $userAgent): static
    {
        $this->userAgent = $userAgent !== null ? mb_substr($userAgent, 0, 500) : null;
        return $this;
    }

    public function getDeviceDescription(): ?string { return $this->deviceDescription; }

    public function setDeviceDescription(?string $deviceDescription): static
    {
        $this->deviceDescription = $deviceDescription;
        return $this;
    }

    public function getExpiresAt(): \DateTimeImmutable { return $this->expiresAt; }

    public function setExpiresAt(\DateTimeImmutable $expiresAt): static
    {
        $this->expiresAt = $expiresAt;
        return $this;
    }

    public function getLastActivityAt(): \DateTime { return $this->lastActivityAt; }

    public function isRevoked(): bool { return $this->isRevoked; }

    public function getCreatedAt(): ?\DateTimeImmutable { return $this->createdAt; }
}
