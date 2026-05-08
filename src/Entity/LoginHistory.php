<?php

declare(strict_types=1);

namespace App\Entity;

use App\Repository\LoginHistoryRepository;
use Doctrine\DBAL\Types\Types;
use Doctrine\ORM\Mapping as ORM;
use Symfony\Component\Uid\Uuid;

/**
 * LoginHistory Entity — Immutable audit log of all login attempts.
 *
 * Records both successful and failed login attempts for security monitoring.
 * This entity is write-once (no updates) to maintain audit integrity.
 *
 * Security note: No lifecycle PreUpdate callback here intentionally —
 * audit records must be immutable once written.
 */
#[ORM\Entity(repositoryClass: LoginHistoryRepository::class)]
#[ORM\Table(
    name: 'login_histories',
    options: ['comment' => 'Immutable audit log of login attempts']
)]
#[ORM\Index(name: 'idx_lh_user', columns: ['user_id'])]
#[ORM\Index(name: 'idx_lh_created', columns: ['created_at'])]
#[ORM\Index(name: 'idx_lh_success', columns: ['is_successful'])]
#[ORM\HasLifecycleCallbacks]
class LoginHistory
{
    #[ORM\Id]
    #[ORM\Column(type: 'uuid', unique: true)]
    #[ORM\GeneratedValue(strategy: 'CUSTOM')]
    #[ORM\CustomIdGenerator(class: 'doctrine.uuid_generator')]
    private ?Uuid $id = null;

    /**
     * User associated with this login attempt.
     * Nullable because login may fail before user is identified.
     */
    #[ORM\ManyToOne(targetEntity: User::class, inversedBy: 'loginHistories')]
    #[ORM\JoinColumn(nullable: true, onDelete: 'SET NULL')]
    private ?User $user = null;

    /**
     * The identifier used in the login attempt (email or mobile).
     * Stored for audit purposes even if user not found.
     * SECURITY: This may contain an email address — handle per privacy policy.
     */
    #[ORM\Column(length: 254, nullable: true)]
    private ?string $loginIdentifier = null;

    #[ORM\Column(options: ['default' => false])]
    private bool $isSuccessful;

    /**
     * Reason for failure (invalid_password, account_locked, etc.).
     */
    #[ORM\Column(length: 100, nullable: true)]
    private ?string $failureReason = null;

    /**
     * Client IP address.
     * IPv4 max = 15 chars, IPv6 max = 45 chars.
     */
    #[ORM\Column(length: 45, nullable: true)]
    private ?string $ipAddress = null;

    /**
     * User-Agent string — truncated to 500 chars to prevent DB abuse.
     */
    #[ORM\Column(length: 500, nullable: true)]
    private ?string $userAgent = null;

    /**
     * Authentication method used (email, mobile, google, github, etc.).
     */
    #[ORM\Column(length: 50, nullable: true)]
    private ?string $authMethod = null;

    /**
     * Session ID created on successful login.
     * Allows correlating login with session activity.
     */
    #[ORM\Column(length: 128, nullable: true)]
    private ?string $sessionId = null;

    /**
     * Whether 2FA was required and completed for this login.
     */
    #[ORM\Column(options: ['default' => false])]
    private bool $twoFactorCompleted = false;

    /**
     * Country derived from IP (optional — requires IP geolocation service).
     */
    #[ORM\Column(length: 100, nullable: true)]
    private ?string $country = null;

    #[ORM\Column(type: Types::DATETIME_IMMUTABLE)]
    private ?\DateTimeImmutable $createdAt = null;

    #[ORM\PrePersist]
    public function onPrePersist(): void
    {
        $this->createdAt = new \DateTimeImmutable();
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

    public function getLoginIdentifier(): ?string
    {
        return $this->loginIdentifier;
    }

    public function setLoginIdentifier(?string $loginIdentifier): static
    {
        $this->loginIdentifier = $loginIdentifier;
        return $this;
    }

    public function isSuccessful(): bool
    {
        return $this->isSuccessful;
    }

    public function setIsSuccessful(bool $isSuccessful): static
    {
        $this->isSuccessful = $isSuccessful;
        return $this;
    }

    public function getFailureReason(): ?string
    {
        return $this->failureReason;
    }

    public function setFailureReason(?string $failureReason): static
    {
        $this->failureReason = $failureReason;
        return $this;
    }

    public function getIpAddress(): ?string
    {
        return $this->ipAddress;
    }

    public function setIpAddress(?string $ipAddress): static
    {
        $this->ipAddress = $ipAddress;
        return $this;
    }

    public function getUserAgent(): ?string
    {
        return $this->userAgent;
    }

    public function setUserAgent(?string $userAgent): static
    {
        // Truncate to prevent abuse of long user-agent strings
        $this->userAgent = $userAgent !== null ? mb_substr($userAgent, 0, 500) : null;
        return $this;
    }

    public function getAuthMethod(): ?string
    {
        return $this->authMethod;
    }

    public function setAuthMethod(?string $authMethod): static
    {
        $this->authMethod = $authMethod;
        return $this;
    }

    public function getSessionId(): ?string
    {
        return $this->sessionId;
    }

    public function setSessionId(?string $sessionId): static
    {
        $this->sessionId = $sessionId;
        return $this;
    }

    public function isTwoFactorCompleted(): bool
    {
        return $this->twoFactorCompleted;
    }

    public function setTwoFactorCompleted(bool $twoFactorCompleted): static
    {
        $this->twoFactorCompleted = $twoFactorCompleted;
        return $this;
    }

    public function getCountry(): ?string
    {
        return $this->country;
    }

    public function setCountry(?string $country): static
    {
        $this->country = $country;
        return $this;
    }

    public function getCreatedAt(): ?\DateTimeImmutable
    {
        return $this->createdAt;
    }
}
