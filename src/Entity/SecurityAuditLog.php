<?php

declare(strict_types=1);

namespace App\Entity;

use App\Enum\AuditEventType;
use App\Repository\SecurityAuditLogRepository;
use Doctrine\DBAL\Types\Types;
use Doctrine\ORM\Mapping as ORM;
use Symfony\Component\Uid\Uuid;

/**
 * SecurityAuditLog Entity — Immutable record of all security-relevant events.
 *
 * This is the central audit trail for the application. All significant security
 * events (logins, logouts, 2FA, password changes, admin actions) are recorded here.
 *
 * Design decisions:
 * - Immutable: no PreUpdate callback, no update methods
 * - Soft-deleted users still appear in logs (user_id nullable)
 * - Partitioned by month in production (via PostgreSQL table partitioning)
 * - Extra context stored as JSONB for flexible querying
 *
 * SECURITY: This table must be append-only. Application accounts should NOT
 * have DELETE privileges on this table in production PostgreSQL setup.
 */
#[ORM\Entity(repositoryClass: SecurityAuditLogRepository::class)]
#[ORM\Table(
    name: 'security_audit_logs',
    options: ['comment' => 'Immutable security event audit log']
)]
#[ORM\Index(name: 'idx_sal_user', columns: ['user_id'])]
#[ORM\Index(name: 'idx_sal_event', columns: ['event_type'])]
#[ORM\Index(name: 'idx_sal_created', columns: ['created_at'])]
#[ORM\Index(name: 'idx_sal_ip', columns: ['ip_address'])]
#[ORM\HasLifecycleCallbacks]
class SecurityAuditLog
{
    #[ORM\Id]
    #[ORM\Column(type: 'uuid', unique: true)]
    #[ORM\GeneratedValue(strategy: 'CUSTOM')]
    #[ORM\CustomIdGenerator(class: 'doctrine.uuid_generator')]
    private ?Uuid $id = null;

    /**
     * The user associated with this event (nullable for pre-authentication events).
     */
    #[ORM\ManyToOne(targetEntity: User::class)]
    #[ORM\JoinColumn(nullable: true, onDelete: 'SET NULL')]
    private ?User $user = null;

    /**
     * Standardized event type identifier.
     */
    #[ORM\Column(type: Types::STRING, enumType: AuditEventType::class)]
    private AuditEventType $eventType;

    /**
     * Human-readable description of what happened.
     */
    #[ORM\Column(type: Types::TEXT, nullable: true)]
    private ?string $description = null;

    /**
     * IP address of the request.
     */
    #[ORM\Column(length: 45, nullable: true)]
    private ?string $ipAddress = null;

    /**
     * User-Agent string (truncated).
     */
    #[ORM\Column(length: 500, nullable: true)]
    private ?string $userAgent = null;

    /**
     * Event severity (info, warning, error).
     * Derived from event type but stored for efficient querying.
     */
    #[ORM\Column(length: 20, options: ['default' => 'info'])]
    private string $severity = 'info';

    /**
     * Additional context data as JSONB.
     * Examples: {'failed_attempts': 3}, {'provider': 'google'}, {'role_changed_to': 'ROLE_ADMIN'}
     * SECURITY: Do NOT store passwords, tokens, or full PII here.
     *
     * @var array<string, mixed>
     */
    #[ORM\Column(type: Types::JSON, nullable: true, options: ['jsonb' => true])]
    private array $context = [];

    /**
     * Entity type affected by this event (User, Session, OTP, etc.).
     */
    #[ORM\Column(length: 100, nullable: true)]
    private ?string $entityType = null;

    /**
     * UUID of the affected entity.
     */
    #[ORM\Column(length: 36, nullable: true)]
    private ?string $entityId = null;

    #[ORM\Column(type: Types::DATETIME_IMMUTABLE)]
    private ?\DateTimeImmutable $createdAt = null;

    #[ORM\PrePersist]
    public function onPrePersist(): void
    {
        $this->createdAt = new \DateTimeImmutable();
        // Auto-set severity from event type
        $this->severity = $this->eventType->severity();
    }

    public function getId(): ?Uuid { return $this->id; }

    public function getUser(): ?User { return $this->user; }

    public function setUser(?User $user): static
    {
        $this->user = $user;
        return $this;
    }

    public function getEventType(): AuditEventType { return $this->eventType; }

    public function setEventType(AuditEventType $eventType): static
    {
        $this->eventType = $eventType;
        return $this;
    }

    public function getDescription(): ?string { return $this->description; }

    public function setDescription(?string $description): static
    {
        $this->description = $description;
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

    public function getSeverity(): string { return $this->severity; }

    /** @return array<string, mixed> */
    public function getContext(): array { return $this->context; }

    /** @param array<string, mixed> $context */
    public function setContext(array $context): static
    {
        $this->context = $context;
        return $this;
    }

    public function getEntityType(): ?string { return $this->entityType; }

    public function setEntityType(?string $entityType): static
    {
        $this->entityType = $entityType;
        return $this;
    }

    public function getEntityId(): ?string { return $this->entityId; }

    public function setEntityId(?string $entityId): static
    {
        $this->entityId = $entityId;
        return $this;
    }

    public function getCreatedAt(): ?\DateTimeImmutable { return $this->createdAt; }
}
