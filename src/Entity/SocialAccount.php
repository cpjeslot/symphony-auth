<?php

declare(strict_types=1);

namespace App\Entity;

use App\Enum\OAuthProvider;
use App\Repository\SocialAccountRepository;
use Doctrine\DBAL\Types\Types;
use Doctrine\ORM\Mapping as ORM;
use Symfony\Component\Uid\Uuid;

/**
 * SocialAccount Entity — Links a user account to OAuth2 providers.
 *
 * Each record represents a connection between a user and a social login provider.
 * Multiple providers can be linked to a single user account.
 *
 * Security considerations:
 * - provider_user_id is stored to prevent duplicate account creation
 * - access_token stored encrypted (or omitted if not needed post-login)
 * - raw provider metadata stored for debugging/compliance (JSON)
 */
#[ORM\Entity(repositoryClass: SocialAccountRepository::class)]
#[ORM\Table(name: 'social_accounts')]
#[ORM\UniqueConstraint(name: 'uq_provider_user', columns: ['provider', 'provider_user_id'])]
#[ORM\Index(name: 'idx_social_user', columns: ['user_id'])]
#[ORM\HasLifecycleCallbacks]
class SocialAccount
{
    #[ORM\Id]
    #[ORM\Column(type: 'uuid', unique: true)]
    #[ORM\GeneratedValue(strategy: 'CUSTOM')]
    #[ORM\CustomIdGenerator(class: 'doctrine.uuid_generator')]
    private ?Uuid $id = null;

    #[ORM\ManyToOne(targetEntity: User::class, inversedBy: 'socialAccounts')]
    #[ORM\JoinColumn(name: 'user_id', referencedColumnName: 'id', nullable: false, onDelete: 'CASCADE')]
    private ?User $user = null;

    /**
     * OAuth2 provider name (google, github, facebook, apple).
     */
    #[ORM\Column(type: Types::STRING, enumType: OAuthProvider::class)]
    private OAuthProvider $provider;

    /**
     * Unique user identifier from the OAuth2 provider.
     * Used to prevent duplicate account creation on subsequent logins.
     */
    #[ORM\Column(length: 255)]
    private string $providerUserId;

    /**
     * Email address from the provider (may differ from app email).
     */
    #[ORM\Column(length: 254, nullable: true)]
    private ?string $providerEmail = null;

    /**
     * Display name from the provider.
     */
    #[ORM\Column(length: 255, nullable: true)]
    private ?string $providerName = null;

    /**
     * Profile avatar URL from the provider.
     */
    #[ORM\Column(length: 500, nullable: true)]
    private ?string $providerAvatar = null;

    /**
     * OAuth2 access token (short-lived).
     * SECURITY: Only store if required for API calls on behalf of user.
     * Consider encrypting if stored long-term.
     */
    #[ORM\Column(type: Types::TEXT, nullable: true)]
    private ?string $accessToken = null;

    /**
     * OAuth2 refresh token.
     * SECURITY: Treat as sensitive credential — encrypt if storing.
     */
    #[ORM\Column(type: Types::TEXT, nullable: true)]
    private ?string $refreshToken = null;

    /**
     * Access token expiry timestamp.
     */
    #[ORM\Column(type: Types::DATETIME_MUTABLE, nullable: true)]
    private ?\DateTimeInterface $tokenExpiresAt = null;

    /**
     * Raw provider metadata (JSON) — for compliance and debugging.
     * SECURITY: May contain PII — handle per GDPR/privacy policy.
     *
     * @var array<string, mixed>
     */
    #[ORM\Column(type: Types::JSON, nullable: true, options: ['jsonb' => true])]
    private array $providerMetadata = [];

    #[ORM\Column(type: Types::DATETIME_IMMUTABLE)]
    private ?\DateTimeImmutable $createdAt = null;

    #[ORM\Column(type: Types::DATETIME_IMMUTABLE)]
    private ?\DateTimeImmutable $updatedAt = null;

    #[ORM\PrePersist]
    public function onPrePersist(): void
    {
        $this->createdAt = new \DateTimeImmutable();
        $this->updatedAt = new \DateTimeImmutable();
    }

    #[ORM\PreUpdate]
    public function onPreUpdate(): void
    {
        $this->updatedAt = new \DateTimeImmutable();
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

    public function getProvider(): OAuthProvider
    {
        return $this->provider;
    }

    public function setProvider(OAuthProvider $provider): static
    {
        $this->provider = $provider;
        return $this;
    }

    public function getProviderUserId(): string
    {
        return $this->providerUserId;
    }

    public function setProviderUserId(string $providerUserId): static
    {
        $this->providerUserId = $providerUserId;
        return $this;
    }

    public function getProviderEmail(): ?string
    {
        return $this->providerEmail;
    }

    public function setProviderEmail(?string $providerEmail): static
    {
        $this->providerEmail = $providerEmail;
        return $this;
    }

    public function getProviderName(): ?string
    {
        return $this->providerName;
    }

    public function setProviderName(?string $providerName): static
    {
        $this->providerName = $providerName;
        return $this;
    }

    public function getProviderAvatar(): ?string
    {
        return $this->providerAvatar;
    }

    public function setProviderAvatar(?string $providerAvatar): static
    {
        $this->providerAvatar = $providerAvatar;
        return $this;
    }

    public function getAccessToken(): ?string
    {
        return $this->accessToken;
    }

    public function setAccessToken(?string $accessToken): static
    {
        $this->accessToken = $accessToken;
        return $this;
    }

    public function getRefreshToken(): ?string
    {
        return $this->refreshToken;
    }

    public function setRefreshToken(?string $refreshToken): static
    {
        $this->refreshToken = $refreshToken;
        return $this;
    }

    public function getTokenExpiresAt(): ?\DateTimeInterface
    {
        return $this->tokenExpiresAt;
    }

    public function setTokenExpiresAt(?\DateTimeInterface $tokenExpiresAt): static
    {
        $this->tokenExpiresAt = $tokenExpiresAt;
        return $this;
    }

    /**
     * @return array<string, mixed>
     */
    public function getProviderMetadata(): array
    {
        return $this->providerMetadata;
    }

    /**
     * @param array<string, mixed> $providerMetadata
     */
    public function setProviderMetadata(array $providerMetadata): static
    {
        $this->providerMetadata = $providerMetadata;
        return $this;
    }

    public function getCreatedAt(): ?\DateTimeImmutable
    {
        return $this->createdAt;
    }

    public function getUpdatedAt(): ?\DateTimeImmutable
    {
        return $this->updatedAt;
    }
}
