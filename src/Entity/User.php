<?php

declare(strict_types=1);

namespace App\Entity;

use App\Enum\AccountStatus;
use App\Enum\BloodGroup;
use App\Enum\Gender;
use App\Enum\LoginType;
use App\Enum\MaritalStatus;
use App\Repository\UserRepository;
use Doctrine\Common\Collections\ArrayCollection;
use Doctrine\Common\Collections\Collection;
use Doctrine\DBAL\Types\Types;
use Doctrine\ORM\Mapping as ORM;
use Symfony\Bridge\Doctrine\Validator\Constraints\UniqueEntity;
use Symfony\Component\Security\Core\User\PasswordAuthenticatedUserInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Uid\Uuid;
use Symfony\Component\Validator\Constraints as Assert;

/**
 * User Entity — Core user model for authentication and user management.
 *
 * This entity implements both UserInterface (for Symfony Security) and
 * PasswordAuthenticatedUserInterface (for password-based authentication).
 *
 * Security considerations:
 * - UUIDs used as primary keys to prevent enumeration attacks
 * - Passwords stored as Argon2id hashes (never plaintext)
 * - Account locking after configurable failed attempts
 * - Email/mobile verified flags prevent unverified access
 * - Sensitive fields (device_token, refresh_token) excluded from serialization
 *
 * @author Symphony Auth System
 */
#[ORM\Entity(repositoryClass: UserRepository::class)]
#[ORM\Table(
    name: 'users',
    options: ['comment' => 'Core user accounts table']
)]
#[ORM\Index(name: 'idx_user_email', columns: ['email'])]
#[ORM\Index(name: 'idx_user_mobile', columns: ['mobile_number'])]
#[ORM\Index(name: 'idx_user_username', columns: ['username'])]
#[ORM\Index(name: 'idx_user_employee_id', columns: ['employee_id'])]
#[ORM\Index(name: 'idx_user_status', columns: ['account_status'])]
#[ORM\HasLifecycleCallbacks]
#[UniqueEntity(fields: ['email'], message: 'An account with this email already exists.')]
#[UniqueEntity(fields: ['mobileNumber'], message: 'An account with this mobile number already exists.')]
#[UniqueEntity(fields: ['username'], message: 'This username is already taken.')]
class User implements UserInterface, PasswordAuthenticatedUserInterface
{
    // ── Identity ───────────────────────────────────────────────────────────────

    /**
     * Primary key using UUID v7 (time-ordered for better DB performance).
     * UUIDs prevent sequential ID enumeration attacks.
     */
    #[ORM\Id]
    #[ORM\Column(type: 'uuid', unique: true)]
    #[ORM\GeneratedValue(strategy: 'CUSTOM')]
    #[ORM\CustomIdGenerator(class: 'doctrine.uuid_generator')]
    private ?Uuid $id = null;

    /**
     * Employee/Staff identifier (company-assigned, optional).
     */
    #[ORM\Column(length: 50, nullable: true, unique: true)]
    #[Assert\Length(max: 50)]
    private ?string $employeeId = null;

    // ── Personal Information ────────────────────────────────────────────────────

    #[ORM\Column(length: 100)]
    #[Assert\NotBlank]
    #[Assert\Length(min: 1, max: 100)]
    #[Assert\Regex(pattern: '/^[\p{L}\s\-\'\.]+$/u', message: 'First name contains invalid characters.')]
    private ?string $firstName = null;

    #[ORM\Column(length: 100, nullable: true)]
    #[Assert\Length(max: 100)]
    private ?string $middleName = null;

    #[ORM\Column(length: 100)]
    #[Assert\NotBlank]
    #[Assert\Length(min: 1, max: 100)]
    #[Assert\Regex(pattern: '/^[\p{L}\s\-\'\.]+$/u', message: 'Last name contains invalid characters.')]
    private ?string $lastName = null;

    /**
     * Computed full name — denormalized for faster queries/display.
     * Automatically updated via lifecycle callbacks.
     */
    #[ORM\Column(length: 300)]
    private string $fullName = '';

    #[ORM\Column(length: 50, nullable: true, unique: true)]
    #[Assert\Length(min: 3, max: 50)]
    #[Assert\Regex(
        pattern: '/^[a-zA-Z0-9_\-\.]+$/',
        message: 'Username may only contain letters, numbers, underscores, hyphens, and dots.'
    )]
    private ?string $username = null;

    // ── Contact Information ─────────────────────────────────────────────────────

    /**
     * Primary email address — used for authentication and notifications.
     * Always stored in lowercase for consistent lookups.
     */
    #[ORM\Column(length: 254, unique: true)]
    #[Assert\NotBlank]
    #[Assert\Email(mode: 'html5')]
    #[Assert\Length(max: 254)]
    private ?string $email = null;

    /**
     * Primary mobile number in E.164 format (e.g. +14155552671).
     */
    #[ORM\Column(length: 20, nullable: true, unique: true)]
    #[Assert\Length(max: 20)]
    #[Assert\Regex(pattern: '/^\+[1-9]\d{6,14}$/', message: 'Mobile number must be in E.164 format.')]
    private ?string $mobileNumber = null;

    #[ORM\Column(length: 20, nullable: true)]
    #[Assert\Length(max: 20)]
    #[Assert\Regex(pattern: '/^\+[1-9]\d{6,14}$/', message: 'Alternate mobile must be in E.164 format.')]
    private ?string $alternateMobile = null;

    // ── Profile Details ─────────────────────────────────────────────────────────

    #[ORM\Column(length: 500, nullable: true)]
    #[Assert\Url]
    #[Assert\Length(max: 500)]
    private ?string $profilePhoto = null;

    #[ORM\Column(type: Types::STRING, enumType: Gender::class, nullable: true)]
    private ?Gender $gender = null;

    #[ORM\Column(type: Types::DATE_MUTABLE, nullable: true)]
    private ?\DateTimeInterface $dateOfBirth = null;

    #[ORM\Column(type: Types::STRING, enumType: MaritalStatus::class, nullable: true)]
    private ?MaritalStatus $maritalStatus = null;

    #[ORM\Column(type: Types::STRING, enumType: BloodGroup::class, nullable: true)]
    private ?BloodGroup $bloodGroup = null;

    #[ORM\Column(length: 100, nullable: true)]
    #[Assert\Length(max: 100)]
    private ?string $nationality = null;

    /**
     * Preferred languages stored as JSON array (e.g. ["en", "fr", "de"]).
     *
     * @var list<string>
     */
    #[ORM\Column(type: Types::JSON, nullable: true, options: ['jsonb' => true])]
    private array $language = [];

    // ── Security & Authentication ───────────────────────────────────────────────

    /**
     * Argon2id hashed password.
     * NEVER store plaintext passwords. NEVER log this field.
     *
     * @see UserPasswordHasherInterface::hashPassword()
     */
    #[ORM\Column]
    private ?string $passwordHash = null;

    /**
     * User roles — stored as JSON array in PostgreSQL.
     * Always includes ROLE_USER as minimum.
     *
     * @var list<string>
     */
    #[ORM\Column(type: Types::JSON, options: ['jsonb' => true])]
    private array $roles = [];

    /**
     * Granular permissions beyond role-based access.
     *
     * @var array<string, bool>
     */
    #[ORM\Column(type: Types::JSON, nullable: true, options: ['jsonb' => true])]
    private array $permissions = [];

    /**
     * Numeric access level for hierarchical permission checks.
     * Higher numbers = more privileged access.
     */
    #[ORM\Column(options: ['default' => 0])]
    private int $accessLevel = 0;

    #[ORM\Column(type: Types::STRING, enumType: LoginType::class, options: ['default' => 'email'])]
    private LoginType $loginType = LoginType::Email;

    // ── 2FA ────────────────────────────────────────────────────────────────────

    #[ORM\Column(options: ['default' => false])]
    private bool $twoFactorEnabled = false;

    #[ORM\Column(options: ['default' => false])]
    private bool $otpVerified = false;

    #[ORM\Column(length: 32, nullable: true)]
    private ?string $totpSecret = null;

    #[ORM\Column(length: 20, options: ['default' => 'email'])]
    private string $twoFactorType = 'email';

    // ── Verification Status ─────────────────────────────────────────────────────

    #[ORM\Column(options: ['default' => false])]
    private bool $emailVerified = false;

    #[ORM\Column(options: ['default' => false])]
    private bool $mobileVerified = false;

    // ── Login Tracking ──────────────────────────────────────────────────────────

    #[ORM\Column(type: Types::DATETIME_MUTABLE, nullable: true)]
    private ?\DateTimeInterface $lastLogin = null;

    /**
     * Last login IP — stored for security audit purposes.
     * Never use this for blocking without additional verification.
     */
    #[ORM\Column(length: 45, nullable: true)]
    private ?string $lastLoginIp = null;

    /**
     * Counter of consecutive failed login attempts.
     * Reset to 0 on successful login.
     */
    #[ORM\Column(options: ['default' => 0])]
    private int $failedLoginAttempts = 0;

    /**
     * Timestamp when the account was temporarily locked.
     * Null means not locked.
     */
    #[ORM\Column(type: Types::DATETIME_MUTABLE, nullable: true)]
    private ?\DateTimeInterface $lockedUntil = null;

    // ── Account Status ──────────────────────────────────────────────────────────

    #[ORM\Column(type: Types::STRING, enumType: AccountStatus::class, options: ['default' => 'active'])]
    private AccountStatus $accountStatus = AccountStatus::Active;

    /**
     * Force password change flag — set by admin for compromised accounts.
     */
    #[ORM\Column(options: ['default' => false])]
    private bool $forcePasswordChange = false;

    // ── Device & Token Storage ──────────────────────────────────────────────────

    /**
     * Push notification device token.
     * SECURITY: Treat as sensitive — do not log this value.
     */
    #[ORM\Column(length: 500, nullable: true)]
    private ?string $deviceToken = null;

    /**
     * JWT refresh token (hashed).
     * SECURITY: Store only hash, never plaintext token.
     */
    #[ORM\Column(length: 255, nullable: true)]
    private ?string $refreshToken = null;

    // ── Timestamps ──────────────────────────────────────────────────────────────

    #[ORM\Column(type: Types::DATETIME_IMMUTABLE)]
    private ?\DateTimeImmutable $createdAt = null;

    #[ORM\Column(type: Types::DATETIME_IMMUTABLE)]
    private ?\DateTimeImmutable $updatedAt = null;

    #[ORM\Column(type: Types::DATETIME_MUTABLE, nullable: true)]
    private ?\DateTimeInterface $deletedAt = null;

    // ── Relationships ───────────────────────────────────────────────────────────

    /**
     * @var Collection<int, SocialAccount>
     */
    #[ORM\OneToMany(targetEntity: SocialAccount::class, mappedBy: 'user', cascade: ['persist', 'remove'], orphanRemoval: true)]
    private Collection $socialAccounts;

    /**
     * @var Collection<int, LoginHistory>
     */
    #[ORM\OneToMany(targetEntity: LoginHistory::class, mappedBy: 'user', cascade: ['persist', 'remove'])]
    #[ORM\OrderBy(['createdAt' => 'DESC'])]
    private Collection $loginHistories;

    /**
     * @var Collection<int, ActiveSession>
     */
    #[ORM\OneToMany(targetEntity: ActiveSession::class, mappedBy: 'user', cascade: ['persist', 'remove'], orphanRemoval: true)]
    private Collection $activeSessions;

    /**
     * @var Collection<int, EmailOtp>
     */
    #[ORM\OneToMany(targetEntity: EmailOtp::class, mappedBy: 'user', cascade: ['persist', 'remove'], orphanRemoval: true)]
    private Collection $emailOtps;

    public function __construct()
    {
        $this->socialAccounts = new ArrayCollection();
        $this->loginHistories = new ArrayCollection();
        $this->activeSessions = new ArrayCollection();
        $this->emailOtps = new ArrayCollection();
    }

    // ── Lifecycle Callbacks ─────────────────────────────────────────────────────

    /**
     * Initialize timestamps and normalize email on entity creation.
     */
    #[ORM\PrePersist]
    public function onPrePersist(): void
    {
        $this->createdAt = new \DateTimeImmutable();
        $this->updatedAt = new \DateTimeImmutable();
        $this->normalizeEmail();
        $this->computeFullName();
    }

    /**
     * Update the updatedAt timestamp and recompute full name on update.
     */
    #[ORM\PreUpdate]
    public function onPreUpdate(): void
    {
        $this->updatedAt = new \DateTimeImmutable();
        $this->computeFullName();
    }

    /**
     * Normalize email to lowercase for consistent lookups.
     * This prevents duplicate accounts from case-insensitive email providers.
     */
    private function normalizeEmail(): void
    {
        if ($this->email !== null) {
            // Use mb_strtolower for proper Unicode email normalization
            $this->email = mb_strtolower(trim($this->email));
        }
    }

    /**
     * Compute and cache the full name from name parts.
     */
    private function computeFullName(): void
    {
        $parts = array_filter([
            $this->firstName,
            $this->middleName,
            $this->lastName,
        ]);
        $this->fullName = implode(' ', $parts);
    }

    // ── UserInterface Implementation ────────────────────────────────────────────

    /**
     * {@inheritdoc}
     *
     * Returns the identifier used for authentication (email).
     * This is used by Symfony Security to identify the user.
     */
    public function getUserIdentifier(): string
    {
        return (string) $this->email;
    }

    /**
     * {@inheritdoc}
     *
     * Returns the roles assigned to the user.
     * ROLE_USER is always included as a baseline role.
     */
    public function getRoles(): array
    {
        $roles = $this->roles;
        // Guarantee every user has at minimum ROLE_USER
        $roles[] = 'ROLE_USER';

        return array_unique($roles);
    }

    /**
     * {@inheritdoc}
     *
     * Erases any temporary credentials from memory.
     * Called by Symfony Security after authentication.
     * Add plaintext password clearing here if storing temporarily.
     */
    public function eraseCredentials(): void
    {
        // If you store a plaintext password temporarily during registration,
        // clear it here: $this->plainPassword = null;
    }

    /**
     * {@inheritdoc}
     *
     * Returns the hashed password.
     */
    public function getPassword(): ?string
    {
        return $this->passwordHash;
    }

    // ── Security Helpers ────────────────────────────────────────────────────────

    /**
     * Check if the account is currently locked due to brute-force protection.
     */
    public function isLocked(): bool
    {
        if ($this->lockedUntil === null) {
            return false;
        }

        // Check if the lock has expired
        return $this->lockedUntil > new \DateTime();
    }

    /**
     * Check if the account is active and not soft-deleted.
     */
    public function isActive(): bool
    {
        return $this->accountStatus === AccountStatus::Active
            && $this->deletedAt === null;
    }

    /**
     * Increment failed login attempt counter and apply lock if threshold exceeded.
     *
     * @param int $maxAttempts  Maximum allowed attempts before locking
     * @param int $lockMinutes  Duration to lock the account (minutes)
     */
    public function recordFailedLoginAttempt(int $maxAttempts = 5, int $lockMinutes = 30): void
    {
        $this->failedLoginAttempts++;

        if ($this->failedLoginAttempts >= $maxAttempts) {
            // Lock account for the specified duration
            $this->lockedUntil = new \DateTime("+{$lockMinutes} minutes");
        }
    }

    /**
     * Reset failed login counter and remove any active lock.
     * Call this on successful authentication.
     */
    public function resetFailedLoginAttempts(): void
    {
        $this->failedLoginAttempts = 0;
        $this->lockedUntil = null;
    }

    /**
     * Soft-delete the user — preserves audit history.
     */
    public function softDelete(): void
    {
        $this->deletedAt = new \DateTime();
        $this->accountStatus = AccountStatus::Suspended;
    }

    // ── Getters & Setters ───────────────────────────────────────────────────────

    public function getId(): ?Uuid
    {
        return $this->id;
    }

    public function getEmployeeId(): ?string
    {
        return $this->employeeId;
    }

    public function setEmployeeId(?string $employeeId): static
    {
        $this->employeeId = $employeeId;
        return $this;
    }

    public function getFirstName(): ?string
    {
        return $this->firstName;
    }

    public function setFirstName(string $firstName): static
    {
        $this->firstName = trim($firstName);
        return $this;
    }

    public function getMiddleName(): ?string
    {
        return $this->middleName;
    }

    public function setMiddleName(?string $middleName): static
    {
        $this->middleName = $middleName !== null ? trim($middleName) : null;
        return $this;
    }

    public function getLastName(): ?string
    {
        return $this->lastName;
    }

    public function setLastName(string $lastName): static
    {
        $this->lastName = trim($lastName);
        return $this;
    }

    public function getFullName(): string
    {
        return $this->fullName;
    }

    public function getUsername(): ?string
    {
        return $this->username;
    }

    public function setUsername(?string $username): static
    {
        $this->username = $username;
        return $this;
    }

    public function getEmail(): ?string
    {
        return $this->email;
    }

    public function setEmail(string $email): static
    {
        // Normalize to lowercase immediately on assignment
        $this->email = mb_strtolower(trim($email));
        return $this;
    }

    public function getMobileNumber(): ?string
    {
        return $this->mobileNumber;
    }

    public function setMobileNumber(?string $mobileNumber): static
    {
        $this->mobileNumber = $mobileNumber;
        return $this;
    }

    public function getAlternateMobile(): ?string
    {
        return $this->alternateMobile;
    }

    public function setAlternateMobile(?string $alternateMobile): static
    {
        $this->alternateMobile = $alternateMobile;
        return $this;
    }

    public function getProfilePhoto(): ?string
    {
        return $this->profilePhoto;
    }

    public function setProfilePhoto(?string $profilePhoto): static
    {
        $this->profilePhoto = $profilePhoto;
        return $this;
    }

    public function getGender(): ?Gender
    {
        return $this->gender;
    }

    public function setGender(?Gender $gender): static
    {
        $this->gender = $gender;
        return $this;
    }

    public function getDateOfBirth(): ?\DateTimeInterface
    {
        return $this->dateOfBirth;
    }

    public function setDateOfBirth(?\DateTimeInterface $dateOfBirth): static
    {
        $this->dateOfBirth = $dateOfBirth;
        return $this;
    }

    public function getMaritalStatus(): ?MaritalStatus
    {
        return $this->maritalStatus;
    }

    public function setMaritalStatus(?MaritalStatus $maritalStatus): static
    {
        $this->maritalStatus = $maritalStatus;
        return $this;
    }

    public function getBloodGroup(): ?BloodGroup
    {
        return $this->bloodGroup;
    }

    public function setBloodGroup(?BloodGroup $bloodGroup): static
    {
        $this->bloodGroup = $bloodGroup;
        return $this;
    }

    public function getNationality(): ?string
    {
        return $this->nationality;
    }

    public function setNationality(?string $nationality): static
    {
        $this->nationality = $nationality;
        return $this;
    }

    /**
     * @return list<string>
     */
    public function getLanguage(): array
    {
        return $this->language;
    }

    /**
     * @param list<string> $language
     */
    public function setLanguage(array $language): static
    {
        $this->language = $language;
        return $this;
    }

    public function getPasswordHash(): ?string
    {
        return $this->passwordHash;
    }

    public function setPasswordHash(?string $passwordHash): static
    {
        $this->passwordHash = $passwordHash;
        return $this;
    }

    public function setRoles(array $roles): static
    {
        $this->roles = $roles;
        return $this;
    }

    /**
     * @return array<string, bool>
     */
    public function getPermissions(): array
    {
        return $this->permissions;
    }

    /**
     * @param array<string, bool> $permissions
     */
    public function setPermissions(array $permissions): static
    {
        $this->permissions = $permissions;
        return $this;
    }

    public function getAccessLevel(): int
    {
        return $this->accessLevel;
    }

    public function setAccessLevel(int $accessLevel): static
    {
        $this->accessLevel = $accessLevel;
        return $this;
    }

    public function getLoginType(): LoginType
    {
        return $this->loginType;
    }

    public function setLoginType(LoginType $loginType): static
    {
        $this->loginType = $loginType;
        return $this;
    }

    public function isTwoFactorEnabled(): bool
    {
        return $this->twoFactorEnabled;
    }

    public function setTwoFactorEnabled(bool $twoFactorEnabled): static
    {
        $this->twoFactorEnabled = $twoFactorEnabled;
        return $this;
    }

    public function isOtpVerified(): bool
    {
        return $this->otpVerified;
    }

    public function setOtpVerified(bool $otpVerified): static
    {
        $this->otpVerified = $otpVerified;
        return $this;
    }

    public function getTotpSecret(): ?string
    {
        return $this->totpSecret;
    }

    public function setTotpSecret(?string $totpSecret): static
    {
        $this->totpSecret = $totpSecret;
        return $this;
    }

    public function getTwoFactorType(): string
    {
        return $this->twoFactorType;
    }

    public function setTwoFactorType(string $twoFactorType): static
    {
        $this->twoFactorType = $twoFactorType;
        return $this;
    }

    public function isEmailVerified(): bool
    {
        return $this->emailVerified;
    }

    public function setEmailVerified(bool $emailVerified): static
    {
        $this->emailVerified = $emailVerified;
        return $this;
    }

    public function isMobileVerified(): bool
    {
        return $this->mobileVerified;
    }

    public function setMobileVerified(bool $mobileVerified): static
    {
        $this->mobileVerified = $mobileVerified;
        return $this;
    }

    public function getLastLogin(): ?\DateTimeInterface
    {
        return $this->lastLogin;
    }

    public function setLastLogin(?\DateTimeInterface $lastLogin): static
    {
        $this->lastLogin = $lastLogin;
        return $this;
    }

    public function getLastLoginIp(): ?string
    {
        return $this->lastLoginIp;
    }

    public function setLastLoginIp(?string $lastLoginIp): static
    {
        $this->lastLoginIp = $lastLoginIp;
        return $this;
    }

    public function getFailedLoginAttempts(): int
    {
        return $this->failedLoginAttempts;
    }

    public function setFailedLoginAttempts(int $failedLoginAttempts): static
    {
        $this->failedLoginAttempts = $failedLoginAttempts;
        return $this;
    }

    public function getLockedUntil(): ?\DateTimeInterface
    {
        return $this->lockedUntil;
    }

    public function setLockedUntil(?\DateTimeInterface $lockedUntil): static
    {
        $this->lockedUntil = $lockedUntil;
        return $this;
    }

    public function getAccountStatus(): AccountStatus
    {
        return $this->accountStatus;
    }

    public function setAccountStatus(AccountStatus $accountStatus): static
    {
        $this->accountStatus = $accountStatus;
        return $this;
    }

    public function isForcePasswordChange(): bool
    {
        return $this->forcePasswordChange;
    }

    public function setForcePasswordChange(bool $forcePasswordChange): static
    {
        $this->forcePasswordChange = $forcePasswordChange;
        return $this;
    }

    /**
     * Get device token.
     * SECURITY WARNING: Handle with care — treat as sensitive credential.
     */
    public function getDeviceToken(): ?string
    {
        return $this->deviceToken;
    }

    public function setDeviceToken(?string $deviceToken): static
    {
        $this->deviceToken = $deviceToken;
        return $this;
    }

    /**
     * Get hashed refresh token.
     * SECURITY WARNING: Only the hash is stored, never the plaintext token.
     */
    public function getRefreshToken(): ?string
    {
        return $this->refreshToken;
    }

    public function setRefreshToken(?string $refreshToken): static
    {
        $this->refreshToken = $refreshToken;
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

    public function getDeletedAt(): ?\DateTimeInterface
    {
        return $this->deletedAt;
    }

    public function isDeleted(): bool
    {
        return $this->deletedAt !== null;
    }

    /**
     * @return Collection<int, SocialAccount>
     */
    public function getSocialAccounts(): Collection
    {
        return $this->socialAccounts;
    }

    public function addSocialAccount(SocialAccount $socialAccount): static
    {
        if (!$this->socialAccounts->contains($socialAccount)) {
            $this->socialAccounts->add($socialAccount);
            $socialAccount->setUser($this);
        }
        return $this;
    }

    public function removeSocialAccount(SocialAccount $socialAccount): static
    {
        if ($this->socialAccounts->removeElement($socialAccount)) {
            if ($socialAccount->getUser() === $this) {
                $socialAccount->setUser(null);
            }
        }
        return $this;
    }

    /**
     * @return Collection<int, LoginHistory>
     */
    public function getLoginHistories(): Collection
    {
        return $this->loginHistories;
    }

    /**
     * @return Collection<int, ActiveSession>
     */
    public function getActiveSessions(): Collection
    {
        return $this->activeSessions;
    }

    /**
     * @return Collection<int, EmailOtp>
     */
    public function getEmailOtps(): Collection
    {
        return $this->emailOtps;
    }

    /**
     * String representation — use full name for display.
     * SECURITY: Never include sensitive fields here.
     */
    public function __toString(): string
    {
        return $this->getFullName() ?: $this->email ?? 'Unknown User';
    }
}
