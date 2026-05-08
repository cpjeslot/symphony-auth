<?php

declare(strict_types=1);

namespace App\Service\Social;

use App\Entity\SocialAccount;
use App\Entity\User;
use App\Enum\AccountStatus;
use App\Enum\AuditEventType;
use App\Enum\LoginType;
use App\Enum\OAuthProvider;
use App\Repository\SocialAccountRepository;
use App\Repository\UserRepository;
use App\Service\Security\AuditLogService;
use Doctrine\ORM\EntityManagerInterface;
use KnpU\OAuth2ClientBundle\Client\ClientRegistry;
use League\OAuth2\Client\Provider\ResourceOwnerInterface;
use Psr\Log\LoggerInterface;

/**
 * OAuthService — Handles OAuth2 social login account linking and creation.
 *
 * Flow for social login:
 * 1. Provider returns user info after authorization
 * 2. Look up existing social account by provider + provider_user_id
 * 3a. If found: return the linked user (login)
 * 3b. If not found, look up user by provider email
 *    - If email matches existing user: link the new provider, return user
 *    - If no user found: create new user account, link social account
 * 4. Audit log the event
 *
 * Security considerations:
 * - Provider email is used for linking only after first social login
 * - Provider email trust: assume providers validate their users' emails
 * - Revoked access: if provider returns error, handle gracefully
 */
class OAuthService
{
    public function __construct(
        private readonly SocialAccountRepository $socialAccountRepository,
        private readonly UserRepository $userRepository,
        private readonly EntityManagerInterface $entityManager,
        private readonly AuditLogService $auditLog,
        private readonly LoggerInterface $logger,
    ) {}

    /**
     * Process an OAuth2 login/registration flow.
     *
     * @param OAuthProvider           $provider     The OAuth provider
     * @param ResourceOwnerInterface  $resourceOwner The provider's user info
     *
     * @return User The authenticated or newly created user
     */
    public function handleOAuthLogin(
        OAuthProvider $provider,
        ResourceOwnerInterface $resourceOwner,
        ?string $ipAddress = null,
    ): User {
        $providerData = $this->extractProviderData($provider, $resourceOwner);

        $this->logger->info('OAuth login attempt', [
            'provider' => $provider->value,
            'provider_user_id' => $providerData['id'],
        ]);

        return $this->entityManager->wrapInTransaction(
            function () use ($provider, $providerData, $resourceOwner, $ipAddress): User {
                // Step 1: Look up by provider ID (most specific match)
                $existingSocialAccount = $this->socialAccountRepository->findByProviderAndId(
                    $provider,
                    $providerData['id']
                );

                if ($existingSocialAccount !== null) {
                    // Update tokens on re-login
                    $this->updateSocialAccountTokens($existingSocialAccount, $resourceOwner);
                    $user = $existingSocialAccount->getUser();
                    $this->auditLog->logSocialLogin($user, $provider->value);

                    return $user;
                }

                // Step 2: Look up by email to link existing account
                $user = null;
                if (!empty($providerData['email'])) {
                    $user = $this->userRepository->findByEmail($providerData['email']);
                }

                if ($user !== null) {
                    // Link new social provider to existing account
                    $socialAccount = $this->createSocialAccount($provider, $providerData, $user, $resourceOwner);
                    $this->entityManager->persist($socialAccount);

                    $this->auditLog->log(
                        AuditEventType::SocialAccountLinked,
                        $user,
                        "Linked {$provider->value} to existing account",
                        ['provider' => $provider->value]
                    );
                } else {
                    // Step 3: Create new user account
                    $user = $this->createUserFromProvider($provider, $providerData);
                    $this->entityManager->persist($user);

                    $socialAccount = $this->createSocialAccount($provider, $providerData, $user, $resourceOwner);
                    $this->entityManager->persist($socialAccount);

                    $this->auditLog->log(
                        AuditEventType::UserRegistered,
                        $user,
                        "Account created via {$provider->value} OAuth",
                        ['provider' => $provider->value]
                    );
                }

                $this->entityManager->flush();
                $this->auditLog->logSocialLogin($user, $provider->value);

                return $user;
            }
        );
    }

    /**
     * Create a new User entity from OAuth provider data.
     */
    private function createUserFromProvider(OAuthProvider $provider, array $providerData): User
    {
        $user = new User();
        $user->setEmail($providerData['email'] ?? "{$providerData['id']}@{$provider->value}.oauth");
        $user->setFirstName($providerData['firstName'] ?? 'User');
        $user->setLastName($providerData['lastName'] ?? $provider->label());
        $user->setProfilePhoto($providerData['avatar'] ?? null);
        $user->setRoles(['ROLE_USER']);
        $user->setLoginType(LoginType::Sso);
        $user->setEmailVerified(!empty($providerData['email'])); // Trust provider email
        $user->setAccountStatus(AccountStatus::Active);

        // OAuth users have no password — generate a random un-guessable hash
        // SECURITY: This hash will never match any real password attempt
        $user->setPasswordHash(password_hash(bin2hex(random_bytes(32)), PASSWORD_ARGON2ID));

        return $user;
    }

    /**
     * Create a SocialAccount entity linking user to OAuth provider.
     */
    private function createSocialAccount(
        OAuthProvider $provider,
        array $providerData,
        User $user,
        ResourceOwnerInterface $resourceOwner,
    ): SocialAccount {
        $socialAccount = new SocialAccount();
        $socialAccount->setUser($user);
        $socialAccount->setProvider($provider);
        $socialAccount->setProviderUserId($providerData['id']);
        $socialAccount->setProviderEmail($providerData['email'] ?? null);
        $socialAccount->setProviderName($providerData['name'] ?? null);
        $socialAccount->setProviderAvatar($providerData['avatar'] ?? null);
        $socialAccount->setProviderMetadata($resourceOwner->toArray());

        return $socialAccount;
    }

    /**
     * Update OAuth tokens on re-login.
     */
    private function updateSocialAccountTokens(
        SocialAccount $socialAccount,
        ResourceOwnerInterface $resourceOwner,
    ): void {
        $socialAccount->setProviderMetadata($resourceOwner->toArray());
        $this->entityManager->persist($socialAccount);
    }

    /**
     * Extract normalized data from any OAuth provider's resource owner.
     *
     * @return array{id: string, email: ?string, name: ?string, firstName: ?string, lastName: ?string, avatar: ?string}
     */
    private function extractProviderData(OAuthProvider $provider, ResourceOwnerInterface $resourceOwner): array
    {
        $raw = $resourceOwner->toArray();

        return match ($provider) {
            OAuthProvider::Google => [
                'id' => (string) $resourceOwner->getId(),
                'email' => $raw['email'] ?? null,
                'name' => $raw['name'] ?? null,
                'firstName' => $raw['given_name'] ?? null,
                'lastName' => $raw['family_name'] ?? null,
                'avatar' => $raw['picture'] ?? null,
            ],
            OAuthProvider::GitHub => [
                'id' => (string) $resourceOwner->getId(),
                'email' => $raw['email'] ?? null,
                'name' => $raw['name'] ?? $raw['login'] ?? null,
                'firstName' => $raw['name'] ?? $raw['login'] ?? null,
                'lastName' => '',
                'avatar' => $raw['avatar_url'] ?? null,
            ],
            OAuthProvider::Facebook => [
                'id' => (string) $resourceOwner->getId(),
                'email' => $raw['email'] ?? null,
                'name' => $raw['name'] ?? null,
                'firstName' => $raw['first_name'] ?? null,
                'lastName' => $raw['last_name'] ?? null,
                'avatar' => isset($raw['picture']['data']['url']) ? $raw['picture']['data']['url'] : null,
            ],
            OAuthProvider::Apple => [
                'id' => (string) $resourceOwner->getId(),
                'email' => $raw['email'] ?? null,
                'name' => null,
                'firstName' => $raw['firstName'] ?? null,
                'lastName' => $raw['lastName'] ?? null,
                'avatar' => null,
            ],
        };
    }
}
