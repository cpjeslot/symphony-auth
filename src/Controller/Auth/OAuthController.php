<?php

declare(strict_types=1);

namespace App\Controller\Auth;

use App\Enum\OAuthProvider;
use App\Service\Social\OAuthService;
use KnpU\OAuth2ClientBundle\Client\ClientRegistry;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Security\Http\Authentication\UserAuthenticatorInterface;

/**
 * OAuthController — Handles OAuth2 social login flows.
 *
 * Routes:
 * - GET /auth/oauth/{provider}          → Redirect to provider's OAuth2 authorization URL
 * - GET /auth/oauth/{provider}/callback → Handle provider callback
 *
 * Supported providers: google, github, facebook, apple
 *
 * Security:
 * - State parameter validated by KnpU OAuth2 client (CSRF for OAuth)
 * - PKCE enabled for Google (configured in knpu_oauth2_client.yaml)
 * - Provider user ID used as primary identifier (not email) to prevent account takeover
 */
#[Route('/auth/oauth')]
class OAuthController extends AbstractController
{
    public function __construct(
        private readonly ClientRegistry $clientRegistry,
        private readonly OAuthService $oauthService,
        private readonly UserAuthenticatorInterface $userAuthenticator,
        private readonly \App\Security\AppAuthenticator $appAuthenticator,
    ) {}

    /**
     * Redirect user to OAuth2 provider's authorization page.
     */
    #[Route('/{provider}', name: 'oauth_connect', methods: ['GET'])]
    public function connect(string $provider): Response
    {
        $supportedProviders = ['google', 'github', 'facebook', 'apple'];

        if (!in_array($provider, $supportedProviders, true)) {
            $this->addFlash('error', 'Unsupported OAuth provider.');
            return $this->redirectToRoute('app_login');
        }

        // Validate provider enum
        $providerEnum = OAuthProvider::tryFrom($provider);

        if ($providerEnum === null) {
            return $this->redirectToRoute('app_login');
        }

        return $this->clientRegistry
            ->getClient($provider)
            ->redirect(
                $this->getProviderScopes($providerEnum),
                []
            );
    }

    /**
     * Handle the OAuth2 provider callback.
     * This route receives the authorization code and exchanges it for a user profile.
     */
    #[Route('/google/callback', name: 'oauth_google_callback', methods: ['GET'])]
    public function googleCallback(Request $request): Response
    {
        return $this->handleCallback('google', OAuthProvider::Google, $request);
    }

    #[Route('/github/callback', name: 'oauth_github_callback', methods: ['GET'])]
    public function githubCallback(Request $request): Response
    {
        return $this->handleCallback('github', OAuthProvider::GitHub, $request);
    }

    #[Route('/facebook/callback', name: 'oauth_facebook_callback', methods: ['GET'])]
    public function facebookCallback(Request $request): Response
    {
        return $this->handleCallback('facebook', OAuthProvider::Facebook, $request);
    }

    #[Route('/apple/callback', name: 'oauth_apple_callback', methods: ['GET', 'POST'])]
    public function appleCallback(Request $request): Response
    {
        return $this->handleCallback('apple', OAuthProvider::Apple, $request);
    }

    /**
     * Common callback handler for all OAuth2 providers.
     */
    private function handleCallback(string $clientName, OAuthProvider $provider, Request $request): Response
    {
        try {
            $client = $this->clientRegistry->getClient($clientName);

            // Check for error from provider (user denied access, etc.)
            if ($request->query->has('error')) {
                $this->addFlash('error', 'Social login was cancelled or denied.');
                return $this->redirectToRoute('app_login');
            }

            // Exchange authorization code for access token and user info
            $resourceOwner = $client->fetchUser();

            // Create or link user account
            $user = $this->oauthService->handleOAuthLogin(
                $provider,
                $resourceOwner,
                $request->getClientIp()
            );

            // Authenticate the user via Symfony's security system
            return $this->userAuthenticator->authenticateUser(
                $user,
                $this->appAuthenticator,
                $request
            ) ?? $this->redirectToRoute('app_profile');
        } catch (\Throwable $e) {
            $this->addFlash('error', 'Social login failed. Please try again or use email login.');

            return $this->redirectToRoute('app_login');
        }
    }

    /**
     * Get the OAuth2 scopes required for each provider.
     *
     * @return list<string>
     */
    private function getProviderScopes(OAuthProvider $provider): array
    {
        return match ($provider) {
            OAuthProvider::Google => ['openid', 'profile', 'email'],
            OAuthProvider::GitHub => ['user:email', 'read:user'],
            OAuthProvider::Facebook => ['email', 'public_profile'],
            OAuthProvider::Apple => ['name', 'email'],
        };
    }
}
