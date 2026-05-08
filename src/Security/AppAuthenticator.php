<?php

declare(strict_types=1);

namespace App\Security;

use App\Entity\LoginHistory;
use App\Entity\User;
use App\Enum\AccountStatus;
use App\Repository\LoginHistoryRepository;
use App\Repository\UserRepository;
use App\Service\Security\AuditLogService;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use Symfony\Component\Security\Core\Exception\CustomUserMessageAuthenticationException;
use Symfony\Component\Security\Http\Authenticator\AbstractLoginFormAuthenticator;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\CsrfTokenBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\RememberMeBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Credentials\PasswordCredentials;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\SecurityRequestAttributes;
use Symfony\Component\Security\Http\Util\TargetPathTrait;

/**
 * AppAuthenticator — Main form-based login authenticator.
 *
 * Supports login via email OR mobile number.
 *
 * Security features:
 * - CSRF token validation (via CsrfTokenBadge)
 * - Password hashing comparison (via PasswordCredentials — Argon2id)
 * - Account lockout check
 * - Account status check (suspended/banned → deny login)
 * - Email verification gate
 * - Login history recording
 * - Session fixation prevention (Symfony regenerates session ID on authentication)
 * - Remember-me token support
 */
class AppAuthenticator extends AbstractLoginFormAuthenticator
{
    use TargetPathTrait;

    public const LOGIN_ROUTE = 'app_login';

    public function __construct(
        private readonly UserRepository $userRepository,
        private readonly LoginHistoryRepository $loginHistoryRepository,
        private readonly AuditLogService $auditLog,
        private readonly UrlGeneratorInterface $urlGenerator,
    ) {}

    /**
     * {@inheritdoc}
     *
     * Builds the authentication Passport with user lookup and credential verification.
     * Also validates CSRF token and prepares remember-me.
     */
    public function authenticate(Request $request): Passport
    {
        $identifier = trim((string) $request->request->get('_identifier', ''));
        $password = (string) $request->request->get('_password', '');
        $csrfToken = (string) $request->request->get('_csrf_token', '');

        // Store the attempted identifier in session for the login form (repopulate on error)
        $request->getSession()->set(SecurityRequestAttributes::LAST_USERNAME, $identifier);

        return new Passport(
            new UserBadge(
                $identifier,
                function (string $userIdentifier) use ($request): User {
                    // Custom user loader: supports email OR mobile number
                    $user = $this->userRepository->findByEmailOrMobile($userIdentifier);

                    if ($user === null) {
                        // SECURITY: Do not reveal whether the identifier exists
                        throw new CustomUserMessageAuthenticationException(
                            'Invalid credentials. Please check your email/mobile and password.'
                        );
                    }

                    // Check if account is locked due to failed attempts
                    if ($user->isLocked()) {
                        $lockUntil = $user->getLockedUntil();
                        $this->recordFailedAttempt($request, $user, $userIdentifier, 'account_locked');
                        throw new CustomUserMessageAuthenticationException(
                            sprintf(
                                'Your account is temporarily locked due to multiple failed login attempts. '
                                . 'Please try again after %s.',
                                $lockUntil?->format('H:i') ?? 'a while'
                            )
                        );
                    }

                    // Check account status
                    if (!$user->isActive()) {
                        $this->recordFailedAttempt($request, $user, $userIdentifier, 'account_inactive');

                        $message = match ($user->getAccountStatus()) {
                            AccountStatus::Suspended => 'Your account has been suspended. Please contact support.',
                            AccountStatus::Banned => 'Your account has been permanently disabled.',
                            AccountStatus::PendingVerification => 'Please verify your email address before logging in.',
                            AccountStatus::Deactivated => 'Your account has been deactivated.',
                            default => 'Your account is not active.',
                        };

                        throw new CustomUserMessageAuthenticationException($message);
                    }

                    return $user;
                }
            ),
            new PasswordCredentials($password),
            [
                // CSRF token validation — prevents cross-site request forgery
                new CsrfTokenBadge('authenticate', $csrfToken),
                // Enable remember-me if user checked the box
                new RememberMeBadge(),
            ]
        );
    }

    /**
     * {@inheritdoc}
     *
     * Called on successful authentication.
     * Records login success, updates last login info, redirects user.
     */
    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): ?Response
    {
        /** @var User $user */
        $user = $token->getUser();

        // Reset failed login counter
        $user->resetFailedLoginAttempts();
        $user->setLastLogin(new \DateTime());
        $user->setLastLoginIp($request->getClientIp());
        $this->userRepository->save($user);

        // Record successful login in history
        $this->recordLoginHistory($request, $user, true);

        // Audit log
        $this->auditLog->logLoginSuccess($user);

        // If 2FA is enabled, redirect to OTP verification
        if ($user->isTwoFactorEnabled()) {
            // Store the user ID in session for the 2FA step
            $request->getSession()->set('2fa_user_id', $user->getId()?->toString());
            $request->getSession()->set('2fa_pending', true);
            $request->getSession()->remove(SecurityRequestAttributes::LAST_USERNAME);

            return new RedirectResponse($this->urlGenerator->generate('app_2fa'));
        }

        // Check if force password change is required
        if ($user->isForcePasswordChange()) {
            return new RedirectResponse($this->urlGenerator->generate('app_profile_change_password'));
        }

        // Redirect to the original target path (or default)
        $targetPath = $this->getTargetPath($request->getSession(), $firewallName);
        if ($targetPath !== null) {
            return new RedirectResponse($targetPath);
        }

        return new RedirectResponse($this->urlGenerator->generate('app_profile'));
    }

    /**
     * {@inheritdoc}
     *
     * Called on authentication failure.
     * Records failed attempt, updates failed count, applies lockout.
     */
    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): Response
    {
        $identifier = trim((string) $request->request->get('_identifier', ''));

        // Try to find the user to update failed attempts
        $user = $this->userRepository->findByEmailOrMobile($identifier);

        if ($user !== null && !($exception instanceof CustomUserMessageAuthenticationException)) {
            // Increment failed login counter and potentially lock the account
            $user->recordFailedLoginAttempt(
                maxAttempts: 5,     // TODO: inject from env
                lockMinutes: 30
            );
            $this->userRepository->save($user);

            if ($user->isLocked()) {
                $this->auditLog->logAccountLocked($user, $user->getFailedLoginAttempts());
            }
        }

        $this->recordLoginHistory($request, $user, false, $exception->getMessage());
        $this->auditLog->logLoginFailure(
            $user,
            $identifier,
            $exception->getMessage()
        );

        // Store error message for display
        $request->getSession()->set(SecurityRequestAttributes::AUTHENTICATION_ERROR, $exception);

        return new RedirectResponse($this->urlGenerator->generate(self::LOGIN_ROUTE));
    }

    /**
     * {@inheritdoc}
     */
    protected function getLoginUrl(Request $request): string
    {
        return $this->urlGenerator->generate(self::LOGIN_ROUTE);
    }

    /**
     * Record a login attempt in the login_histories table.
     */
    private function recordLoginHistory(
        Request $request,
        ?User $user,
        bool $success,
        ?string $failureReason = null,
    ): void {
        $history = new LoginHistory();
        $history->setUser($user);
        $history->setIsSuccessful($success);
        $history->setIpAddress($request->getClientIp());
        $history->setUserAgent($request->headers->get('User-Agent'));
        $history->setAuthMethod('email_password');
        $history->setLoginIdentifier(
            trim((string) $request->request->get('_identifier', ''))
        );

        if (!$success && $failureReason !== null) {
            $history->setFailureReason(substr($failureReason, 0, 100));
        }

        $this->loginHistoryRepository->save($history);
    }

    /**
     * Record a failed attempt from within the user loader (before password check).
     */
    private function recordFailedAttempt(
        Request $request,
        User $user,
        string $identifier,
        string $reason,
    ): void {
        $history = new LoginHistory();
        $history->setUser($user);
        $history->setIsSuccessful(false);
        $history->setIpAddress($request->getClientIp());
        $history->setUserAgent($request->headers->get('User-Agent'));
        $history->setAuthMethod('email_password');
        $history->setLoginIdentifier($identifier);
        $history->setFailureReason($reason);

        $this->loginHistoryRepository->save($history);
    }
}
