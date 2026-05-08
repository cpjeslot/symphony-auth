<?php

declare(strict_types=1);

namespace App\Security;

use App\Entity\User;
use App\Repository\UserRepository;
use App\Service\Otp\OtpService;
use App\Service\Security\TotpService;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\CustomUserMessageAuthenticationException;
use Symfony\Component\Security\Http\Authenticator\AbstractAuthenticator;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;
use Symfony\Component\Security\Http\SecurityRequestAttributes;

/**
 * TwoFactorAuthenticator — Handles Email OTP verification as second authentication factor.
 *
 * This authenticator fires ONLY on the 2FA verification route (app_2fa_verify).
 * It reads the pending user from the session (set by AppAuthenticator on successful
 * password verification) and verifies the submitted OTP.
 *
 * Flow:
 * 1. AppAuthenticator succeeds → stores user ID in session with '2fa_pending' flag
 * 2. User is redirected to 2FA page
 * 3. User submits OTP → this authenticator verifies it
 * 4. On success: clears 2FA session markers, completes login
 * 5. On failure: increments OTP retry count, shows error
 */
class TwoFactorAuthenticator extends AbstractAuthenticator
{
    public function __construct(
        private readonly UserRepository $userRepository,
        private readonly OtpService $otpService,
        private readonly TotpService $totpService,
        private readonly UrlGeneratorInterface $urlGenerator,
    ) {}

    /**
     * {@inheritdoc}
     *
     * Only supports POST requests to the 2FA verification endpoint.
     */
    public function supports(Request $request): ?bool
    {
        return $request->isMethod('POST')
            && $request->attributes->get('_route') === 'app_2fa_verify';
    }

    /**
     * {@inheritdoc}
     */
    public function authenticate(Request $request): Passport
    {
        $session = $request->getSession();

        // Verify that we have a pending 2FA session (set by AppAuthenticator)
        if (!$session->get('2fa_pending', false)) {
            throw new CustomUserMessageAuthenticationException(
                'No pending 2FA verification session found. Please log in again.'
            );
        }

        $userId = $session->get('2fa_user_id');

        if (!$userId) {
            throw new CustomUserMessageAuthenticationException('Invalid 2FA session. Please log in again.');
        }

        // Find the user
        $user = $this->userRepository->find($userId);

        if (!$user instanceof User) {
            throw new CustomUserMessageAuthenticationException('User not found. Please log in again.');
        }

        // Get the submitted OTP from the form
        $submittedOtp = trim((string) $request->request->get('otp', ''));

        if (empty($submittedOtp)) {
            throw new CustomUserMessageAuthenticationException('Please enter the verification code.');
        }

        // Verify the code based on the user's preferred method
        $isValid = false;
        if ($user->getTwoFactorType() === 'totp') {
            $secret = $user->getTotpSecret();
            if ($secret) {
                $isValid = $this->totpService->verifyCode($secret, $submittedOtp);
            }
        } else {
            // Default to Email OTP
            $isValid = $this->otpService->verifyOtp($user, $submittedOtp, 'login_2fa');
        }

        if (!$isValid) {
            throw new CustomUserMessageAuthenticationException(
                'Invalid or expired verification code. Please try again.'
            );
        }

        // OTP is valid — create a self-validating passport (no password check needed)
        return new SelfValidatingPassport(
            new UserBadge($user->getUserIdentifier(), fn () => $user)
        );
    }

    /**
     * {@inheritdoc}
     *
     * Clear 2FA session markers and redirect to profile on success.
     */
    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): ?Response
    {
        $session = $request->getSession();

        // Clear 2FA session markers
        $session->remove('2fa_pending');
        $session->remove('2fa_user_id');

        /** @var User $user */
        $user = $token->getUser();
        $user->setOtpVerified(true);
        $this->userRepository->save($user);

        return new RedirectResponse($this->urlGenerator->generate('app_profile'));
    }

    /**
     * {@inheritdoc}
     *
     * Store error and redirect back to 2FA page.
     */
    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): Response
    {
        $request->getSession()->set(SecurityRequestAttributes::AUTHENTICATION_ERROR, $exception);

        return new RedirectResponse($this->urlGenerator->generate('app_2fa'));
    }
}
