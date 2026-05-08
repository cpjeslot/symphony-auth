<?php

declare(strict_types=1);

namespace App\Controller\Auth;

use App\Entity\User;
use App\Service\Otp\OtpService;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Security\Http\SecurityRequestAttributes;

/**
 * TwoFactorController — Manages the Email OTP 2FA verification step.
 *
 * Routes:
 * - GET  /auth/2fa         → Show OTP input form
 * - POST /auth/2fa/verify  → Verify OTP (handled by TwoFactorAuthenticator)
 * - POST /auth/2fa/resend  → Resend OTP with cooldown
 */
#[Route('/auth')]
class TwoFactorController extends AbstractController
{
    public function __construct(
        private readonly OtpService $otpService,
    ) {}

    /**
     * Display the 2FA OTP input form.
     * If no pending 2FA session exists, redirect to login.
     */
    #[Route('/2fa', name: 'app_2fa', methods: ['GET', 'POST'])]
    public function twoFactor(Request $request): Response
    {
        $session = $request->getSession();

        // Guard: must have a pending 2FA session
        if (!$session->get('2fa_pending', false)) {
            return $this->redirectToRoute('app_login');
        }

        // Get any authentication error (from TwoFactorAuthenticator failure)
        $error = $request->getSession()->get(SecurityRequestAttributes::AUTHENTICATION_ERROR);
        $request->getSession()->remove(SecurityRequestAttributes::AUTHENTICATION_ERROR);

        return $this->render('auth/two_factor.html.twig', [
            'error' => $error,
        ]);
    }

    /**
     * Resend an OTP to the user's email with cooldown enforcement.
     * POST /auth/2fa/resend
     */
    #[Route('/2fa/resend', name: 'app_2fa_resend', methods: ['POST'])]
    public function resendOtp(Request $request): Response
    {
        $session = $request->getSession();

        if (!$session->get('2fa_pending', false)) {
            return $this->redirectToRoute('app_login');
        }

        // CSRF check for the resend form
        if (!$this->isCsrfTokenValid('2fa_resend', (string) $request->request->get('_csrf_token', ''))) {
            $this->addFlash('error', 'Invalid security token. Please try again.');
            return $this->redirectToRoute('app_2fa');
        }

        $userId = $session->get('2fa_user_id');

        // Retrieve user
        $user = $this->getUser();

        if ($user instanceof User) {
            $canResend = $this->otpService->canResendOtp($user);

            if (!$canResend['allowed']) {
                $this->addFlash(
                    'warning',
                    sprintf(
                        'Please wait %d seconds before requesting a new code.',
                        $canResend['wait_seconds']
                    )
                );
                return $this->redirectToRoute('app_2fa');
            }

            $this->otpService->generateAndSendOtp(
                $user,
                'login_2fa',
                $request->getClientIp()
            );

            $this->addFlash('success', 'A new verification code has been sent to your email.');
        }

        return $this->redirectToRoute('app_2fa');
    }

    /**
     * This route is the POST target for TwoFactorAuthenticator.
     * The controller method itself is only a placeholder — the authenticator
     * intercepts the request before reaching this method.
     */
    #[Route('/2fa/verify', name: 'app_2fa_verify', methods: ['POST'])]
    public function verify(): Response
    {
        // Handled by TwoFactorAuthenticator
        return $this->redirectToRoute('app_2fa');
    }
}
