<?php

declare(strict_types=1);

namespace App\Controller\Auth;

use App\Service\Auth\EmailVerificationService;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

/**
 * EmailVerificationController — Handles email address verification.
 */
class EmailVerificationController extends AbstractController
{
    public function __construct(
        private readonly EmailVerificationService $verificationService,
    ) {}

    /**
     * Verify an email address using the token from the verification link.
     * GET /auth/verify-email?token=...
     */
    #[Route('/auth/verify-email', name: 'app_email_verify', methods: ['GET'])]
    public function verify(Request $request): Response
    {
        $token = (string) $request->query->get('token', '');

        if (empty($token)) {
            $this->addFlash('error', 'Invalid verification link.');
            return $this->redirectToRoute('app_login');
        }

        $success = $this->verificationService->verifyEmail($token);

        if ($success) {
            $this->addFlash('success', 'Email verified successfully! You can now log in.');
        } else {
            // SECURITY: Generic message — don't reveal if token is invalid vs expired
            $this->addFlash(
                'error',
                'This verification link is invalid or has expired. Please request a new verification email.'
            );
        }

        return $this->redirectToRoute('app_login');
    }
}
