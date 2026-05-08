<?php

declare(strict_types=1);

namespace App\Controller\Auth;

use App\Service\Auth\PasswordResetService;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\RateLimiter\RateLimiterFactory;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Validator\Constraints as Assert;
use Symfony\Component\Validator\Validator\ValidatorInterface;

/**
 * PasswordResetController — Handles forgot password and reset flows.
 *
 * Routes:
 * - GET/POST /auth/forgot-password  → Request reset link
 * - GET      /auth/reset-password   → Show new password form (from link)
 * - POST     /auth/reset-password   → Submit new password
 */
#[Route('/auth')]
class PasswordResetController extends AbstractController
{
    public function __construct(
        private readonly PasswordResetService $passwordResetService,
        private readonly RateLimiterFactory $passwordResetLimiter,
        private readonly ValidatorInterface $validator,
    ) {}

    /**
     * Forgot password form — request a password reset link.
     */
    #[Route('/forgot-password', name: 'app_forgot_password', methods: ['GET', 'POST'])]
    public function forgotPassword(Request $request): Response
    {
        if ($request->isMethod('POST')) {
            // CSRF validation
            if (!$this->isCsrfTokenValid('forgot_password', (string) $request->request->get('_csrf_token', ''))) {
                $this->addFlash('error', 'Invalid security token. Please try again.');
                return $this->redirectToRoute('app_forgot_password');
            }

            // Rate limit per IP
            $limiter = $this->passwordResetLimiter->create($request->getClientIp());
            if (!$limiter->consume()->isAccepted()) {
                $this->addFlash('warning', 'Too many requests. Please try again later.');
                return $this->redirectToRoute('app_forgot_password');
            }

            $email = trim((string) $request->request->get('email', ''));

            // Basic email validation
            $violations = $this->validator->validate($email, [
                new Assert\NotBlank(),
                new Assert\Email(),
                new Assert\Length(max: 254),
            ]);

            if (count($violations) > 0) {
                $this->addFlash('error', 'Please enter a valid email address.');
                return $this->render('auth/forgot_password.html.twig', ['email' => $email]);
            }

            // Initiate reset (always shows success, never reveals if email exists)
            $this->passwordResetService->initiateReset($email, $request->getClientIp());

            // SECURITY: Always show success message even for non-existent emails
            $this->addFlash(
                'success',
                'If an account exists with this email, you will receive a password reset link shortly.'
            );

            return $this->redirectToRoute('app_forgot_password');
        }

        return $this->render('auth/forgot_password.html.twig', ['email' => '']);
    }

    /**
     * Show and process the password reset form (from email link).
     */
    #[Route('/reset-password', name: 'app_password_reset', methods: ['GET', 'POST'])]
    public function resetPassword(Request $request): Response
    {
        $token = $request->query->get('token') ?? $request->request->get('token');

        if (!$token) {
            $this->addFlash('error', 'Invalid password reset link.');
            return $this->redirectToRoute('app_forgot_password');
        }

        if ($request->isMethod('POST')) {
            if (!$this->isCsrfTokenValid('reset_password', (string) $request->request->get('_csrf_token', ''))) {
                $this->addFlash('error', 'Invalid security token.');
                return $this->redirectToRoute('app_password_reset', ['token' => $token]);
            }

            $newPassword = (string) $request->request->get('password', '');
            $confirmPassword = (string) $request->request->get('password_confirm', '');

            if ($newPassword !== $confirmPassword) {
                $this->addFlash('error', 'Passwords do not match.');
                return $this->render('auth/reset_password.html.twig', ['token' => $token]);
            }

            // Validate password strength
            $violations = $this->validator->validate($newPassword, [
                new Assert\NotBlank(['message' => 'Password is required.']),
                new \App\Validator\StrongPassword(),
            ]);

            if (count($violations) > 0) {
                foreach ($violations as $violation) {
                    $this->addFlash('error', $violation->getMessage());
                }
                return $this->render('auth/reset_password.html.twig', ['token' => $token]);
            }

            try {
                $this->passwordResetService->resetPassword((string) $token, $newPassword);
                $this->addFlash('success', 'Password reset successfully. Please log in with your new password.');

                return $this->redirectToRoute('app_login');
            } catch (\InvalidArgumentException $e) {
                $this->addFlash('error', $e->getMessage());
                return $this->redirectToRoute('app_forgot_password');
            }
        }

        return $this->render('auth/reset_password.html.twig', ['token' => $token]);
    }
}
