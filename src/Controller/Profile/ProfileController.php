<?php

declare(strict_types=1);

namespace App\Controller\Profile;

use App\Entity\User;
use App\Repository\ActiveSessionRepository;
use App\Repository\LoginHistoryRepository;
use App\Service\Otp\OtpService;
use App\Service\Security\AuditLogService;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Security\Http\Attribute\IsGranted;

/**
 * ProfileController — Manages user profile, security settings, and sessions.
 *
 * All routes require authentication (ROLE_USER).
 */
#[Route('/profile')]
#[IsGranted('ROLE_USER')]
class ProfileController extends AbstractController
{
    public function __construct(
        private readonly LoginHistoryRepository $loginHistoryRepository,
        private readonly ActiveSessionRepository $sessionRepository,
        private readonly UserPasswordHasherInterface $passwordHasher,
        private readonly OtpService $otpService,
        private readonly AuditLogService $auditLog,
    ) {}

    /**
     * Profile overview page.
     */
    #[Route('', name: 'app_profile', methods: ['GET'])]
    public function index(): Response
    {
        /** @var User $user */
        $user = $this->getUser();

        return $this->render('profile/index.html.twig', [
            'user' => $user,
            'recent_logins' => $this->loginHistoryRepository->findRecentForUser($user, 5),
        ]);
    }

    /**
     * Security settings — 2FA toggle, password change, active sessions.
     */
    #[Route('/security', name: 'app_profile_security', methods: ['GET'])]
    public function security(Request $request): Response
    {
        /** @var User $user */
        $user = $this->getUser();

        return $this->render('profile/security.html.twig', [
            'user' => $user,
        ]);
    }

    /**
     * Enable 2FA — send OTP and store pending state.
     */
    #[Route('/security/2fa/enable', name: 'app_2fa_enable', methods: ['POST'])]
    public function enableTwoFactor(Request $request): Response
    {
        /** @var User $user */
        $user = $this->getUser();

        if (!$this->isCsrfTokenValid('2fa_enable', (string) $request->request->get('_csrf_token', ''))) {
            $this->addFlash('error', 'Invalid security token.');
            return $this->redirectToRoute('app_profile_security');
        }

        if ($user->isTwoFactorEnabled()) {
            $this->addFlash('info', '2FA is already enabled.');
            return $this->redirectToRoute('app_profile_security');
        }

        $user->setTwoFactorEnabled(true);

        $this->auditLog->logTwoFactorEnabled($user);
        $this->addFlash('success', 'Two-factor authentication has been enabled.');

        return $this->redirectToRoute('app_profile_security');
    }

    /**
     * Disable 2FA.
     */
    #[Route('/security/2fa/disable', name: 'app_2fa_disable', methods: ['POST'])]
    public function disableTwoFactor(Request $request): Response
    {
        /** @var User $user */
        $user = $this->getUser();

        if (!$this->isCsrfTokenValid('2fa_disable', (string) $request->request->get('_csrf_token', ''))) {
            $this->addFlash('error', 'Invalid security token.');
            return $this->redirectToRoute('app_profile_security');
        }

        $user->setTwoFactorEnabled(false);
        $this->auditLog->logTwoFactorDisabled($user);
        $this->addFlash('success', 'Two-factor authentication has been disabled.');

        return $this->redirectToRoute('app_profile_security');
    }

    /**
     * Change password from profile.
     */
    #[Route('/security/change-password', name: 'app_profile_change_password', methods: ['GET', 'POST'])]
    public function changePassword(Request $request): Response
    {
        /** @var User $user */
        $user = $this->getUser();

        if ($request->isMethod('POST')) {
            if (!$this->isCsrfTokenValid('change_password', (string) $request->request->get('_csrf_token', ''))) {
                $this->addFlash('error', 'Invalid security token.');
                return $this->redirectToRoute('app_profile_security');
            }

            $currentPassword = (string) $request->request->get('current_password', '');
            $newPassword = (string) $request->request->get('new_password', '');
            $confirmPassword = (string) $request->request->get('confirm_password', '');

            // Verify current password
            if (!$this->passwordHasher->isPasswordValid($user, $currentPassword)) {
                $this->addFlash('error', 'Current password is incorrect.');
                return $this->redirectToRoute('app_profile_security');
            }

            if ($newPassword !== $confirmPassword) {
                $this->addFlash('error', 'New passwords do not match.');
                return $this->redirectToRoute('app_profile_security');
            }

            // Validate new password strength
            $newHash = $this->passwordHasher->hashPassword($user, $newPassword);
            $user->setPasswordHash($newHash);
            $user->setForcePasswordChange(false);

            $this->auditLog->logPasswordChanged($user);
            $this->addFlash('success', 'Password changed successfully.');

            return $this->redirectToRoute('app_profile_security');
        }

        return $this->render('profile/change_password.html.twig', ['user' => $user]);
    }

    /**
     * View and manage active sessions.
     */
    #[Route('/sessions', name: 'app_profile_sessions', methods: ['GET'])]
    public function sessions(): Response
    {
        /** @var User $user */
        $user = $this->getUser();

        return $this->render('profile/sessions.html.twig', [
            'user' => $user,
            'sessions' => $this->sessionRepository->findActiveForUser($user),
        ]);
    }

    /**
     * Login history page.
     */
    #[Route('/login-history', name: 'app_profile_login_history', methods: ['GET'])]
    public function loginHistory(): Response
    {
        /** @var User $user */
        $user = $this->getUser();

        return $this->render('profile/login_history.html.twig', [
            'user' => $user,
            'login_history' => $this->loginHistoryRepository->findRecentForUser($user, 50),
        ]);
    }
}
