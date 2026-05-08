<?php

declare(strict_types=1);

namespace App\Admin;

use App\Controller\Admin\ActiveSessionCrudController;
use App\Controller\Admin\EmailOtpCrudController;
use App\Controller\Admin\EmailVerificationTokenCrudController;
use App\Controller\Admin\LoginHistoryCrudController;
use App\Controller\Admin\PasswordResetTokenCrudController;
use App\Controller\Admin\SecurityAuditLogCrudController;
use App\Controller\Admin\SocialAccountCrudController;
use App\Controller\Admin\UserCrudController;
use App\Entity\ActiveSession;
use App\Entity\EmailOtp;
use App\Entity\EmailVerificationToken;
use App\Entity\LoginHistory;
use App\Entity\PasswordResetToken;
use App\Entity\SecurityAuditLog;
use App\Entity\SocialAccount;
use App\Entity\User;
use App\Repository\SecurityAuditLogRepository;
use App\Repository\UserRepository;
use Doctrine\ORM\EntityManagerInterface;
use EasyCorp\Bundle\EasyAdminBundle\Attribute\AdminDashboard;
use EasyCorp\Bundle\EasyAdminBundle\Config\Dashboard;
use EasyCorp\Bundle\EasyAdminBundle\Config\MenuItem;
use EasyCorp\Bundle\EasyAdminBundle\Controller\AbstractDashboardController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Security\Http\Attribute\IsGranted;

#[IsGranted('ROLE_ADMIN')]
#[AdminDashboard(routePath: '/admin', routeName: 'admin')]
class DashboardController extends AbstractDashboardController
{
    public function __construct(
        private readonly UserRepository $userRepository,
        private readonly SecurityAuditLogRepository $auditLogRepository,
        private readonly EntityManagerInterface $entityManager,
    ) {}

    #[Route('/admin', name: 'admin')]
    public function index(): Response
    {
        // Gather dashboard metrics
        $totalUsers = $this->userRepository->count([]);
        $activeUsers = $this->userRepository->count(['accountStatus' => 'active']);
        $recentAlerts = $this->auditLogRepository->countHighSeverityRecentEvents(24);
        
        $totalSocialAccounts = $this->entityManager->getRepository(SocialAccount::class)->count([]);
        $activeSessions = $this->entityManager->getRepository(ActiveSession::class)->count(['isRevoked' => false]);
        
        $recentEvents = $this->auditLogRepository->findBy([], ['createdAt' => 'DESC'], 5);

        return $this->render('admin/dashboard.html.twig', [
            'total_users' => $totalUsers,
            'active_users' => $activeUsers,
            'recent_alerts' => $recentAlerts,
            'total_social_accounts' => $totalSocialAccounts,
            'active_sessions' => $activeSessions,
            'recent_events' => $recentEvents,
        ]);
    }

    public function configureDashboard(): Dashboard
    {
        return Dashboard::new()
            ->setTitle('<i class="fa fa-shield-halved me-2"></i> Auth System Admin')
            ->setFaviconPath('favicon.ico')
            ->renderContentMaximized();
    }

    public function configureMenuItems(): iterable
    {
        yield MenuItem::linkToDashboard('Dashboard', 'fa fa-home');
        
        yield MenuItem::section('User Management');
        yield MenuItem::linkTo(UserCrudController::class, 'Users', 'fa fa-users');
        yield MenuItem::linkTo(SocialAccountCrudController::class, 'Social Accounts', 'fa fa-share-nodes');
        yield MenuItem::linkTo(ActiveSessionCrudController::class, 'Active Sessions', 'fa fa-clock');

        yield MenuItem::section('Security & Logs');
        yield MenuItem::linkTo(SecurityAuditLogCrudController::class, 'Audit Logs', 'fa fa-shield-halved');
        yield MenuItem::linkTo(LoginHistoryCrudController::class, 'Login History', 'fa fa-history');

        yield MenuItem::section('Verification & Recovery');
        yield MenuItem::linkTo(EmailOtpCrudController::class, 'Email OTPs', 'fa fa-key');
        yield MenuItem::linkTo(EmailVerificationTokenCrudController::class, 'Verification Tokens', 'fa fa-envelope-circle-check');
        yield MenuItem::linkTo(PasswordResetTokenCrudController::class, 'Password Reset Tokens', 'fa fa-rotate-left');

        yield MenuItem::section('System');
        yield MenuItem::linkToRoute('← Back to Site', 'fa fa-arrow-left', 'app_profile');
    }
}
