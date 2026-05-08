<?php

declare(strict_types=1);

namespace App\Admin;

use App\Entity\LoginHistory;
use App\Entity\SecurityAuditLog;
use App\Entity\User;
use App\Repository\SecurityAuditLogRepository;
use App\Repository\UserRepository;
use EasyCorp\Bundle\EasyAdminBundle\Attribute\AdminDashboard;
use EasyCorp\Bundle\EasyAdminBundle\Config\Action;
use EasyCorp\Bundle\EasyAdminBundle\Config\Dashboard;
use EasyCorp\Bundle\EasyAdminBundle\Config\MenuItem;
use EasyCorp\Bundle\EasyAdminBundle\Controller\AbstractDashboardController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Security\Http\Attribute\IsGranted;

/**
 * AdminDashboardController — EasyAdmin dashboard for system administration.
 *
 * Provides:
 * - Overview dashboard with key metrics
 * - User management
 * - Security audit log viewer
 * - Login history viewer
 *
 * Access restricted to ROLE_ADMIN.
 */
#[IsGranted('ROLE_ADMIN')]
#[AdminDashboard(routePath: '/admin', routeName: 'admin')]
class DashboardController extends AbstractDashboardController
{
    public function __construct(
        private readonly UserRepository $userRepository,
        private readonly SecurityAuditLogRepository $auditLogRepository,
    ) {}

    #[Route('/admin', name: 'easyadmin')]
    public function index(): Response
    {
        // Gather dashboard metrics
        $totalUsers = count($this->userRepository->createActiveUsersQueryBuilder()->getQuery()->getResult());
        $recentAlerts = $this->auditLogRepository->countHighSeverityRecentEvents(24);

        return $this->render('admin/dashboard.html.twig', [
            'total_users' => $totalUsers,
            'recent_alerts' => $recentAlerts,
        ]);
    }

    public function configureDashboard(): Dashboard
    {
        return Dashboard::new()
            ->setTitle('<img src="/images/logo.svg" alt="Auth Admin"> Auth System')
            ->setFaviconPath('favicon.ico')
            ->setTranslationDomain('admin')
            ->renderContentMaximized();
    }

    public function configureMenuItems(): iterable
    {
        yield MenuItem::linkToDashboard('Dashboard', 'fa fa-home');
        yield MenuItem::section('User Management');
        yield MenuItem::linkTo(UserCrudController::class, 'Users', 'fa bi-users')->setAction(Action::INDEX);
        yield MenuItem::section('Security');
        yield MenuItem::linkTo(SecurityAuditLogCrudController::class, 'Security Audit Logs', 'fa bi-shield-halved')->setAction(Action::INDEX);
        yield MenuItem::linkTo(LoginHistoryCrudController::class, 'Login History', 'fa bi-history')->setAction(Action::INDEX);
        yield MenuItem::section('');
        yield MenuItem::linkToRoute('← Back to Site', 'fa bi-arrow-left', 'app_profile');
    }
}
