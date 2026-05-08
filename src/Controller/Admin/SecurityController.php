<?php

declare(strict_types=1);

namespace App\Controller\Admin;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Security\Http\Authentication\AuthenticationUtils;

/**
 * SecurityController — Handles authentication for the Admin panel.
 */
class SecurityController extends AbstractController
{
    /**
     * Admin login page.
     */
    #[Route('/admin/login', name: 'security_admin_login')]
    public function login(AuthenticationUtils $authenticationUtils): Response
    {
        if ($this->getUser()) {
            return $this->redirectToRoute('admin');
        }

        $error = $authenticationUtils->getLastAuthenticationError();
        $lastUsername = $authenticationUtils->getLastUsername();

        return $this->render('admin/security/login.html.twig', [
            'last_username' => $lastUsername,
            'error' => $error,
            'csrf_token_intention' => 'authenticate',
        ]);
    }

    /**
     * Admin logout.
     */
    #[Route('/admin/logout', name: 'admin_logout')]
    public function logout(): void
    {
        throw new \LogicException('This method can be blank - it will be intercepted by the logout key on your firewall.');
    }
}
