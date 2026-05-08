<?php

declare(strict_types=1);

namespace App\Controller\Auth;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Security\Http\Authentication\AuthenticationUtils;

/**
 * LoginController — Manages the login and logout routes.
 *
 * The actual authentication logic is handled by AppAuthenticator.
 * This controller only renders the login form and provides
 * the last error / last username for form pre-population.
 */
class LoginController extends AbstractController
{
    /**
     * Display the login form.
     * Authentication is handled by AppAuthenticator on POST.
     */
    #[Route('/auth/login', name: 'app_login', methods: ['GET', 'POST'])]
    public function login(AuthenticationUtils $authenticationUtils, Request $request): Response
    {
        // Redirect already-authenticated users
        if ($this->getUser() !== null) {
            return $this->redirectToRoute('app_profile');
        }

        // Get the last authentication error (e.g., wrong password)
        $error = $authenticationUtils->getLastAuthenticationError();

        // Get the last entered username (to pre-populate the form)
        $lastUsername = $authenticationUtils->getLastUsername();

        return $this->render('auth/login.html.twig', [
            'last_username' => $lastUsername,
            'error' => $error,
        ]);
    }

    /**
     * Logout is handled by Symfony's security system (configured in security.yaml).
     * This method will never be called — it's a marker for the route.
     */
    #[Route('/auth/logout', name: 'app_logout', methods: ['GET'])]
    public function logout(): never
    {
        // This line is intentionally unreachable.
        // Symfony's security component intercepts this route before reaching the controller.
        throw new \LogicException('This method should not be called directly.');
    }
}
