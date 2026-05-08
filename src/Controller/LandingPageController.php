<?php

declare(strict_types=1);

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

/**
 * LandingPageController — Handles the main entrance to the application.
 */
class LandingPageController extends AbstractController
{
    #[Route('/', name: 'app_landing')]
    public function index(): Response
    {
        // If user is already logged in, redirect to profile or dashboard
        if ($this->getUser()) {
            return $this->redirectToRoute('app_profile');
        }

        return $this->render('landing/index.html.twig');
    }
}
