<?php

declare(strict_types=1);

namespace App\Controller\Auth;

use App\DTO\RegistrationDTO;
use App\Form\RegistrationFormType;
use App\Service\Auth\RegistrationService;
use Psr\Log\LoggerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\RateLimiter\RateLimiterFactory;
use Symfony\Component\Routing\Attribute\Route;

/**
 * RegistrationController — Handles the user registration flow.
 *
 * Routes:
 * - GET  /auth/register       → Show registration form
 * - POST /auth/register       → Process registration
 *
 * Security:
 * - Rate limited: 3 registrations per hour per IP
 * - CSRF protected via form token
 * - All validation in RegistrationDTO + form type
 */
#[Route('/auth')]
class RegistrationController extends AbstractController
{
    public function __construct(
        private readonly RegistrationService $registrationService,
        private readonly RateLimiterFactory $registrationLimiter,
        private readonly LoggerInterface $logger,
    ) {}

    /**
     * Display and process the registration form.
     */
    #[Route('/register', name: 'app_register', methods: ['GET', 'POST'])]
    public function register(Request $request): Response
    {
        // Redirect already-authenticated users
        if ($this->getUser() !== null) {
            return $this->redirectToRoute('app_profile');
        }

        // Rate limit: 3 registrations per hour per IP
        $limiter = $this->registrationLimiter->create($request->getClientIp());
        $limit = $limiter->consume();

        if (!$limit->isAccepted()) {
            $this->addFlash(
                'error',
                'Too many registration attempts. Please try again later.'
            );
            return $this->render('auth/register.html.twig', [
                'form' => $this->createForm(RegistrationFormType::class)->createView(),
                'rate_limited' => true,
            ]);
        }

        $form = $this->createForm(RegistrationFormType::class);
        $form->handleRequest($request);

        if ($form->isSubmitted() && $form->isValid()) {
            $data = $form->getData();

            try {
                $dto = new RegistrationDTO(
                    firstName: trim((string) $form->get('firstName')->getData()),
                    lastName: trim((string) $form->get('lastName')->getData()),
                    email: trim((string) $form->get('email')->getData()),
                    password: (string) $form->get('password')->getData(),
                    passwordConfirm: (string) $form->get('password')->getData(),
                    middleName: $form->get('middleName')->getData() ?: null,
                    mobileNumber: $form->get('mobileNumber')->getData() ?: null,
                    agreeTerms: (bool) $form->get('agreeTerms')->getData(),
                );

                $this->registrationService->register($dto, $request->getClientIp());

                $this->addFlash(
                    'success',
                    'Registration successful! Please check your email to verify your account.'
                );

                return $this->redirectToRoute('app_login');
            } catch (\InvalidArgumentException $e) {
                // Business logic error (duplicate email, mobile, etc.)
                $this->addFlash('error', $e->getMessage());
            } catch (\Throwable $e) {
                $this->logger->error('Registration failed', [
                    'error' => $e->getMessage(),
                    'ip' => $request->getClientIp(),
                ]);
                $this->addFlash('error', 'Registration failed due to a server error. Please try again.');
            }
        }

        return $this->render('auth/register.html.twig', [
            'form' => $form->createView(),
            'rate_limited' => false,
        ]);
    }
}
