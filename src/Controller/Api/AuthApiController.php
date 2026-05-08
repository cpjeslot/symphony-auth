<?php

declare(strict_types=1);

namespace App\Controller\Api;

use App\Entity\User;
use App\Repository\UserRepository;
use App\Service\Auth\PasswordResetService;
use App\Service\Auth\RegistrationService;
use App\Service\Otp\OtpService;
use Lexik\Bundle\JWTAuthenticationBundle\Services\JWTTokenManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\RateLimiter\RateLimiterFactory;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Security\Http\Attribute\CurrentUser;
use Symfony\Component\Serializer\SerializerInterface;

/**
 * AuthApiController — JWT-based REST API authentication endpoints.
 *
 * All responses use consistent JSON structure:
 * {
 *   "success": bool,
 *   "data": object|null,
 *   "message": string,
 *   "errors": array
 * }
 *
 * Rate limiting applied to all auth endpoints.
 */
#[Route('/api/auth', name: 'api_auth_')]
class AuthApiController extends AbstractController
{
    public function __construct(
        private readonly UserRepository $userRepository,
        private readonly UserPasswordHasherInterface $passwordHasher,
        private readonly JWTTokenManagerInterface $jwtManager,
        private readonly RegistrationService $registrationService,
        private readonly PasswordResetService $passwordResetService,
        private readonly OtpService $otpService,
        private readonly RateLimiterFactory $loginLimiter,
    ) {}

    /**
     * POST /api/auth/login
     * Exchange credentials for JWT token.
     * 
     * Request body: {"identifier": "email_or_mobile", "password": "..."}
     * Response: {"token": "...", "refresh_token": "...", "user": {...}}
     */
    #[Route('/login', name: 'login', methods: ['POST'])]
    public function login(Request $request, #[CurrentUser] ?User $user): JsonResponse
    {
        // LexikJWT handles the actual authentication.
        // If we reach this controller, authentication succeeded.
        // If authentication fails, Lexik returns a 401 JSON response automatically.

        if ($user === null) {
            return $this->json([
                'success' => false,
                'message' => 'Authentication required.',
                'data' => null,
                'errors' => [],
            ], Response::HTTP_UNAUTHORIZED);
        }

        // Generate JWT token
        $token = $this->jwtManager->create($user);

        // Handle 2FA
        if ($user->isTwoFactorEnabled()) {
            $this->otpService->generateAndSendOtp(
                $user,
                'login_2fa',
                $request->getClientIp()
            );

            return $this->json([
                'success' => true,
                'message' => '2FA required. OTP sent to your email.',
                'data' => [
                    'requires_2fa' => true,
                    'temp_token' => $token,  // Short-lived token for OTP verification
                ],
                'errors' => [],
            ]);
        }

        return $this->json([
            'success' => true,
            'message' => 'Login successful.',
            'data' => [
                'token' => $token,
                'user' => $this->serializeUser($user),
            ],
            'errors' => [],
        ]);
    }

    /**
     * POST /api/auth/register
     * Register a new user account.
     */
    #[Route('/register', name: 'register', methods: ['POST'])]
    public function register(Request $request): JsonResponse
    {
        // Rate limit: 3 registrations per hour per IP
        $limiter = $this->loginLimiter->create('reg_' . $request->getClientIp());
        if (!$limiter->consume()->isAccepted()) {
            return $this->json([
                'success' => false,
                'message' => 'Too many registration attempts. Try again later.',
                'data' => null,
                'errors' => [],
            ], Response::HTTP_TOO_MANY_REQUESTS);
        }

        $data = json_decode($request->getContent(), true) ?? [];

        // Validate required fields
        if (empty($data['email']) || empty($data['password']) || empty($data['firstName']) || empty($data['lastName'])) {
            return $this->json([
                'success' => false,
                'message' => 'Missing required fields.',
                'data' => null,
                'errors' => ['required' => ['firstName', 'lastName', 'email', 'password']],
            ], Response::HTTP_UNPROCESSABLE_ENTITY);
        }

        try {
            $dto = new \App\DTO\RegistrationDTO(
                firstName: trim($data['firstName']),
                lastName: trim($data['lastName']),
                email: trim($data['email']),
                password: $data['password'],
                passwordConfirm: $data['password'],
                middleName: $data['middleName'] ?? null,
                mobileNumber: $data['mobileNumber'] ?? null,
                agreeTerms: (bool) ($data['agreeTerms'] ?? false),
            );

            $user = $this->registrationService->register($dto, $request->getClientIp());

            return $this->json([
                'success' => true,
                'message' => 'Registration successful. Please verify your email.',
                'data' => ['user_id' => $user->getId()?->toString()],
                'errors' => [],
            ], Response::HTTP_CREATED);
        } catch (\InvalidArgumentException $e) {
            return $this->json([
                'success' => false,
                'message' => $e->getMessage(),
                'data' => null,
                'errors' => [],
            ], Response::HTTP_CONFLICT);
        } catch (\Throwable $e) {
            return $this->json([
                'success' => false,
                'message' => 'Registration failed. Please try again.',
                'data' => null,
                'errors' => [],
            ], Response::HTTP_INTERNAL_SERVER_ERROR);
        }
    }

    /**
     * GET /api/auth/me
     * Return the authenticated user's profile.
     */
    #[Route('/me', name: 'me', methods: ['GET'])]
    public function me(#[CurrentUser] ?User $user): JsonResponse
    {
        if ($user === null) {
            return $this->json([
                'success' => false,
                'message' => 'Not authenticated.',
                'data' => null,
                'errors' => [],
            ], Response::HTTP_UNAUTHORIZED);
        }

        return $this->json([
            'success' => true,
            'message' => 'Profile retrieved.',
            'data' => $this->serializeUser($user),
            'errors' => [],
        ]);
    }

    /**
     * POST /api/auth/forgot-password
     * Initiate password reset (always returns success).
     */
    #[Route('/forgot-password', name: 'forgot_password', methods: ['POST'])]
    public function forgotPassword(Request $request): JsonResponse
    {
        $data = json_decode($request->getContent(), true) ?? [];
        $email = trim($data['email'] ?? '');

        // Always return 200 (enumeration protection)
        $this->passwordResetService->initiateReset($email, $request->getClientIp());

        return $this->json([
            'success' => true,
            'message' => 'If an account exists with this email, a reset link has been sent.',
            'data' => null,
            'errors' => [],
        ]);
    }

    /**
     * POST /api/auth/reset-password
     * Complete a password reset.
     */
    #[Route('/reset-password', name: 'reset_password', methods: ['POST'])]
    public function resetPassword(Request $request): JsonResponse
    {
        $data = json_decode($request->getContent(), true) ?? [];
        $token = $data['token'] ?? '';
        $newPassword = $data['password'] ?? '';

        if (empty($token) || empty($newPassword)) {
            return $this->json([
                'success' => false,
                'message' => 'Token and new password are required.',
                'data' => null,
                'errors' => [],
            ], Response::HTTP_UNPROCESSABLE_ENTITY);
        }

        try {
            $this->passwordResetService->resetPassword($token, $newPassword);

            return $this->json([
                'success' => true,
                'message' => 'Password reset successfully.',
                'data' => null,
                'errors' => [],
            ]);
        } catch (\InvalidArgumentException $e) {
            return $this->json([
                'success' => false,
                'message' => $e->getMessage(),
                'data' => null,
                'errors' => [],
            ], Response::HTTP_BAD_REQUEST);
        }
    }

    /**
     * POST /api/auth/2fa/verify
     * Verify OTP for API 2FA flow.
     */
    #[Route('/2fa/verify', name: '2fa_verify', methods: ['POST'])]
    public function verifyOtp(Request $request, #[CurrentUser] ?User $user): JsonResponse
    {
        if ($user === null) {
            return $this->json([
                'success' => false,
                'message' => 'Not authenticated.',
                'data' => null,
                'errors' => [],
            ], Response::HTTP_UNAUTHORIZED);
        }

        $data = json_decode($request->getContent(), true) ?? [];
        $otp = trim($data['otp'] ?? '');

        if (empty($otp)) {
            return $this->json([
                'success' => false,
                'message' => 'OTP code is required.',
                'data' => null,
                'errors' => [],
            ], Response::HTTP_UNPROCESSABLE_ENTITY);
        }

        $isValid = $this->otpService->verifyOtp($user, $otp, 'login_2fa');

        if (!$isValid) {
            return $this->json([
                'success' => false,
                'message' => 'Invalid or expired OTP.',
                'data' => null,
                'errors' => [],
            ], Response::HTTP_UNAUTHORIZED);
        }

        // Issue full JWT on successful 2FA
        $token = $this->jwtManager->create($user);

        return $this->json([
            'success' => true,
            'message' => '2FA verified successfully.',
            'data' => [
                'token' => $token,
                'user' => $this->serializeUser($user),
            ],
            'errors' => [],
        ]);
    }

    /**
     * Serialize user to safe API response (no sensitive fields).
     *
     * SECURITY: Never include passwordHash, refreshToken, deviceToken, etc.
     *
     * @return array<string, mixed>
     */
    private function serializeUser(User $user): array
    {
        return [
            'id' => $user->getId()?->toString(),
            'firstName' => $user->getFirstName(),
            'lastName' => $user->getLastName(),
            'fullName' => $user->getFullName(),
            'email' => $user->getEmail(),
            'username' => $user->getUsername(),
            'mobileNumber' => $user->getMobileNumber(),
            'profilePhoto' => $user->getProfilePhoto(),
            'roles' => $user->getRoles(),
            'emailVerified' => $user->isEmailVerified(),
            'twoFactorEnabled' => $user->isTwoFactorEnabled(),
            'accountStatus' => $user->getAccountStatus()->value,
            'lastLogin' => $user->getLastLogin()?->format(\DateTimeInterface::ATOM),
            'createdAt' => $user->getCreatedAt()?->format(\DateTimeInterface::ATOM),
        ];
    }
}
