<?php

declare(strict_types=1);

namespace App\Security\Voter;

use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authorization\Voter\Voter;

/**
 * TwoFactorVoter — Handles the custom 'IS_AUTHENTICATED_2FA_IN_PROGRESS' security attribute.
 * 
 * This voter allows access to 2FA routes only if there is a pending 2FA session.
 */
class TwoFactorVoter extends Voter
{
    public const IS_AUTHENTICATED_2FA_IN_PROGRESS = 'IS_AUTHENTICATED_2FA_IN_PROGRESS';

    public function __construct(
        private readonly RequestStack $requestStack,
    ) {}

    protected function supports(string $attribute, mixed $subject): bool
    {
        return $attribute === self::IS_AUTHENTICATED_2FA_IN_PROGRESS;
    }

    protected function voteOnAttribute(string $attribute, mixed $subject, TokenInterface $token): bool
    {
        $request = $this->requestStack->getCurrentRequest();
        if (!$request) {
            return false;
        }

        $session = $request->getSession();
        
        // Allow access if the session has a pending 2FA flag
        return (bool) $session->get('2fa_pending', false);
    }
}
