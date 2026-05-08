<?php

declare(strict_types=1);

namespace App\Security\Voter;

use App\Entity\User;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authorization\Voter\Voter;

/**
 * UserVoter — Access control for user resource operations.
 *
 * Defines fine-grained permission rules for operating on User entities.
 *
 * Permissions:
 * - USER_VIEW:   Can the current user view a User profile?
 * - USER_EDIT:   Can the current user edit a User profile?
 * - USER_DELETE: Can the current user delete/deactivate a User?
 *
 * Rules:
 * - ROLE_ADMIN can perform all operations on all users
 * - ROLE_USER can only view/edit their own profile
 * - Only ROLE_ADMIN can delete users
 *
 * @extends Voter<string, User>
 */
class UserVoter extends Voter
{
    public const USER_VIEW = 'USER_VIEW';
    public const USER_EDIT = 'USER_EDIT';
    public const USER_DELETE = 'USER_DELETE';

    protected function supports(string $attribute, mixed $subject): bool
    {
        return in_array($attribute, [self::USER_VIEW, self::USER_EDIT, self::USER_DELETE], true)
            && $subject instanceof User;
    }

    protected function voteOnAttribute(string $attribute, mixed $subject, TokenInterface $token): bool
    {
        $currentUser = $token->getUser();

        if (!$currentUser instanceof User) {
            // Not authenticated — deny all
            return false;
        }

        /** @var User $targetUser */
        $targetUser = $subject;

        // Admins can do everything
        if (in_array('ROLE_ADMIN', $token->getRoleNames(), true)) {
            return true;
        }

        return match ($attribute) {
            // Users can view their own profile
            self::USER_VIEW => $this->isSameUser($currentUser, $targetUser),
            // Users can edit only their own profile
            self::USER_EDIT => $this->isSameUser($currentUser, $targetUser),
            // Only admins can delete (already handled above)
            self::USER_DELETE => false,
            default => false,
        };
    }

    private function isSameUser(User $currentUser, User $targetUser): bool
    {
        return $currentUser->getId()?->toString() === $targetUser->getId()?->toString();
    }
}
