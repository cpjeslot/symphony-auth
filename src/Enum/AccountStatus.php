<?php

declare(strict_types=1);

namespace App\Enum;

/**
 * User account status enumeration.
 *
 * Defines the possible states a user account can be in.
 * Used for access control decisions throughout the application.
 */
enum AccountStatus: string
{
    case Active = 'active';
    case Suspended = 'suspended';
    case PendingVerification = 'pending_verification';
    case Deactivated = 'deactivated';
    case Banned = 'banned';

    /**
     * Get a human-readable label for the status.
     */
    public function label(): string
    {
        return match($this) {
            self::Active => 'Active',
            self::Suspended => 'Suspended',
            self::PendingVerification => 'Pending Email Verification',
            self::Deactivated => 'Deactivated',
            self::Banned => 'Banned',
        };
    }

    /**
     * Check if the status allows login.
     */
    public function allowsLogin(): bool
    {
        return $this === self::Active;
    }
}
