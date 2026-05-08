<?php

declare(strict_types=1);

namespace App\Enum;

/**
 * Login type enumeration.
 * Tracks the primary authentication method used by the user.
 */
enum LoginType: string
{
    case Email = 'email';
    case Mobile = 'mobile';
    case Sso = 'sso';         // Social/OAuth login

    public function label(): string
    {
        return match($this) {
            self::Email => 'Email',
            self::Mobile => 'Mobile Number',
            self::Sso => 'Single Sign-On (SSO)',
        };
    }
}
