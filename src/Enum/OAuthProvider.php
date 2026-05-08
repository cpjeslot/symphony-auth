<?php

declare(strict_types=1);

namespace App\Enum;

/**
 * OAuth2 provider enumeration.
 * Lists supported social login providers.
 */
enum OAuthProvider: string
{
    case Google = 'google';
    case GitHub = 'github';
    case Facebook = 'facebook';
    case Apple = 'apple';

    public function label(): string
    {
        return match($this) {
            self::Google => 'Google',
            self::GitHub => 'GitHub',
            self::Facebook => 'Facebook',
            self::Apple => 'Apple',
        };
    }

    public function icon(): string
    {
        return match($this) {
            self::Google => 'fab fa-google',
            self::GitHub => 'fab fa-github',
            self::Facebook => 'fab fa-facebook',
            self::Apple => 'fab fa-apple',
        };
    }
}
