<?php

declare(strict_types=1);

namespace App\Enum;

/**
 * Marital status enumeration for user profiles.
 */
enum MaritalStatus: string
{
    case Single = 'single';
    case Married = 'married';
    case Divorced = 'divorced';
    case Widowed = 'widowed';
    case Separated = 'separated';
    case PreferNotToSay = 'prefer_not_to_say';

    public function label(): string
    {
        return match($this) {
            self::Single => 'Single',
            self::Married => 'Married',
            self::Divorced => 'Divorced',
            self::Widowed => 'Widowed',
            self::Separated => 'Separated',
            self::PreferNotToSay => 'Prefer not to say',
        };
    }
}
