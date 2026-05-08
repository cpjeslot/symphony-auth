<?php

declare(strict_types=1);

namespace App\Enum;

/**
 * Gender enumeration for user profiles.
 */
enum Gender: string
{
    case Male = 'male';
    case Female = 'female';
    case NonBinary = 'non_binary';
    case PreferNotToSay = 'prefer_not_to_say';
    case Other = 'other';

    public function label(): string
    {
        return match($this) {
            self::Male => 'Male',
            self::Female => 'Female',
            self::NonBinary => 'Non-binary',
            self::PreferNotToSay => 'Prefer not to say',
            self::Other => 'Other',
        };
    }
}
