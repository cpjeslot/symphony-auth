<?php

declare(strict_types=1);

namespace App\Enum;

/**
 * Blood group enumeration for user profiles.
 * Uses ABO+Rh system with standard medical notation.
 */
enum BloodGroup: string
{
    case APositive = 'A+';
    case ANegative = 'A-';
    case BPositive = 'B+';
    case BNegative = 'B-';
    case ABPositive = 'AB+';
    case ABNegative = 'AB-';
    case OPositive = 'O+';
    case ONegative = 'O-';

    public function label(): string
    {
        return $this->value;
    }
}
