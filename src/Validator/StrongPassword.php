<?php

declare(strict_types=1);

namespace App\Validator;

use Symfony\Component\Validator\Constraint;

/**
 * StrongPassword — Custom validation constraint for strong password rules.
 *
 * Enforces:
 * - Minimum 8 characters
 * - At least one uppercase letter
 * - At least one lowercase letter
 * - At least one digit
 * - At least one special character
 *
 * Applied as an attribute: #[StrongPassword]
 */
#[\Attribute(\Attribute::TARGET_PROPERTY | \Attribute::TARGET_METHOD | \Attribute::TARGET_PARAMETER)]
class StrongPassword extends Constraint
{
    public string $message = 'Password must be at least 8 characters and contain uppercase, lowercase, number, and special character.';

    public string $tooShortMessage = 'Password must be at least {{ min }} characters.';
    public string $missingUpperMessage = 'Password must contain at least one uppercase letter.';
    public string $missingLowerMessage = 'Password must contain at least one lowercase letter.';
    public string $missingDigitMessage = 'Password must contain at least one number.';
    public string $missingSpecialMessage = 'Password must contain at least one special character (!@#$%^&* etc).';

    public int $minLength = 8;
}
