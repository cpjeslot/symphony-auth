<?php

declare(strict_types=1);

namespace App\Validator;

use Symfony\Component\Validator\Constraint;
use Symfony\Component\Validator\ConstraintValidator;
use Symfony\Component\Validator\Exception\UnexpectedTypeException;

/**
 * StrongPasswordValidator — Validates that a password meets strength requirements.
 *
 * Rules enforced:
 * - Minimum length (default: 8)
 * - Contains uppercase letter (A-Z)
 * - Contains lowercase letter (a-z)
 * - Contains digit (0-9)
 * - Contains special character (!@#$%^&* etc.)
 *
 * Multiple violations are reported (user sees all issues at once).
 */
class StrongPasswordValidator extends ConstraintValidator
{
    public function validate(mixed $value, Constraint $constraint): void
    {
        if (!$constraint instanceof StrongPassword) {
            throw new UnexpectedTypeException($constraint, StrongPassword::class);
        }

        if ($value === null || $value === '') {
            return; // NotBlank handles empty validation
        }

        if (!is_string($value)) {
            throw new UnexpectedTypeException($value, 'string');
        }

        // Check minimum length
        if (mb_strlen($value) < $constraint->minLength) {
            $this->context->buildViolation($constraint->tooShortMessage)
                ->setParameter('{{ min }}', (string) $constraint->minLength)
                ->addViolation();
        }

        // Check for uppercase letter
        if (!preg_match('/[A-Z]/', $value)) {
            $this->context->buildViolation($constraint->missingUpperMessage)
                ->addViolation();
        }

        // Check for lowercase letter
        if (!preg_match('/[a-z]/', $value)) {
            $this->context->buildViolation($constraint->missingLowerMessage)
                ->addViolation();
        }

        // Check for digit
        if (!preg_match('/[0-9]/', $value)) {
            $this->context->buildViolation($constraint->missingDigitMessage)
                ->addViolation();
        }

        // Check for special character
        // Covers: ! @ # $ % ^ & * ( ) _ - + = [ ] { } ; : ' " , . < > ? / \ | ~ `
        if (!preg_match('/[^a-zA-Z0-9]/', $value)) {
            $this->context->buildViolation($constraint->missingSpecialMessage)
                ->addViolation();
        }
    }
}
