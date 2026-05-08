<?php

declare(strict_types=1);

namespace App\DTO;

use App\Validator\StrongPassword;
use Symfony\Component\Validator\Constraints as Assert;

/**
 * RegistrationDTO — Data Transfer Object for user registration form.
 *
 * Provides validated, typed data from the registration form before
 * the data is passed to the RegistrationService.
 *
 * All validation is performed here via Symfony Validator constraints,
 * keeping the service layer clean and focused on business logic.
 */
final class RegistrationDTO
{
    public function __construct(
        #[Assert\NotBlank(message: 'First name is required.')]
        #[Assert\Length(min: 1, max: 100, minMessage: 'First name must be at least 1 character.')]
        #[Assert\Regex(
            pattern: '/^[\p{L}\s\-\'\.]+$/u',
            message: 'First name contains invalid characters.'
        )]
        public readonly string $firstName,

        #[Assert\NotBlank(message: 'Last name is required.')]
        #[Assert\Length(min: 1, max: 100)]
        #[Assert\Regex(
            pattern: '/^[\p{L}\s\-\'\.]+$/u',
            message: 'Last name contains invalid characters.'
        )]
        public readonly string $lastName,

        #[Assert\NotBlank(message: 'Email address is required.')]
        #[Assert\Email(message: 'Please enter a valid email address.', mode: 'html5')]
        #[Assert\Length(max: 254, maxMessage: 'Email address is too long.')]
        public readonly string $email,

        #[Assert\NotBlank(message: 'Password is required.')]
        #[StrongPassword]
        public readonly string $password,

        #[Assert\NotBlank(message: 'Please confirm your password.')]
        #[Assert\EqualTo(
            propertyPath: 'password',
            message: 'Passwords do not match.'
        )]
        public readonly string $passwordConfirm,

        #[Assert\Length(max: 100)]
        public readonly ?string $middleName = null,

        #[Assert\Regex(
            pattern: '/^\+[1-9]\d{6,14}$/',
            message: 'Mobile number must be in E.164 format (e.g. +14155552671).'
        )]
        public readonly ?string $mobileNumber = null,

        #[Assert\IsTrue(message: 'You must accept the Terms & Conditions.')]
        public readonly bool $agreeTerms = false,
    ) {}
}
