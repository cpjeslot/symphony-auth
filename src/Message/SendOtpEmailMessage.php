<?php

declare(strict_types=1);

namespace App\Message;

/**
 * Message to send an OTP email asynchronously.
 */
class SendOtpEmailMessage
{
    public function __construct(
        private readonly int $userId,
        private readonly string $otpCode
    ) {
    }

    public function getUserId(): int
    {
        return $this->userId;
    }

    public function getOtpCode(): string
    {
        return $this->otpCode;
    }
}
