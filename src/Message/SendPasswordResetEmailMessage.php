<?php

declare(strict_types=1);

namespace App\Message;

/**
 * Message to send a password reset email asynchronously.
 */
class SendPasswordResetEmailMessage
{
    public function __construct(
        private readonly int $userId,
        private readonly string $token
    ) {
    }

    public function getUserId(): int
    {
        return $this->userId;
    }

    public function getToken(): string
    {
        return $this->token;
    }
}
