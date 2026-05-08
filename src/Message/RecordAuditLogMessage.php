<?php

declare(strict_types=1);

namespace App\Message;

/**
 * Message to record an audit log event asynchronously.
 */
class RecordAuditLogMessage
{
    public function __construct(
        private readonly string $event,
        private readonly array $data,
        private readonly ?int $userId = null
    ) {
    }

    public function getEvent(): string
    {
        return $this->event;
    }

    public function getData(): array
    {
        return $this->data;
    }

    public function getUserId(): ?int
    {
        return $this->userId;
    }
}
