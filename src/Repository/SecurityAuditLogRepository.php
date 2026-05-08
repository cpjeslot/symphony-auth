<?php

declare(strict_types=1);

namespace App\Repository;

use App\Entity\SecurityAuditLog;
use App\Entity\User;
use App\Enum\AuditEventType;
use Doctrine\Bundle\DoctrineBundle\Repository\ServiceEntityRepository;
use Doctrine\Persistence\ManagerRegistry;

/**
 * SecurityAuditLogRepository.
 *
 * @extends ServiceEntityRepository<SecurityAuditLog>
 */
class SecurityAuditLogRepository extends ServiceEntityRepository
{
    public function __construct(ManagerRegistry $registry)
    {
        parent::__construct($registry, SecurityAuditLog::class);
    }

    /**
     * Get recent security events for a user.
     *
     * @return list<SecurityAuditLog>
     */
    public function findRecentForUser(User $user, int $limit = 50): array
    {
        return $this->createQueryBuilder('l')
            ->where('l.user = :user')
            ->setParameter('user', $user)
            ->orderBy('l.createdAt', 'DESC')
            ->setMaxResults($limit)
            ->getQuery()
            ->getResult();
    }

    /**
     * Get events by type in the last N hours.
     *
     * @return list<SecurityAuditLog>
     */
    public function findByEventTypeInLastHours(AuditEventType $eventType, int $hours = 24): array
    {
        $since = new \DateTimeImmutable("-{$hours} hours");

        return $this->createQueryBuilder('l')
            ->where('l.eventType = :type')
            ->andWhere('l.createdAt > :since')
            ->setParameter('type', $eventType)
            ->setParameter('since', $since)
            ->orderBy('l.createdAt', 'DESC')
            ->getQuery()
            ->getResult();
    }

    /**
     * Count security warnings/errors in last N hours (for admin dashboard).
     */
    public function countHighSeverityRecentEvents(int $hours = 24): int
    {
        $since = new \DateTimeImmutable("-{$hours} hours");

        return (int) $this->createQueryBuilder('l')
            ->select('COUNT(l.id)')
            ->where("l.severity IN ('warning', 'error')")
            ->andWhere('l.createdAt > :since')
            ->setParameter('since', $since)
            ->getQuery()
            ->getSingleScalarResult();
    }

    public function save(SecurityAuditLog $log, bool $flush = true): void
    {
        $this->getEntityManager()->persist($log);

        if ($flush) {
            $this->getEntityManager()->flush();
        }
    }
}
