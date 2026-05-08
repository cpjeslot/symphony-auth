<?php

declare(strict_types=1);

namespace App\Repository;

use App\Entity\LoginHistory;
use App\Entity\User;
use Doctrine\Bundle\DoctrineBundle\Repository\ServiceEntityRepository;
use Doctrine\Persistence\ManagerRegistry;

/**
 * LoginHistoryRepository.
 *
 * @extends ServiceEntityRepository<LoginHistory>
 */
class LoginHistoryRepository extends ServiceEntityRepository
{
    public function __construct(ManagerRegistry $registry)
    {
        parent::__construct($registry, LoginHistory::class);
    }

    /**
     * Get recent login history for a user (paginated).
     *
     * @return list<LoginHistory>
     */
    public function findRecentForUser(User $user, int $limit = 20): array
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
     * Count failed login attempts from an IP in the last N minutes.
     * Used for IP-based rate limiting in addition to Symfony rate limiter.
     */
    public function countRecentFailuresFromIp(string $ipAddress, int $minutes = 60): int
    {
        $since = new \DateTimeImmutable("-{$minutes} minutes");

        return (int) $this->createQueryBuilder('l')
            ->select('COUNT(l.id)')
            ->where('l.ipAddress = :ip')
            ->andWhere('l.isSuccessful = false')
            ->andWhere('l.createdAt > :since')
            ->setParameter('ip', $ipAddress)
            ->setParameter('since', $since)
            ->getQuery()
            ->getSingleScalarResult();
    }

    public function save(LoginHistory $history, bool $flush = true): void
    {
        $this->getEntityManager()->persist($history);

        if ($flush) {
            $this->getEntityManager()->flush();
        }
    }
}
