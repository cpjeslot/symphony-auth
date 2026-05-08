<?php

declare(strict_types=1);

namespace App\Repository;

use App\Entity\ActiveSession;
use App\Entity\User;
use Doctrine\Bundle\DoctrineBundle\Repository\ServiceEntityRepository;
use Doctrine\Persistence\ManagerRegistry;

/**
 * ActiveSessionRepository.
 *
 * @extends ServiceEntityRepository<ActiveSession>
 */
class ActiveSessionRepository extends ServiceEntityRepository
{
    public function __construct(ManagerRegistry $registry)
    {
        parent::__construct($registry, ActiveSession::class);
    }

    /**
     * Find a session by hashed token, only if active (not revoked, not expired).
     */
    public function findActiveByTokenHash(string $tokenHash): ?ActiveSession
    {
        return $this->createQueryBuilder('s')
            ->where('s.sessionTokenHash = :hash')
            ->andWhere('s.isRevoked = false')
            ->andWhere('s.expiresAt > :now')
            ->setParameter('hash', $tokenHash)
            ->setParameter('now', new \DateTimeImmutable())
            ->getQuery()
            ->getOneOrNullResult();
    }

    /**
     * Find all active sessions for a user.
     *
     * @return list<ActiveSession>
     */
    public function findActiveForUser(User $user): array
    {
        return $this->createQueryBuilder('s')
            ->where('s.user = :user')
            ->andWhere('s.isRevoked = false')
            ->andWhere('s.expiresAt > :now')
            ->setParameter('user', $user)
            ->setParameter('now', new \DateTimeImmutable())
            ->orderBy('s.lastActivityAt', 'DESC')
            ->getQuery()
            ->getResult();
    }

    /**
     * Revoke all sessions for a user except the current one.
     * Used for "log out all other devices" functionality.
     */
    public function revokeAllExcept(User $user, string $currentTokenHash): int
    {
        return (int) $this->createQueryBuilder('s')
            ->update()
            ->set('s.isRevoked', 'true')
            ->where('s.user = :user')
            ->andWhere('s.sessionTokenHash != :current')
            ->andWhere('s.isRevoked = false')
            ->setParameter('user', $user)
            ->setParameter('current', $currentTokenHash)
            ->getQuery()
            ->execute();
    }

    /**
     * Delete expired and revoked sessions older than X days.
     */
    public function cleanupExpired(int $days = 1): int
    {
        $cutoff = new \DateTimeImmutable("-{$days} days");

        return (int) $this->createQueryBuilder('s')
            ->delete()
            ->where('s.expiresAt < :cutoff OR s.isRevoked = true')
            ->setParameter('cutoff', $cutoff)
            ->getQuery()
            ->execute();
    }

    public function save(ActiveSession $session, bool $flush = true): void
    {
        $this->getEntityManager()->persist($session);

        if ($flush) {
            $this->getEntityManager()->flush();
        }
    }
}
