<?php

declare(strict_types=1);

namespace App\Repository;

use App\Entity\PasswordResetToken;
use App\Entity\User;
use Doctrine\Bundle\DoctrineBundle\Repository\ServiceEntityRepository;
use Doctrine\Persistence\ManagerRegistry;

/**
 * PasswordResetTokenRepository.
 *
 * @extends ServiceEntityRepository<PasswordResetToken>
 */
class PasswordResetTokenRepository extends ServiceEntityRepository
{
    public function __construct(ManagerRegistry $registry)
    {
        parent::__construct($registry, PasswordResetToken::class);
    }

    /**
     * Find a valid (unexpired, unused) token by its SHA-256 hash.
     *
     * SECURITY: The token hash is compared — never the raw token.
     */
    public function findValidByTokenHash(string $tokenHash): ?PasswordResetToken
    {
        return $this->createQueryBuilder('t')
            ->where('t.tokenHash = :hash')
            ->andWhere('t.isUsed = false')
            ->andWhere('t.expiresAt > :now')
            ->setParameter('hash', $tokenHash)
            ->setParameter('now', new \DateTimeImmutable())
            ->getQuery()
            ->getOneOrNullResult();
    }

    /**
     * Invalidate all pending reset tokens for a user.
     * Called before issuing a new reset link.
     */
    public function invalidateUserTokens(User $user): void
    {
        $this->createQueryBuilder('t')
            ->update()
            ->set('t.isUsed', 'true')
            ->where('t.user = :user')
            ->andWhere('t.isUsed = false')
            ->setParameter('user', $user)
            ->getQuery()
            ->execute();
    }

    /**
     * Delete expired tokens (older than X days) for housekeeping.
     */
    public function deleteExpiredOlderThan(int $days = 3): int
    {
        $cutoff = new \DateTimeImmutable("-{$days} days");

        return (int) $this->createQueryBuilder('t')
            ->delete()
            ->where('t.expiresAt < :cutoff')
            ->setParameter('cutoff', $cutoff)
            ->getQuery()
            ->execute();
    }

    public function save(PasswordResetToken $token, bool $flush = true): void
    {
        $this->getEntityManager()->persist($token);

        if ($flush) {
            $this->getEntityManager()->flush();
        }
    }
}
