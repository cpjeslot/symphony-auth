<?php

declare(strict_types=1);

namespace App\Repository;

use App\Entity\EmailOtp;
use App\Entity\User;
use Doctrine\Bundle\DoctrineBundle\Repository\ServiceEntityRepository;
use Doctrine\Persistence\ManagerRegistry;

/**
 * EmailOtpRepository — Data access for Email OTP records.
 *
 * @extends ServiceEntityRepository<EmailOtp>
 */
class EmailOtpRepository extends ServiceEntityRepository
{
    public function __construct(ManagerRegistry $registry)
    {
        parent::__construct($registry, EmailOtp::class);
    }

    /**
     * Find the most recent valid OTP for a user and purpose.
     * "Valid" means: not expired, not used, retry limit not exceeded.
     */
    public function findValidOtp(User $user, string $purpose = 'login_2fa'): ?EmailOtp
    {
        return $this->createQueryBuilder('o')
            ->where('o.user = :user')
            ->andWhere('o.purpose = :purpose')
            ->andWhere('o.isUsed = false')
            ->andWhere('o.expiresAt > :now')
            ->andWhere('o.retryCount < o.maxRetries')
            ->setParameter('user', $user)
            ->setParameter('purpose', $purpose)
            ->setParameter('now', new \DateTimeImmutable())
            ->orderBy('o.createdAt', 'DESC')
            ->setMaxResults(1)
            ->getQuery()
            ->getOneOrNullResult();
    }

    /**
     * Invalidate all pending OTPs for a user (before issuing a new one).
     * Prevents OTP accumulation and replay with old codes.
     */
    public function invalidatePendingOtps(User $user, string $purpose = 'login_2fa'): void
    {
        $this->createQueryBuilder('o')
            ->update()
            ->set('o.isUsed', 'true')
            ->where('o.user = :user')
            ->andWhere('o.purpose = :purpose')
            ->andWhere('o.isUsed = false')
            ->setParameter('user', $user)
            ->setParameter('purpose', $purpose)
            ->getQuery()
            ->execute();
    }

    /**
     * Count OTP send requests in the last N minutes (for rate limiting check).
     */
    public function countRecentOtpRequests(User $user, int $minutes = 5): int
    {
        $since = new \DateTimeImmutable("-{$minutes} minutes");

        return (int) $this->createQueryBuilder('o')
            ->select('COUNT(o.id)')
            ->where('o.user = :user')
            ->andWhere('o.createdAt > :since')
            ->setParameter('user', $user)
            ->setParameter('since', $since)
            ->getQuery()
            ->getSingleScalarResult();
    }

    /**
     * Delete expired OTP records older than the given number of days.
     * Used by cleanup command.
     */
    public function deleteExpiredOlderThan(int $days = 7): int
    {
        $cutoff = new \DateTimeImmutable("-{$days} days");

        return (int) $this->createQueryBuilder('o')
            ->delete()
            ->where('o.expiresAt < :cutoff')
            ->setParameter('cutoff', $cutoff)
            ->getQuery()
            ->execute();
    }

    public function save(EmailOtp $otp, bool $flush = true): void
    {
        $this->getEntityManager()->persist($otp);

        if ($flush) {
            $this->getEntityManager()->flush();
        }
    }
}
