<?php

declare(strict_types=1);

namespace App\Repository;

use App\Entity\EmailVerificationToken;
use Doctrine\Bundle\DoctrineBundle\Repository\ServiceEntityRepository;
use Doctrine\Persistence\ManagerRegistry;

/**
 * EmailVerificationTokenRepository.
 *
 * @extends ServiceEntityRepository<EmailVerificationToken>
 */
class EmailVerificationTokenRepository extends ServiceEntityRepository
{
    public function __construct(ManagerRegistry $registry)
    {
        parent::__construct($registry, EmailVerificationToken::class);
    }

    /**
     * Find a valid verification token by its hash.
     */
    public function findValidByTokenHash(string $tokenHash): ?EmailVerificationToken
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

    public function save(EmailVerificationToken $token, bool $flush = true): void
    {
        $this->getEntityManager()->persist($token);

        if ($flush) {
            $this->getEntityManager()->flush();
        }
    }
}
