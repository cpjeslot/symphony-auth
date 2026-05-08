<?php

declare(strict_types=1);

namespace App\Repository;

use App\Entity\SocialAccount;
use App\Entity\User;
use App\Enum\OAuthProvider;
use Doctrine\Bundle\DoctrineBundle\Repository\ServiceEntityRepository;
use Doctrine\Persistence\ManagerRegistry;

/**
 * SocialAccountRepository.
 *
 * @extends ServiceEntityRepository<SocialAccount>
 */
class SocialAccountRepository extends ServiceEntityRepository
{
    public function __construct(ManagerRegistry $registry)
    {
        parent::__construct($registry, SocialAccount::class);
    }

    /**
     * Find an existing social account by provider and provider user ID.
     * Used to look up existing accounts on social login (prevent duplicates).
     */
    public function findByProviderAndId(OAuthProvider $provider, string $providerUserId): ?SocialAccount
    {
        return $this->createQueryBuilder('s')
            ->where('s.provider = :provider')
            ->andWhere('s.providerUserId = :providerId')
            ->setParameter('provider', $provider)
            ->setParameter('providerId', $providerUserId)
            ->getQuery()
            ->getOneOrNullResult();
    }

    /**
     * Find all social accounts for a user.
     *
     * @return list<SocialAccount>
     */
    public function findForUser(User $user): array
    {
        return $this->createQueryBuilder('s')
            ->where('s.user = :user')
            ->setParameter('user', $user)
            ->getQuery()
            ->getResult();
    }

    public function save(SocialAccount $account, bool $flush = true): void
    {
        $this->getEntityManager()->persist($account);

        if ($flush) {
            $this->getEntityManager()->flush();
        }
    }
}
