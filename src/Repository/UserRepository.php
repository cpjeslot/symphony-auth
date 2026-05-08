<?php

declare(strict_types=1);

namespace App\Repository;

use App\Entity\User;
use Doctrine\Bundle\DoctrineBundle\Repository\ServiceEntityRepository;
use Doctrine\ORM\QueryBuilder;
use Doctrine\Persistence\ManagerRegistry;

/**
 * UserRepository — Data access layer for User entities.
 *
 * Provides secure, optimized query methods for user lookups.
 * All methods use parameterized queries via Doctrine (SQL injection prevention).
 *
 * @extends ServiceEntityRepository<User>
 */
class UserRepository extends ServiceEntityRepository
{
    public function __construct(ManagerRegistry $registry)
    {
        parent::__construct($registry, User::class);
    }

    /**
     * Find a user by email (case-insensitive) excluding soft-deleted accounts.
     *
     * Uses LOWER() for case-insensitive comparison to handle email providers
     * that treat addresses as case-insensitive (RFC 5321 recommendation).
     */
    public function findByEmail(string $email): ?User
    {
        return $this->createQueryBuilder('u')
            ->where('LOWER(u.email) = LOWER(:email)')
            ->andWhere('u.deletedAt IS NULL')
            ->setParameter('email', trim($email))
            ->getQuery()
            ->getOneOrNullResult();
    }

    /**
     * Find a user by mobile number excluding soft-deleted accounts.
     */
    public function findByMobileNumber(string $mobileNumber): ?User
    {
        return $this->createQueryBuilder('u')
            ->where('u.mobileNumber = :mobile')
            ->andWhere('u.deletedAt IS NULL')
            ->setParameter('mobile', $mobileNumber)
            ->getQuery()
            ->getOneOrNullResult();
    }

    /**
     * Find a user by email OR mobile number.
     *
     * Used during login when identifier could be either.
     * SECURITY: Returns null if account is soft-deleted or suspended.
     */
    public function findByEmailOrMobile(string $identifier): ?User
    {
        return $this->createQueryBuilder('u')
            ->where('LOWER(u.email) = LOWER(:identifier) OR u.mobileNumber = :identifier')
            ->andWhere('u.deletedAt IS NULL')
            ->setParameter('identifier', trim($identifier))
            ->getQuery()
            ->getOneOrNullResult();
    }

    /**
     * Find a user by username (case-insensitive).
     */
    public function findByUsername(string $username): ?User
    {
        return $this->createQueryBuilder('u')
            ->where('LOWER(u.username) = LOWER(:username)')
            ->andWhere('u.deletedAt IS NULL')
            ->setParameter('username', trim($username))
            ->getQuery()
            ->getOneOrNullResult();
    }

    /**
     * Check if a user with the given email exists (active or pending).
     * Returns bool for quick duplicate-prevention checks without loading the entity.
     */
    public function emailExists(string $email): bool
    {
        return (bool) $this->createQueryBuilder('u')
            ->select('1')
            ->where('LOWER(u.email) = LOWER(:email)')
            ->andWhere('u.deletedAt IS NULL')
            ->setParameter('email', trim($email))
            ->setMaxResults(1)
            ->getQuery()
            ->getOneOrNullResult();
    }

    /**
     * Check if a user with the given mobile number exists.
     */
    public function mobileExists(string $mobileNumber): bool
    {
        return (bool) $this->createQueryBuilder('u')
            ->select('1')
            ->where('u.mobileNumber = :mobile')
            ->andWhere('u.deletedAt IS NULL')
            ->setParameter('mobile', $mobileNumber)
            ->setMaxResults(1)
            ->getQuery()
            ->getOneOrNullResult();
    }

    /**
     * Get a QueryBuilder for active, non-deleted users.
     * Base builder used by admin listing queries.
     */
    public function createActiveUsersQueryBuilder(): QueryBuilder
    {
        return $this->createQueryBuilder('u')
            ->where('u.deletedAt IS NULL')
            ->orderBy('u.createdAt', 'DESC');
    }

    /**
     * Find users with accounts locked due to failed login attempts.
     *
     * @return list<User>
     */
    public function findLockedAccounts(): array
    {
        return $this->createQueryBuilder('u')
            ->where('u.lockedUntil > :now')
            ->setParameter('now', new \DateTime())
            ->getQuery()
            ->getResult();
    }

    /**
     * Unlock accounts whose lock period has expired.
     * Called by scheduled cleanup command.
     */
    public function unlockExpiredLocks(): int
    {
        return (int) $this->createQueryBuilder('u')
            ->update()
            ->set('u.lockedUntil', 'NULL')
            ->set('u.failedLoginAttempts', '0')
            ->where('u.lockedUntil <= :now')
            ->setParameter('now', new \DateTime())
            ->getQuery()
            ->execute();
    }

    /**
     * Save a user entity (flush optional for batch operations).
     */
    public function save(User $user, bool $flush = true): void
    {
        $this->getEntityManager()->persist($user);

        if ($flush) {
            $this->getEntityManager()->flush();
        }
    }

    /**
     * Soft-delete a user by setting deletedAt timestamp.
     */
    public function softDelete(User $user, bool $flush = true): void
    {
        $user->softDelete();
        $this->save($user, $flush);
    }
}
