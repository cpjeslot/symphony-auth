<?php

declare(strict_types=1);

namespace App\Command;

use App\Entity\User;
use App\Enum\AccountStatus;
use App\Repository\UserRepository;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;

/**
 * CreateAdminCommand — Initial system setup command.
 *
 * Creates the first super-admin account for the system.
 */
#[AsCommand(
    name: 'app:create-admin',
    description: 'Creates an initial admin user for the system.',
)]
class CreateAdminCommand extends Command
{
    protected function configure(): void
    {
        $this
            ->addArgument('email', \Symfony\Component\Console\Input\InputArgument::OPTIONAL, 'Admin email')
            ->addArgument('password', \Symfony\Component\Console\Input\InputArgument::OPTIONAL, 'Admin password');
    }
    public function __construct(
        private readonly UserRepository $userRepository,
        private readonly UserPasswordHasherInterface $passwordHasher,
    ) {
        parent::__construct();
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);

        $io->title('Enterprise Auth System — Admin Creation');

        $email = $input->getArgument('email') ?? $io->ask('Admin Email', 'admin@example.com');
        $firstName = $io->ask('First Name', 'System');
        $lastName = $io->ask('Last Name', 'Admin');
        
        $password = $input->getArgument('password') ?? $io->askHidden('Password (must be strong)');
        if (strlen($password) < 8) {
            $io->error('Password too short. Minimum 8 characters.');
            return Command::FAILURE;
        }

        if ($this->userRepository->emailExists($email)) {
            $io->error(sprintf('User with email %s already exists.', $email));
            return Command::FAILURE;
        }

        $user = new User();
        $user->setEmail($email);
        $user->setFirstName($firstName);
        $user->setLastName($lastName);
        $user->setRoles(['ROLE_ADMIN']);
        $user->setAccountStatus(AccountStatus::Active);
        $user->setEmailVerified(true);

        $user->setPasswordHash(
            $this->passwordHasher->hashPassword($user, $password)
        );

        $this->userRepository->save($user);

        $io->success(sprintf('Admin user %s created successfully!', $email));
        $io->note('You can now log in at /auth/login and access the admin panel at /admin.');

        return Command::SUCCESS;
    }
}
