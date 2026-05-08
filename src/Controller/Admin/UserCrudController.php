<?php

declare(strict_types=1);

namespace App\Controller\Admin;

use App\Entity\User;
use App\Enum\AccountStatus;
use App\Enum\BloodGroup;
use App\Enum\Gender;
use App\Enum\MaritalStatus;
use EasyCorp\Bundle\EasyAdminBundle\Attribute\AdminRoute;
use EasyCorp\Bundle\EasyAdminBundle\Config\Action;
use EasyCorp\Bundle\EasyAdminBundle\Config\Actions;
use EasyCorp\Bundle\EasyAdminBundle\Config\Crud;
use EasyCorp\Bundle\EasyAdminBundle\Context\AdminContext;
use EasyCorp\Bundle\EasyAdminBundle\Controller\AbstractCrudController;
use EasyCorp\Bundle\EasyAdminBundle\Field\ArrayField;
use EasyCorp\Bundle\EasyAdminBundle\Field\ChoiceField;
use EasyCorp\Bundle\EasyAdminBundle\Field\DateTimeField;
use EasyCorp\Bundle\EasyAdminBundle\Field\EmailField;
use EasyCorp\Bundle\EasyAdminBundle\Field\IdField;
use EasyCorp\Bundle\EasyAdminBundle\Field\TextField;
use EasyCorp\Bundle\EasyAdminBundle\Router\AdminUrlGenerator;
use Symfony\Component\HttpFoundation\Response;

class UserCrudController extends AbstractCrudController
{
    public function __construct(
        private AdminUrlGenerator $adminUrlGenerator
    ) {}

    public static function getEntityFqcn(): string
    {
        return User::class;
    }

    public function configureActions(Actions $actions): Actions
    {
        $verifyUser = Action::new('verifyUser', 'Verify Email', 'fa fa-check-circle')
            ->linkToCrudAction('verifyUser')
            ->addCssClass('btn btn-success')
            ->displayIf(fn (User $user) => !$user->isEmailVerified());

        $suspendUser = Action::new('suspendUser', 'Suspend', 'fa fa-ban')
            ->linkToCrudAction('suspendUser')
            ->addCssClass('btn btn-danger')
            ->displayIf(fn (User $user) => $user->getAccountStatus() === AccountStatus::Active);

        $activateUser = Action::new('activateUser', 'Activate', 'fa fa-check')
            ->linkToCrudAction('activateUser')
            ->addCssClass('btn btn-success')
            ->displayIf(fn (User $user) => $user->getAccountStatus() !== AccountStatus::Active);

        return $actions
            ->add(Crud::PAGE_INDEX, $verifyUser)
            ->add(Crud::PAGE_INDEX, $suspendUser)
            ->add(Crud::PAGE_INDEX, $activateUser)
            ->add(Crud::PAGE_DETAIL, $verifyUser)
            ->add(Crud::PAGE_DETAIL, $suspendUser)
            ->add(Crud::PAGE_DETAIL, $activateUser);
    }

    public function configureFields(string $pageName): iterable
    {
        yield IdField::new('id')->hideOnForm();
        yield EmailField::new('email');
        yield TextField::new('firstName');
        yield TextField::new('lastName');
        yield ChoiceField::new('accountStatus')
            ->setChoices([
                'Active' => AccountStatus::Active,
                'Suspended' => AccountStatus::Suspended,
                'Pending Verification' => AccountStatus::PendingVerification,
                'Deactivated' => AccountStatus::Deactivated,
                'Banned' => AccountStatus::Banned,
            ])
            ->renderAsBadges([
                AccountStatus::Active->value => 'success',
                AccountStatus::Suspended->value => 'warning',
                AccountStatus::PendingVerification->value => 'info',
                AccountStatus::Deactivated->value => 'secondary',
                AccountStatus::Banned->value => 'danger',
            ])
            ->formatValue(fn ($value) => $value instanceof \BackedEnum ? $value->value : $value);
        yield ChoiceField::new('gender')
            ->setChoices(Gender::cases())
            ->formatValue(fn ($value) => $value instanceof \BackedEnum ? $value->value : $value)
            ->hideOnIndex();
        yield ChoiceField::new('maritalStatus')
            ->setChoices(MaritalStatus::cases())
            ->formatValue(fn ($value) => $value instanceof \BackedEnum ? $value->value : $value)
            ->hideOnIndex();
        yield ChoiceField::new('bloodGroup')
            ->setChoices(BloodGroup::cases())
            ->formatValue(fn ($value) => $value instanceof \BackedEnum ? $value->value : $value)
            ->hideOnIndex();
        yield ArrayField::new('roles');
        yield DateTimeField::new('createdAt')->hideOnForm();
    }

    #[AdminRoute(path: '/verify-user', name: 'verify_user')]
    public function verifyUser(AdminContext $context): Response
    {
        $user = $context->getEntity()->getInstance();
        if (!$user instanceof User) {
            throw new \RuntimeException('Invalid user instance');
        }

        $user->setEmailVerified(true);
        $this->container->get('doctrine')->getManager()->flush();

        $this->addFlash('success', sprintf('User %s has been verified.', $user->getEmail()));

        return $this->redirect($this->adminUrlGenerator
            ->setController(self::class)
            ->setAction(Action::INDEX)
            ->generateUrl());
    }

    #[AdminRoute(path: '/suspend-user', name: 'suspend_user')]
    public function suspendUser(AdminContext $context): Response
    {
        $user = $context->getEntity()->getInstance();
        if (!$user instanceof User) {
            throw new \RuntimeException('Invalid user instance');
        }

        $user->setAccountStatus(AccountStatus::Suspended);
        $this->container->get('doctrine')->getManager()->flush();

        $this->addFlash('warning', sprintf('User %s has been suspended.', $user->getEmail()));

        return $this->redirect($this->adminUrlGenerator
            ->setController(self::class)
            ->setAction(Action::INDEX)
            ->generateUrl());
    }

    #[AdminRoute(path: '/activate-user', name: 'activate_user')]
    public function activateUser(AdminContext $context): Response
    {
        $user = $context->getEntity()->getInstance();
        if (!$user instanceof User) {
            throw new \RuntimeException('Invalid user instance');
        }

        $user->setAccountStatus(AccountStatus::Active);
        $this->container->get('doctrine')->getManager()->flush();

        $this->addFlash('success', sprintf('User %s has been activated.', $user->getEmail()));

        return $this->redirect($this->adminUrlGenerator
            ->setController(self::class)
            ->setAction(Action::INDEX)
            ->generateUrl());
    }
}
