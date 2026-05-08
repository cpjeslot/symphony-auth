<?php

declare(strict_types=1);

namespace App\Controller\Admin;

use App\Entity\User;
use EasyCorp\Bundle\EasyAdminBundle\Controller\AbstractCrudController;
use EasyCorp\Bundle\EasyAdminBundle\Field\ArrayField;
use EasyCorp\Bundle\EasyAdminBundle\Field\ChoiceField;
use EasyCorp\Bundle\EasyAdminBundle\Field\EmailField;
use EasyCorp\Bundle\EasyAdminBundle\Field\IdField;
use EasyCorp\Bundle\EasyAdminBundle\Field\TextField;
use EasyCorp\Bundle\EasyAdminBundle\Field\DateTimeField;
use App\Enum\AccountStatus;

class UserCrudController extends AbstractCrudController
{
    public static function getEntityFqcn(): string
    {
        return User::class;
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
                'Locked' => AccountStatus::Locked,
            ]);
        yield ArrayField::new('roles');
        yield DateTimeField::new('createdAt')->hideOnForm();
    }
}
