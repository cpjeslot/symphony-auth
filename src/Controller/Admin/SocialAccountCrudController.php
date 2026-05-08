<?php

declare(strict_types=1);

namespace App\Controller\Admin;

use App\Entity\SocialAccount;
use EasyCorp\Bundle\EasyAdminBundle\Controller\AbstractCrudController;
use EasyCorp\Bundle\EasyAdminBundle\Field\DateTimeField;
use EasyCorp\Bundle\EasyAdminBundle\Field\IdField;
use EasyCorp\Bundle\EasyAdminBundle\Field\TextField;
use EasyCorp\Bundle\EasyAdminBundle\Field\AssociationField;
use EasyCorp\Bundle\EasyAdminBundle\Field\EmailField;

class SocialAccountCrudController extends AbstractCrudController
{
    public static function getEntityFqcn(): string
    {
        return SocialAccount::class;
    }

    public function configureFields(string $pageName): iterable
    {
        yield IdField::new('id')->hideOnForm();
        yield AssociationField::new('user');
        yield TextField::new('provider');
        yield TextField::new('providerUserId');
        yield EmailField::new('providerEmail');
        yield TextField::new('providerName');
        yield DateTimeField::new('createdAt')->hideOnForm();
    }
}
