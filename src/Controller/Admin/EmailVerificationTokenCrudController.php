<?php

declare(strict_types=1);

namespace App\Controller\Admin;

use App\Entity\EmailVerificationToken;
use EasyCorp\Bundle\EasyAdminBundle\Controller\AbstractCrudController;
use EasyCorp\Bundle\EasyAdminBundle\Field\BooleanField;
use EasyCorp\Bundle\EasyAdminBundle\Field\DateTimeField;
use EasyCorp\Bundle\EasyAdminBundle\Field\IdField;
use EasyCorp\Bundle\EasyAdminBundle\Field\TextField;
use EasyCorp\Bundle\EasyAdminBundle\Field\AssociationField;
use EasyCorp\Bundle\EasyAdminBundle\Field\EmailField;

class EmailVerificationTokenCrudController extends AbstractCrudController
{
    public static function getEntityFqcn(): string
    {
        return EmailVerificationToken::class;
    }

    public function configureFields(string $pageName): iterable
    {
        yield IdField::new('id')->hideOnForm();
        yield AssociationField::new('user');
        yield EmailField::new('email');
        yield DateTimeField::new('expiresAt');
        yield BooleanField::new('isUsed');
        yield DateTimeField::new('verifiedAt');
        yield DateTimeField::new('createdAt')->hideOnForm();
    }
}
