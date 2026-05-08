<?php

declare(strict_types=1);

namespace App\Controller\Admin;

use App\Entity\PasswordResetToken;
use EasyCorp\Bundle\EasyAdminBundle\Controller\AbstractCrudController;
use EasyCorp\Bundle\EasyAdminBundle\Field\BooleanField;
use EasyCorp\Bundle\EasyAdminBundle\Field\DateTimeField;
use EasyCorp\Bundle\EasyAdminBundle\Field\IdField;
use EasyCorp\Bundle\EasyAdminBundle\Field\TextField;
use EasyCorp\Bundle\EasyAdminBundle\Field\AssociationField;

class PasswordResetTokenCrudController extends AbstractCrudController
{
    public static function getEntityFqcn(): string
    {
        return PasswordResetToken::class;
    }

    public function configureFields(string $pageName): iterable
    {
        yield IdField::new('id')->hideOnForm();
        yield AssociationField::new('user');
        yield DateTimeField::new('expiresAt');
        yield BooleanField::new('isUsed');
        yield TextField::new('requestIp');
        yield DateTimeField::new('usedAt');
        yield DateTimeField::new('createdAt')->hideOnForm();
    }
}
