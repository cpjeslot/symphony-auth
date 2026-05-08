<?php

declare(strict_types=1);

namespace App\Controller\Admin;

use App\Entity\EmailOtp;
use EasyCorp\Bundle\EasyAdminBundle\Controller\AbstractCrudController;
use EasyCorp\Bundle\EasyAdminBundle\Field\BooleanField;
use EasyCorp\Bundle\EasyAdminBundle\Field\DateTimeField;
use EasyCorp\Bundle\EasyAdminBundle\Field\IdField;
use EasyCorp\Bundle\EasyAdminBundle\Field\IntegerField;
use EasyCorp\Bundle\EasyAdminBundle\Field\TextField;
use EasyCorp\Bundle\EasyAdminBundle\Field\AssociationField;

class EmailOtpCrudController extends AbstractCrudController
{
    public static function getEntityFqcn(): string
    {
        return EmailOtp::class;
    }

    public function configureFields(string $pageName): iterable
    {
        yield IdField::new('id')->hideOnForm();
        yield AssociationField::new('user');
        yield TextField::new('purpose');
        yield IntegerField::new('retryCount');
        yield BooleanField::new('isUsed');
        yield DateTimeField::new('expiresAt');
        yield DateTimeField::new('createdAt')->hideOnForm();
    }
}
