<?php

declare(strict_types=1);

namespace App\Controller\Admin;

use App\Entity\ActiveSession;
use EasyCorp\Bundle\EasyAdminBundle\Controller\AbstractCrudController;
use EasyCorp\Bundle\EasyAdminBundle\Field\BooleanField;
use EasyCorp\Bundle\EasyAdminBundle\Field\DateTimeField;
use EasyCorp\Bundle\EasyAdminBundle\Field\IdField;
use EasyCorp\Bundle\EasyAdminBundle\Field\TextField;
use EasyCorp\Bundle\EasyAdminBundle\Field\AssociationField;

class ActiveSessionCrudController extends AbstractCrudController
{
    public static function getEntityFqcn(): string
    {
        return ActiveSession::class;
    }

    public function configureFields(string $pageName): iterable
    {
        yield IdField::new('id')->hideOnForm();
        yield AssociationField::new('user');
        yield TextField::new('deviceDescription');
        yield TextField::new('ipAddress');
        yield DateTimeField::new('expiresAt');
        yield DateTimeField::new('lastActivityAt');
        yield BooleanField::new('isRevoked');
        yield DateTimeField::new('createdAt')->hideOnForm();
    }
}
