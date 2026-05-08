<?php

declare(strict_types=1);

namespace App\Controller\Admin;

use App\Entity\LoginHistory;
use EasyCorp\Bundle\EasyAdminBundle\Controller\AbstractCrudController;
use EasyCorp\Bundle\EasyAdminBundle\Field\AssociationField;
use EasyCorp\Bundle\EasyAdminBundle\Field\BooleanField;
use EasyCorp\Bundle\EasyAdminBundle\Field\DateTimeField;
use EasyCorp\Bundle\EasyAdminBundle\Field\IdField;
use EasyCorp\Bundle\EasyAdminBundle\Field\TextField;
use EasyCorp\Bundle\EasyAdminBundle\Config\Action;
use EasyCorp\Bundle\EasyAdminBundle\Config\Actions;

class LoginHistoryCrudController extends AbstractCrudController
{
    public static function getEntityFqcn(): string
    {
        return LoginHistory::class;
    }

    public function configureActions(Actions $actions): Actions
    {
        return $actions
            ->disable(Action::NEW, Action::EDIT, Action::DELETE)
            ->add(Action::INDEX, Action::DETAIL);
    }

    public function configureFields(string $pageName): iterable
    {
        yield IdField::new('id');
        yield DateTimeField::new('createdAt');
        yield AssociationField::new('user');
        yield BooleanField::new('success');
        yield TextField::new('ipAddress');
        yield TextField::new('userAgent')->hideOnIndex();
    }
}
