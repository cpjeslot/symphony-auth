<?php

declare(strict_types=1);

namespace App\Controller\Admin;

use App\Entity\SecurityAuditLog;
use App\Enum\AuditEventType;
use EasyCorp\Bundle\EasyAdminBundle\Controller\AbstractCrudController;
use EasyCorp\Bundle\EasyAdminBundle\Field\AssociationField;
use EasyCorp\Bundle\EasyAdminBundle\Field\DateTimeField;
use EasyCorp\Bundle\EasyAdminBundle\Field\IdField;
use EasyCorp\Bundle\EasyAdminBundle\Field\TextField;
use EasyCorp\Bundle\EasyAdminBundle\Field\ChoiceField;
use EasyCorp\Bundle\EasyAdminBundle\Config\Action;
use EasyCorp\Bundle\EasyAdminBundle\Config\Actions;

class SecurityAuditLogCrudController extends AbstractCrudController
{
    public static function getEntityFqcn(): string
    {
        return SecurityAuditLog::class;
    }

    public function configureActions(Actions $actions): Actions
    {
        return $actions
            ->disable(Action::NEW, Action::EDIT, Action::DELETE)
            ->add(Action::INDEX, Action::DETAIL);
    }

    public function configureFields(string $pageName): iterable
    {
        yield IdField::new('id')->hideOnForm();
        yield DateTimeField::new('createdAt');
        yield ChoiceField::new('eventType')
            ->setChoices(AuditEventType::cases())
            ->formatValue(fn ($value) => $value instanceof \BackedEnum ? $value->value : $value);
        yield ChoiceField::new('severity')
            ->setChoices([
                'Info' => 'info',
                'Warning' => 'warning',
                'Error' => 'error',
            ])
            ->renderAsBadges([
                'info' => 'info',
                'warning' => 'warning',
                'error' => 'danger',
            ]);
        yield TextField::new('ipAddress');
        yield AssociationField::new('user');
        yield TextField::new('userAgent')->hideOnIndex();
    }
}
