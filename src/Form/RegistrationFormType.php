<?php

declare(strict_types=1);

namespace App\Form;

use App\DTO\RegistrationDTO;
use App\Validator\StrongPassword;
use Symfony\Component\Form\AbstractType;
use Symfony\Component\Form\Extension\Core\Type\CheckboxType;
use Symfony\Component\Form\Extension\Core\Type\EmailType;
use Symfony\Component\Form\Extension\Core\Type\PasswordType;
use Symfony\Component\Form\Extension\Core\Type\RepeatedType;
use Symfony\Component\Form\Extension\Core\Type\TelType;
use Symfony\Component\Form\Extension\Core\Type\TextType;
use Symfony\Component\Form\FormBuilderInterface;
use Symfony\Component\OptionsResolver\OptionsResolver;
use Symfony\Component\Validator\Constraints as Assert;

/**
 * RegistrationFormType — Symfony form for user registration.
 *
 * Maps to RegistrationDTO. CSRF protection is enabled by default.
 */
class RegistrationFormType extends AbstractType
{
    public function buildForm(FormBuilderInterface $builder, array $options): void
    {
        $builder
            ->add('firstName', TextType::class, [
                'label' => 'First Name',
                'attr' => [
                    'placeholder' => 'John',
                    'autocomplete' => 'given-name',
                    'class' => 'form-control',
                ],
            ])
            ->add('middleName', TextType::class, [
                'label' => 'Middle Name',
                'required' => false,
                'attr' => [
                    'placeholder' => 'Optional',
                    'autocomplete' => 'additional-name',
                    'class' => 'form-control',
                ],
            ])
            ->add('lastName', TextType::class, [
                'label' => 'Last Name',
                'attr' => [
                    'placeholder' => 'Doe',
                    'autocomplete' => 'family-name',
                    'class' => 'form-control',
                ],
            ])
            ->add('email', EmailType::class, [
                'label' => 'Email Address',
                'attr' => [
                    'placeholder' => 'you@example.com',
                    'autocomplete' => 'email',
                    'class' => 'form-control',
                ],
            ])
            ->add('mobileNumber', TelType::class, [
                'label' => 'Mobile Number',
                'required' => false,
                'attr' => [
                    'placeholder' => '+14155552671',
                    'autocomplete' => 'tel',
                    'class' => 'form-control',
                ],
            ])
            ->add('password', RepeatedType::class, [
                'type' => PasswordType::class,
                'invalid_message' => 'The passwords do not match.',
                'first_options' => [
                    'label' => 'Password',
                    'attr' => [
                        'placeholder' => 'Min 8 characters',
                        'autocomplete' => 'new-password',
                        'class' => 'form-control',
                    ],
                    'constraints' => [
                        new Assert\NotBlank(['message' => 'Password is required.']),
                        new StrongPassword(),
                    ],
                ],
                'second_options' => [
                    'label' => 'Confirm Password',
                    'attr' => [
                        'placeholder' => 'Repeat password',
                        'autocomplete' => 'new-password',
                        'class' => 'form-control',
                    ],
                ],
                'mapped' => false,  // Handle separately in controller
            ])
            ->add('agreeTerms', CheckboxType::class, [
                'label' => 'I agree to the Terms of Service and Privacy Policy',
                'mapped' => false,
                'constraints' => [
                    new Assert\IsTrue(['message' => 'You must accept the Terms & Conditions.']),
                ],
                'attr' => ['class' => 'form-check-input'],
            ]);
    }

    public function configureOptions(OptionsResolver $resolver): void
    {
        $resolver->setDefaults([
            'data_class' => null,   // We handle mapping manually in the controller
            'csrf_protection' => true,
            'csrf_field_name' => '_csrf_token',
            'csrf_token_id' => 'registration',
        ]);
    }
}
