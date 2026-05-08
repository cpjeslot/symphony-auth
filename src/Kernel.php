<?php

declare(strict_types=1);

namespace App;

use Symfony\Bundle\FrameworkBundle\Kernel\MicroKernelTrait;
use Symfony\Component\HttpKernel\Kernel as BaseKernel;

/**
 * Application Kernel.
 *
 * Entry point for the Symfony application. Registers all bundles
 * and configures the container using MicroKernelTrait.
 */
class Kernel extends BaseKernel
{
    use MicroKernelTrait;
}
