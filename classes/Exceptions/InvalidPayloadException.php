<?php
/**
 * Utility class for SendCloud module.
 *
 * PHP version 7.4
 *
 *  @author    SendCloud Global B.V. <contact@sendcloud.eu>
 *  @copyright 2023 SendCloud Global B.V.
 *  @license   http://opensource.org/licenses/afl-3.0.php  Academic Free License (AFL 3.0)
 *
 *  @category  Shipping
 *
 *  @see      https://sendcloud.eu
 */

namespace Sendcloud\PrestaShop\Classes\Exceptions;

use PrestaShop\PrestaShop\Adapter\Entity\PrestaShopModuleException;

if (!defined('_PS_VERSION_')) {
    exit;
}

/**
 * Class InvalidPayloadException
 *
 * @package Sendcloud\PrestaShop\Classes\Exceptions
 */
class InvalidPayloadException extends PrestaShopModuleException
{
}
