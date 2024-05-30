<?php
/**
 * Utility class for SendCloud module.
 *
 * PHP version 7.4
 *
 * @author    SendCloud Global B.V. <contact@sendcloud.eu>
 * @copyright 2023 SendCloud Global B.V.
 * @license   http://opensource.org/licenses/afl-3.0.php  Academic Free License (AFL 3.0)
 *
 * @category  Shipping
 *
 * @see      https://sendcloud.eu
 */

namespace Sendcloud\PrestaShop\Classes\Interfaces;

if (!defined('_PS_VERSION_')) {
    exit;
}

/**
 * Class HooksInterface
 *
 * @package Sendcloud\PrestaShop\Classes\Interfaces
 */
interface HooksInterface
{
    const HOOKS = [
        'actionValidateOrder',
        'actionObjectAddAfter',
        'actionCarrierUpdate',
        'actionProductUpdate',
        'actionObjectOrderUpdateAfter',
        'actionEmailAddAfterContent',
        'displayHeader',
        'displayCarrierExtraContent',
        'displayBeforeCarrier',
        'displayOrderConfirmation',
        'displayAdminOrderMain',
        'displayAdminProductsMainStepLeftColumnMiddle',
        'displayAdminProductsExtra'
    ];
}
