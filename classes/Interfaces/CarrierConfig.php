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
 * Class CarrierConfig
 *
 * @package Sendcloud\PrestaShop\Classes\Interfaces
 */
interface CarrierConfig
{
    const CARRIER_CONFIG = [
        'name' => 'Service Point Delivery',
        'id_tax_rules_group' => 0,
        'active' => true,
        'deleted' => false,
        'shipping_handling' => false,
        'range_behavior' => 0,
        'is_module' => true,
        'delay' => [
            'be' => 'Afhaalpuntevering',
            'de' => 'Paketshop Zustellung',
            'en' => 'Service Point Delivery',
            'es' => 'Recogida en punto de servicio',
            'fr' => 'Livraison en point service',
            'nl' => 'Afhaalpuntevering',
        ],
        'shipping_external' => true,
        'external_module_name' => null,
        'need_range' => true,
        'max_width' => 150,
        'max_height' => 150,
        'max_depth' => 150,
        'max_weight' => 0,  // Will be overriden by max($defaultWeightRange)
        'grade' => 4,
    ];
}
