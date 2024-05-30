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
 * Class ApiResourcesInterface
 *
 * @package Sendcloud\PrestaShop\Classes\Interfaces
 */
interface ApiResourcesInterface
{
    /**
     * Default API permissions used by Sendcloud. It __MUST__ use the following
     *  format:
     *
     *  Example: ```
     *  array(
     *   '<permission_name>': array(  // e.g: addresses, customers
     *       '<method_name>': 'on' // e.g: GET, POST, PUT, DELETE
     *   )
     *  );
     *  ```
     */
    const API_RESOURCES = [
        'addresses',
        'carriers',
        'currencies',
        'configurations',
        'countries',
        'customers',
        'languages',
        'order_details',
        'order_states',
        'orders',
        'products',
        'states',
        'combinations',
        'images',
        'product_features',
        'product_feature_values'
    ];
}
