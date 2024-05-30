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

namespace Sendcloud\PrestaShop\Classes\Utilities;

if (!defined('_PS_VERSION_')) {
    exit;
}

/**
 * Class Base64UrlEncoder
 *
 * @package Sendcloud\PrestaShop\Classes\Utilities
 */
class Base64UrlEncoder
{
    /**
     * @param $data
     *
     * @return string
     */
    public static function encode($data) {
        $base64 = base64_encode($data);
        $base64url = strtr($base64, '+/', '-_');

        return rtrim($base64url, '=');
    }
}
