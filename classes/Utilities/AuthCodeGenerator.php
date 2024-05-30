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
 * Class AuthCodeGenerator
 *
 * @package Sendcloud\PrestaShop\Classes\Utilities
 */
class AuthCodeGenerator
{
    /**
     * Generates random code which will be used for authorization purposes
     *
     * @param $length
     *
     * @return string
     */
    public static function generate($length)
    {
        $chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';

        return substr(str_shuffle($chars), 0, $length);
    }
}
