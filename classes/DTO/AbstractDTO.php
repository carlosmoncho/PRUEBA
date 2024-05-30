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

namespace Sendcloud\PrestaShop\Classes\DTO;

if (!defined('_PS_VERSION_')) {
    exit;
}

/**
 * Class AbstractDTO
 *
 * @package Sendcloud\PrestaShop\Classes\DTO
 */
abstract class AbstractDTO
{
    /**
     * @param $search
     * @param $key
     * @param $default
     *
     * @return mixed
     */
    protected static function getValue($search, $key, $default = '')
    {
        return array_key_exists($key, $search) ? $search[$key] : $default;
    }
}
