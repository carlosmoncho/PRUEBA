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
 * Class SHA256SignatureGenerator
 *
 * @package Sendcloud\PrestaShop\Classes\Utilities
 */
class SHA256SignatureGenerator
{
    /**
     * @param string $apiKey
     * @param string $integrationId
     * @param array $payload
     *
     * @return string
     */
    public static function generateSignature($apiKey, $integrationId, $payload)
    {
        $encodedPayload = json_encode($payload);
        $message = "v1|{$integrationId}|{$encodedPayload}";

        return hash_hmac('sha512', $message, $apiKey);
    }
}
