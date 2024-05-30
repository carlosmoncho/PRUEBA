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

namespace Sendcloud\PrestaShop\Classes\Services\Validators;

use Sendcloud\PrestaShop\Classes\Exceptions\InvalidPayloadException;

if (!defined('_PS_VERSION_')) {
    exit;
}

/**
 * Class OauthConnectValidator
 *
 * @package Sendcloud\PrestaShop\Classes\Services\Validators
 */
class OauthConnectValidator
{
    const RESPONSE_TYPE = 'code';
    const SCOPE = 'api';

    /**
     * Validates payload request
     *
     * @param $requestData
     * @param $module
     *
     * @return void
     * @throws InvalidPayloadException
     */
    public static function verifyPayload($requestData, $module)
    {
        $dataExist = self::dataExist($requestData);
        $dataIsValid = self::isDataValid($module, $requestData);

        if (!$dataExist || !$dataIsValid) {
            throw new InvalidPayloadException('Invalid payload data.');
        }
    }

    /**
     * Checks if all parameters exist in the request
     *
     * @param $requestData
     *
     * @return bool
     */
    private static function dataExist($requestData)
    {
        return isset($requestData['module'])
            && isset($requestData['redirect_uri'])
            && isset($requestData['response_type'])
            && isset($requestData['client_id'])
            && isset($requestData['scope'])
            && isset($requestData['state'])
            && isset($requestData['code_challenge'])
            && isset($requestData['code_challenge_method']);
    }

    /**
     * Checks if request data is valid
     *
     * @param $module
     * @param $requestData
     *
     * @return bool
     */
    private static function isDataValid($module, $requestData)
    {
        $isModuleValid = $requestData['module'] === $module;
        $isResponseTypeValid = $requestData['response_type'] === self::RESPONSE_TYPE;
        $isScopeValid = $requestData['scope'] === self::SCOPE;

        return $isModuleValid && $isResponseTypeValid && $isScopeValid;
    }
}
