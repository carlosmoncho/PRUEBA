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

use Sendcloud\PrestaShop\Classes\Bootstrap\ServiceRegister;
use Sendcloud\PrestaShop\Classes\DTO\AuthorizationObject;
use Sendcloud\PrestaShop\Classes\Exceptions\InvalidPayloadException;
use Sendcloud\PrestaShop\Classes\Interfaces\ColumnNamesInterface;
use Sendcloud\PrestaShop\Classes\Services\ConfigService;
use Sendcloud\PrestaShop\Classes\Utilities\Base64UrlEncoder;

if (!defined('_PS_VERSION_')) {
    exit;
}

/**
 * Class OauthAuthorizeValidator
 *
 * @package Sendcloud\PrestaShop\Classes\Services\Validators
 */
class OauthAuthorizeValidator
{
    const GRANT_TYPE = 'authorization_code';

    /**
     * Validates payload request
     *
     * @param array $requestData
     * @param string $module
     * @param array $postData
     *
     * @return void
     * @throws InvalidPayloadException
     */
    public static function verifyPayload($requestData, $module, $postData)
    {
        $dataExist = self::dataExist($requestData);
        $isDataValid = self::isDataValid($module, $requestData, $postData);
        $isFormDataValid = self::checkPostData($postData);
        $isCodeValid = self::checkAuthorizationCode($postData);
        $isCodeChallengeValid = self::checkCodeChallenge($postData);

        if (!$dataExist || !$isDataValid || !$isFormDataValid || !$isCodeValid || !$isCodeChallengeValid) {
            throw new InvalidPayloadException('Invalid request.');
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
        return isset($requestData['module']);
    }

    /**
     * Checks form parameters
     *
     * @param $postRequest
     *
     * @return bool
     */
    private static function checkPostData($postRequest)
    {
        return isset($postRequest['code'])
            && isset($postRequest['client_id'])
            && isset($postRequest['grant_type'])
            && isset($postRequest['code_verifier']);
    }

    /**
     * Checks if request data is valid
     *
     * @param $module
     * @param $requestData
     *
     * @return bool
     */
    private static function isDataValid($module, $requestData, $postData)
    {
        $isModuleValid = $requestData['module'] === $module;
        $isGrantTypeValid = $postData['grant_type'] === self::GRANT_TYPE;

        return $isModuleValid && $isGrantTypeValid;
    }

    /**
     * Validates if authorization code is the same as the one saved during connect request
     *
     * @param array $postData
     *
     * @return bool
     */
    private static function checkAuthorizationCode($postData)
    {
        /** @var string $authObject */
        $authObject = self::getConfigService()->getConfigValue(ColumnNamesInterface::AUTH_PARAMS);

        if (!$authObject) {
            return false;
        }
        $code = (AuthorizationObject::fromArray(json_decode($authObject, true)))->getAuthCode();

        return $code === $postData['code'];
    }

    /**
     * Validates if code_verifier is the same as the sha256 computed code_challenge
     *
     * @param array $postData
     *
     * @return bool
     */
    private static function checkCodeChallenge($postData)
    {
        /** @var string $authObject */
        $authObject = self::getConfigService()->getConfigValue(ColumnNamesInterface::AUTH_PARAMS);
        $codeChallenge = (AuthorizationObject::fromArray(json_decode($authObject, true)))->getCodeChallenge();
        $computedCodeChallenge = Base64UrlEncoder::encode(hash('sha256', $postData['code_verifier'], true));

        return $codeChallenge === $computedCodeChallenge;
    }

    /**
     * @return ConfigService
     */
    private static function getConfigService()
    {
        return ServiceRegister::getService(ConfigService::class);
    }
}
