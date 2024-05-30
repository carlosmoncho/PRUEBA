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

namespace Sendcloud\PrestaShop\Classes\Services;

use PrestaShop\PrestaShop\Adapter\Entity\Shop;
use PrestaShop\PrestaShop\Adapter\Entity\Tools;
use PrestaShop\PrestaShop\Adapter\Entity\WebserviceKey;
use SendCloud\Infrastructure\Logger\Logger;
use Sendcloud\PrestaShop\Classes\Bootstrap\ServiceRegister;
use Sendcloud\PrestaShop\Classes\DTO\AuthorizationObject;
use Sendcloud\PrestaShop\Classes\Exceptions\MissingAPIKeyException;
use Sendcloud\PrestaShop\Classes\Interfaces\ApiResourcesInterface;
use Sendcloud\PrestaShop\Classes\Interfaces\ColumnNamesInterface;
use Sendcloud\PrestaShop\Classes\Interfaces\ModuleInterface;
use Sendcloud\PrestaShop\Classes\Utilities\AuthCodeGenerator;

if (!defined('_PS_VERSION_')) {
    exit;
}

/**
 * Class AuthService
 *
 * @package Sendcloud\PrestaShop\Classes\Services
 */
class AuthService
{
    const AUTH_CODE_LENGTH = 16;

    /**
     * @var ConfigService
     */
    private $configService;
    /**
     * @var ConnectService
     */
    private $connectService;
    /**
     * @var ApiWebService
     */
    private $apiWebService;

    /**
     * Saves authorization data to the database
     *
     * @param string $codeChallenge
     *
     * @return string
     */
    public function saveAuthorizationData($codeChallenge)
    {
        $code = $this->generateAuthorizationCode();
        $this->getConfigService()->saveConfigValue(ColumnNamesInterface::AUTH_PARAMS, $this->createAuthorizationObject($code, $codeChallenge));

        return $code;
    }

    /**
     * Generates redirect authorization url
     *
     * @param string $redirectUri
     * @param string $code
     * @param string $state
     *
     * @return string
     */
    public function generateRedirectUrl($redirectUri, $code, $state)
    {
        return rtrim($redirectUri, '/') . '?code=' . $code . '&state=' . $state;
    }

    /**
     * Activate the WebService feature of PrestaShop, creates or updates the required
     * API credentials related to the Sendcloud connection _for the current shop_
     * and redirect to Sendcloud panel to connect with the newly created settings.
     *
     * If an existing API account is already created, it will be updated with a new
     * API key and the connection in the Sendcloud Panel updated accordingly.
     *
     * @return WebserviceKey new or updated connection data, including latest key/id
     *
     * @throws MissingAPIKeyException
     * @throws \PrestaShopDatabaseException
     * @throws \PrestaShopException
     * @throws \Exception
     */
    public function completeOAuth()
    {
        $connectSettings = $this->getConnectService()->fetchConnectSettings();
        $apiKey = $this->getOrGenerateAPIKey();

        if (!$connectSettings['key'] && !$apiKey) {
            throw new MissingAPIKeyException();
        }
        $this->getApiWebService()->updateWebServiceFlag();

        $connectedShops = $connectSettings['shops'];
        $connectedShops[] = Shop::getContextShopID(false);

        $webServiceKey = $this->createWebServiceKey($connectSettings, $apiKey);

        $this->saveWebServiceKey($webServiceKey);

        $this->getApiWebService()->setPermissionForAccount($webServiceKey->id, $this->getAPIPermissions());
        $this->getConnectService()->saveOrUpdateConnectSettings($webServiceKey, $connectedShops);

        return $webServiceKey;
    }

    /**
     * Retrieves Prestashop API permissions
     *
     * @return array
     */
    public function getAPIPermissions()
    {
        $methods = [
            'GET' => 'on',
            'POST' => 'on',
            'PUT' => 'on',
            'DELETE' => 'on',
            'HEAD' => 'on',
        ];

        $permissions = [];
        foreach ($this->getApiResources() as $res) {
            $permissions[$res] = $methods;
        }

        return $permissions;
    }

    /**
     * @return string[]
     */
    public function getApiResources()
    {
        return ApiResourcesInterface::API_RESOURCES;
    }

    /**
     * Saves webservice key to the database
     *
     * @param WebserviceKey $webServiceKey
     *
     * @return void
     *
     * @throws \Exception
     */
    private function saveWebServiceKey($webServiceKey)
    {
        try {
            if ($webServiceKey->id) {
                $webServiceKey->update();
            } else {
                $webServiceKey->add();
            }
        } catch (\Exception $ex) {
            //if $webserviceKey->id exists, it means that key was successfully saved and that error occurred as a result of
            // logging entity that does not exist when debug mode is enabled
            if (!$webServiceKey->id) {
                Logger::logError('Error occurred while adding webservice key. ' . $ex->getMessage());
                throw $ex;
            }
        }
    }

    /**
     * Generate new web service api key
     *
     * @param array $connectSettings
     * @param string $apiKey
     *
     * @return WebserviceKey
     * @throws \PrestaShopDatabaseException
     * @throws \PrestaShopException
     */
    private function createWebServiceKey($connectSettings, $apiKey)
    {
        $localizedDate = Tools::displayDate(date('Y-m-d H:i:s'), null, true);
        $webServiceTitle = sprintf('%s (%s)', 'SendCloud API Key', $localizedDate);

        $webServiceKey = new WebserviceKey($connectSettings['id']);
        $webServiceKey->description = $webServiceTitle;
        $webServiceKey->active = true;

        // Use the existing key *OR* grab the new one.
        $webServiceKey->key = $connectSettings['key'] ?: $apiKey;

        return $webServiceKey;
    }

    /**
     * Returns json encoded representation of the auth object
     *
     * @param string $code
     * @param string $codeChallenge
     *
     * @return string
     */
    private function createAuthorizationObject($code, $codeChallenge)
    {
        $authObject = new AuthorizationObject($code, $codeChallenge);

        return json_encode($authObject->toArray());
    }

    /**
     * Generates new API key
     *
     * @return string
     */
    private function getOrGenerateAPIKey()
    {
        $key = preg_replace('/\s\s*/im', '', Tools::getValue('new_key'));
        if (!empty($key)) {
            return $key;
        }

        $key = Tools::strtoupper(md5(rand() . time() . ModuleInterface::MODULE_NAME));
        $key = preg_replace('/[O0]/i', 'A', $key);

        return Tools::substr($key, 0, 32);
    }

    /**
     * Generates random string used as authorization code
     *
     * @return string
     */
    private function generateAuthorizationCode()
    {
        return AuthCodeGenerator::generate(self::AUTH_CODE_LENGTH);
    }

    /**
     * @return ConfigService
     */
    private function getConfigService()
    {
        if ($this->configService === null) {
            $this->configService = ServiceRegister::getService(ConfigService::class);
        }

        return $this->configService;
    }

    /**
     * @return ApiWebService
     */
    private function getApiWebService()
    {
        if ($this->apiWebService === null) {
            $this->apiWebService = ServiceRegister::getService(ApiWebService::class);
        }

        return $this->apiWebService;
    }

    /**
     * @return ConnectService
     */
    private function getConnectService()
    {
        if ($this->connectService === null) {
            $this->connectService = ServiceRegister::getService(ConnectService::class);
        }

        return $this->connectService;
    }
}
