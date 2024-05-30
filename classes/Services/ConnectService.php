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

namespace Sendcloud\PrestaShop\Classes\Services;

use PrestaShop\PrestaShop\Adapter\Entity\PrestaShopException;
use PrestaShop\PrestaShop\Adapter\Entity\Shop;
use PrestaShop\PrestaShop\Adapter\Entity\Tools;
use PrestaShop\PrestaShop\Adapter\Entity\WebserviceKey;
use Sendcloud\PrestaShop\Classes\Bootstrap\ServiceRegister;
use Sendcloud\PrestaShop\Classes\Interfaces\ColumnNamesInterface;
use Sendcloud\PrestaShop\Classes\Utilities\UtilityTools;

if (!defined('_PS_VERSION_')) {
    exit;
}

/**
 * Class ConnectService
 *
 * @package Sendcloud\PrestaShop\Classes\Services
 */
class ConnectService
{
    /**
     * @var array $connectSettings
     */
    private $connectSettings;
    /**
     * @var ConfigService
     */
    private $configService;
    /**
     * @var ApiWebService
     */
    private $apiWebService;

    /**
     * Retrieve connection url
     *
     * @param $shop
     *
     * @return string
     */
    public function getConnectUrl($shop)
    {
        $queryParams = [
            'url_webshop' => $this->formatUrl($shop->getBaseURL(true)),
            'shop_name' => $shop->name,
            'shop_id' => $shop->id
        ];

        return UtilityTools::getPanelURL('/shops/prestashop_v2/redirect/auth/connect', $queryParams);
    }

    /**
     * Checks if integration is connected
     *
     * @return bool
     */
    public function isIntegrationConnected()
    {
        $currentShopId = (int)Shop::getContextShopID();

        return (bool)$this->getConfigService()->getConfigValueByShopIdAndName($currentShopId, ColumnNamesInterface::INTEGRATION_ID);
    }

    /**
     * @param WebserviceKey $webServiceKey
     * @param array $connectedShops
     *
     * @return void
     * @throws PrestaShopException
     */
    public function saveOrUpdateConnectSettings($webServiceKey, $connectedShops)
    {
        $connectionSettings = [
            'id' => $webServiceKey->id,
            'key' => $webServiceKey->key,
            'shops' => array_unique($connectedShops),
        ];

        if (Tools::version_compare(_PS_VERSION_, '1.8.0.0', '>=')) {
            $saved = $this->getConfigService()->updateGlobalValue(ColumnNamesInterface::CONNECT_SETTINGS, json_encode($connectionSettings));
        } else {
            $saved = $this->getConfigService()->updateGlobalValue(ColumnNamesInterface::CONNECT_SETTINGS, Tools::jsonEncode($connectionSettings));
        }

        if (!$saved) {
            throw new PrestaShopException($this->l('Unable to update the connection settings.', $this->module->name));
        }
    }

    /**
     * @return array
     */
    public function fetchConnectSettings()
    {
        if (!$this->connectSettings) {
            $this->connectSettings = $this->loadSettings();
        }

        return $this->connectSettings;
    }

    /**
     * @return array
     */
    private function loadSettings()
    {
        $empty = ['id' => null, 'key' => null, 'shops' => []];
        $settings = $this->getConfigService()->getGlobalValue(ColumnNamesInterface::CONNECT_SETTINGS);

        if (!$settings) {
            return $empty;
        }

        if (Tools::version_compare(_PS_VERSION_, '1.8.0.0', '>=')) {
            $settings = json_decode($settings, true);
        } else {
            $settings = Tools::jsonDecode($settings, true);
        }

        if ($this->isEmptySettings($settings)) {
            return $empty;
        }

        if (!$this->getApiWebService()->keyExists($settings['key'])) {
            $this->getConfigService()->deleteByName(ColumnNamesInterface::CONNECT_SETTINGS);
            return $empty;
        }

        if (!isset($settings['shops'])) {
            $settings['shops'] = [];
        }

        return $settings;
    }

    /**
     * @param array $settings
     *
     * @return bool
     */
    private function isEmptySettings($settings)
    {
        return empty($settings) || !isset($settings['id']) || !isset($settings['key']);
    }

    /**
     * Cuts https from the redirect url
     *
     * @param $url
     *
     * @return string
     */
    private function formatUrl($url)
    {
        $url = str_replace("https://", "", $url);

        return rtrim($url, '/');
    }

    /**
     * Return instance of ApiWebService
     *
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
     * Return instance of ConfigService
     *
     * @return ConfigService
     */
    private function getConfigService()
    {
        if ($this->configService === null) {
            $this->configService = ServiceRegister::getService(ConfigService::class);
        }

        return $this->configService;
    }
}
