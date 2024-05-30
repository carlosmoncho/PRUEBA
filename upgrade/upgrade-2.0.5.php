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

use PrestaShop\PrestaShop\Adapter\Entity\Tools;
use Sendcloud\PrestaShop\Classes\Bootstrap\Bootstrap;
use Sendcloud\PrestaShop\Classes\Bootstrap\ServiceRegister;
use Sendcloud\PrestaShop\Classes\Interfaces\ColumnNamesInterface;
use Sendcloud\PrestaShop\Classes\Services\ApiWebService;
use Sendcloud\PrestaShop\Classes\Services\AuthService;
use Sendcloud\PrestaShop\Classes\Services\ConfigService;

if (!defined('_PS_VERSION_')) {
    exit;
}

/**
 * Upgrades module to version 2.0.5
 *
 * @param $module
 *
 * @return bool
 * @throws PrestaShopException
 */
function upgrade_module_2_0_5($module)
{
    $previousShopContext = Shop::getContext();
    Shop::setContext(Shop::CONTEXT_ALL);

    Bootstrap::init();

    updateApiPermissions();

    $module->enable();
    Shop::setContext($previousShopContext);

    \Configuration::loadConfiguration();

    return true;
}

/**
 * Updates api permission for the connected api key
 *
 * @throws PrestaShopDatabaseException
 * @throws PrestaShopException
 */
function updateApiPermissions()
{
    $settings = getConfigService()->getGlobalValue(ColumnNamesInterface::CONNECT_SETTINGS);

    if ($settings) {
        if (Tools::version_compare(_PS_VERSION_, '1.8.0.0', '>=')) {
            $settings = json_decode($settings, true);
        } else {
            $settings = Tools::jsonDecode($settings, true);
        }
        $keyId = null;

        if ($settings['id'] && $settings['key']) {
            $keyId = $settings['id'];
        }
        $webServiceKey = new WebserviceKey($keyId);

        if (Validate::isLoadedObject($webServiceKey)) {
            // Key exists, integration can access its properties
            getApiWebService()->setPermissionForAccount($webServiceKey->id, getAuthService()->getAPIPermissions());
        }
    }
}

/**
 * @return ApiWebService
 */
function getApiWebService()
{
    return ServiceRegister::getService(ApiWebService::class);
}

/**
 * @return ConfigService
 */
function getConfigService()
{
    return ServiceRegister::getService(ConfigService::class);
}

/**
 * @return AuthService
 */
function getAuthService()
{
    return ServiceRegister::getService(AuthService::class);
}
