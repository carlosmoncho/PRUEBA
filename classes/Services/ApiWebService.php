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

use PrestaShop\PrestaShop\Adapter\Entity\Tools;
use Sendcloud\PrestaShop\Classes\Bootstrap\ServiceRegister;
use Sendcloud\PrestaShop\Classes\Repositories\ConfigRepository;
use Sendcloud\PrestaShop\Classes\Repositories\WebserviceAPIRepository;

if (!defined('_PS_VERSION_')) {
    exit;
}

/**
 * Class ShopService
 *
 * @package Sendcloud\PrestaShop\Classes\Services
 */
class ApiWebService
{
    /**
     * @var WebserviceAPIRepository
     */
    private $webserviceApiRepository;
    /**
     * @var ConfigRepository
     */
    private $configRepository;

    /**
     * Removes all webservice records from the Presta database
     *
     * @param int $webserviceAccountId
     *
     * @return void
     */
    public function eraseWebServiceAccountData($webserviceAccountId)
    {
        $this->getWebServiceApiRepository()->eraseWebServiceAccountData($webserviceAccountId);
    }

    /**
     * Updates PS_WEBSERVICE flag value in the database
     *
     * @return void
     */
    public function updateWebServiceFlag()
    {
        if (preg_match('/cgi/i', Tools::strtolower(php_sapi_name()))) {
            $this->getConfigRepository()->saveConfigValue('PS_WEBSERVICE_CGI_HOST', 1);
        }

        $this->getConfigRepository()->saveConfigValue('PS_WEBSERVICE', 1);
    }

    /**
     * Set permissions for web service key
     *
     * @param int|null $id
     * @param array $apiPermissions
     *
     * @return void
     */
    public function setPermissionForAccount($id, $apiPermissions)
    {
        $this->getWebServiceApiRepository()->setPermissionForAccount($id, $apiPermissions);
    }

    /**
     * Check if key exists
     *
     * @param string $key
     *
     * @return bool
     */
    public function keyExists($key)
    {
        return $this->getWebServiceApiRepository()->keyExists($key);
    }

    /**
     * Return instance of WebserviceAPIRepository
     *
     * @return WebserviceAPIRepository
     */
    private function getWebServiceApiRepository()
    {
        if ($this->webserviceApiRepository === null) {
            $this->webserviceApiRepository = ServiceRegister::getService(WebserviceAPIRepository::class);
        }

        return $this->webserviceApiRepository;
    }

    /**
     * Return instance of ConfigRepository
     *
     * @return ConfigRepository
     */
    private function getConfigRepository()
    {
        if ($this->configRepository === null) {
            $this->configRepository = ServiceRegister::getService(ConfigRepository::class);
        }

        return $this->configRepository;
    }
}
