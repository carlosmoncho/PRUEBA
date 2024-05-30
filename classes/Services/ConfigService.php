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
use Sendcloud\PrestaShop\Classes\Bootstrap\ServiceRegister;
use Sendcloud\PrestaShop\Classes\Repositories\ConfigRepository;

if (!defined('_PS_VERSION_')) {
    exit;
}

/**
 * Class ConfigService
 *
 * @package Sendcloud\PrestaShop\Classes\Services
 */
class ConfigService
{
    /**
     * @var ConfigRepository
     */
    private $configRepository;

    /**
     * Save config value to ps_configuration table
     *
     * @param string $key
     * @param string $value
     *
     * @return void
     */
    public function saveConfigValue($key, $value)
    {
        $this->getConfigRepository()->saveConfigValue($key, $value);
    }

    /**
     * Fetch config value from ps_configuration table
     *
     * @param string $key
     * @param int|null $shopId
     *
     * @return mixed
     */
    public function getConfigValue($key, $shopId = null)
    {
        return $this->getConfigRepository()->getValue($key, $shopId);
    }

    /**
     * @param int $shopId
     * @param string $name
     *
     * @return string|null
     */
    public function getConfigValueByShopIdAndName($shopId, $name)
    {
        return $this->getConfigRepository()->getConfigValueByShopIdAndName($shopId, $name);
    }

    /**
     * Get several configuration values (in one language only).
     *
     * @param array $configNames
     * @param int|null $shopId
     *
     * @return array
     * @throws \PrestaShopException
     */
    public function getMultiple($configNames, $shopId = null)
    {
        return $this->getConfigRepository()->getMultiple($configNames, $shopId);
    }

    /**
     * Update global value
     *
     * @param string $key
     * @param string $value
     *
     * @return bool
     */
    public function updateGlobalValue($key, $value)
    {
        return $this->getConfigRepository()->updateGlobalValue($key, $value);
    }

    /**
     * Return global value by key
     *
     * @param string $key
     *
     * @return string
     */
    public function getGlobalValue($key)
    {
        return $this->getConfigRepository()->getGlobalValue($key);
    }

    /**
     * Deletes config entry from the configuration table
     *
     * @param $key
     *
     * @return bool
     */
    public function deleteConfigEntry($key)
    {
        return $this->getConfigRepository()->deleteByName($key);
    }

    /**
     * @param int $shopId
     * @param string $name
     *
     * @return bool
     */
    public function deleteByShopIdAndName($shopId, $name)
    {
        return $this->getConfigRepository()->deleteByShopIdAndName($shopId, $name);
    }

    /**
     * Deletes all configuration values whose names contain $name parameter
     *
     * @param string $name
     *
     * @return void
     */
    public function deleteWhereNameLike($name)
    {
        $this->getConfigRepository()->deleteWhereNameLike($name);
    }

    /**
     * Delete configuration value by name
     *
     * @param string $name
     *
     * @return void
     */
    public function deleteByName($name)
    {
        $this->getConfigRepository()->deleteByName($name);
    }

    /**
     * Given a `Carrier` instance, return the registered Sendcloud carrier code for it
     *
     * @param $carrier
     *
     * @return string|null
     */
    public function getCarrierCode($carrier)
    {
        return $this->getConfigRepository()->getCarrierCode($carrier);
    }

    /**
     * Each PS carrier has an entry in the configuration table holding its latest synced ID. This will
     * return all (Sendcloud) carrier codes based on the configuration names.
     *
     * @return array List of Sendcloud-specific carrier codes (i.e.: colissimo, dpd, chronopost, mondial_relay)
     * @throws \PrestaShopDatabaseException
     */
    public function getAllRegisteredCarrierCodes()
    {
        return $this->getConfigRepository()->getAllRegisteredCarrierCodes();
    }

    /**
     * Returns carrier configurations for all shops except for one used as function parameter
     *
     * @param Shop $shop
     *
     * @return array
     * @throws \PrestaShopDatabaseException
     */
    public function getOtherCarriers($shop)
    {
        return $this->getConfigRepository()->getOtherCarriers($shop);
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
