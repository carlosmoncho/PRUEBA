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

namespace Sendcloud\PrestaShop\Classes\Repositories;

use PDO;
use PrestaShop\PrestaShop\Adapter\Entity\Configuration;
use PrestaShop\PrestaShop\Adapter\Entity\Db;
use PrestaShop\PrestaShop\Adapter\Entity\Shop;
use PrestaShop\PrestaShop\Adapter\Entity\Tools;
use SendCloud\Infrastructure\Logger\Logger;
use Sendcloud\PrestaShop\Classes\Exceptions\ServicePointException;
use Sendcloud\PrestaShop\Classes\Interfaces\ColumnNamesInterface;

if (!defined('_PS_VERSION_')) {
    exit;
}

/**
 * Class ConfigRepository
 *
 * @package Sendcloud\PrestaShop\Classes\Repositories
 */
class ConfigRepository
{
    const CONFIGURATION_TABLE = 'configuration';

    /**
     * Save value in the ps_configuration table
     *
     * @param string $key
     * @param string $value
     *
     * @return void
     */
    public function saveConfigValue($key, $value)
    {
        Configuration::updateValue($key, $value);
    }

    /**
     * @param string $key
     * @param string $value
     *
     * @return bool
     */
    public function updateGlobalValue($key, $value)
    {
        return Configuration::updateGlobalValue($key, $value);
    }

    /**
     * Fetch value from ps_configuration table based on key parameter
     *
     * @param string $key
     * @param int|null $shopId
     *
     * @return mixed
     */
    public function getValue($key, $shopId = null)
    {
        return Configuration::get($key, null, null, $shopId);
    }

    /**
     * @param int $shopId
     * @param string $name
     *
     * @return string|null
     */
    public function getConfigValueByShopIdAndName($shopId, $name)
    {
        $db = \Db::getInstance();
        $sql = "SELECT * FROM " . _DB_PREFIX_ . self::CONFIGURATION_TABLE . " WHERE id_shop = '" . pSQL($shopId) . "' AND name = '" . pSQL($name) . "'";

        try {
            $result = $db->executeS($sql);

            if (!empty($result) && isset($result[0]['value'])) {
                return $result[0]['value'];
            }
        } catch (\PrestaShopException $e) {
            Logger::logError('Could not fetch config value for ' . $name . 'for shop with id ' .$shopId);
        }

        return null;
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
        return Configuration::getMultiple($configNames, null, null, $shopId);
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
        return Configuration::getGlobalValue($key);
    }

    /**
     * Delete configuration by name
     *
     * @param string $name
     *
     * @return bool
     */
    public function deleteByName($name)
    {
        return Configuration::deleteByName($name);
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
        $removeConfig = sprintf(
            "DELETE FROM `%s` WHERE name LIKE '%%%s%%'",
            pSQL(_DB_PREFIX_ . self::CONFIGURATION_TABLE),
            pSQL($name)
        );

        \Db::getInstance()->execute($removeConfig);
    }

    /**
     * @param int $shopId
     * @param string $name
     *
     * @return bool
     */
    public function deleteByShopIdAndName($shopId, $name)
    {
        $db = \Db::getInstance();
        $sql = "DELETE FROM " . _DB_PREFIX_ . self::CONFIGURATION_TABLE . " WHERE id_shop = '" . pSQL($shopId) . "' AND name = '" . pSQL($name) . "'";

        return $db->execute($sql);
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
        $allConfigSQL = sprintf(
            "SELECT name FROM `%s` WHERE name LIKE '%s%%'",
            pSQL(_DB_PREFIX_ . self::CONFIGURATION_TABLE),
            pSQL(ColumnNamesInterface::SENDCLOUD_CARRIER_PREFIX)
        );
        $data = Db::getInstance()->query($allConfigSQL)->fetchAll(PDO::FETCH_COLUMN);
        $codes = [];

        foreach ($data as $entry) {
            $sanitized = str_replace(ColumnNamesInterface::SENDCLOUD_CARRIER_PREFIX, '', $entry);
            $sanitized = str_replace('_REFERENCE', '', $sanitized);
            // Sendcloud carrier codes are sent in lowercase, but configurations are saved in all-caps.
            $codes[] = Tools::strtolower($sanitized);
        }

        return array_unique($codes);
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
        $carrierConfigurations = Db::getInstance()->query(sprintf(
            "SELECT value from `%s` WHERE name='%s' AND id_shop != %d AND id_shop != 0",
            pSQL(_DB_PREFIX_ . 'configuration'),
            pSQL(ColumnNamesInterface::SENDCLOUD_CARRIERS),
            (int) $shop->id
        ));

        return $carrierConfigurations && is_array($carrierConfigurations) ? $carrierConfigurations : [];
    }

    /**
     * Avoid polluting the database with multiple (perhaps incorrect) data related to service points.
     * If an attempt to enable the feature successfully creates the configuration but Sendcloud refuses
     * to save it we may start to create several service point configurations.
     *
     * PrestaShop is designed in such a way that it allows us to have multiple configurations with
     * the same name, shop, and shop group, hence the deletion of previously added configurations.
     *
     * @param Shop $shop
     * @param string $name
     * @param int|null $preserveId configuration ID passed here is not removed
     * @throws ServicePointException
     */
    public function removeOrphanConfiguration($shop, $name, $preserveId)
    {
        $configuration = pSQL(_DB_PREFIX_ . self::CONFIGURATION_TABLE);
        $configName = pSQL($name);
        $shopID = (int) $shop->id;
        $configID = (int) $preserveId;

        $removeOrphansSQL = "DELETE FROM `{$configuration}`
            WHERE name='{$configName}' AND
            id_shop='{$shopID}' AND
            id_configuration != {$configID}";

        $deletedRows = Db::getInstance()->execute($removeOrphansSQL);
        if (!$deletedRows) {
            throw new ServicePointException('Unable to remove orphan configurations.');
        }
    }

    /**
     * Given a `Carrier` instance, return the registered Sendcloud carrier code for it
     *
     * @param $carrier
     *
     * @return string|null The carrier code or NULL in case the configuration is not found
     */
    public function getCarrierCode($carrier)
    {
        $sql = sprintf(
            "SELECT name FROM `%s` WHERE name LIKE '%s%%' AND value=%d",
            pSQL(_DB_PREFIX_ . self::CONFIGURATION_TABLE),
            pSQL(ColumnNamesInterface::SENDCLOUD_CARRIER_PREFIX),
            (int) $carrier->id
        );
        $config = Db::getInstance()->getValue($sql);
        if (!$config) {
            return null;
        }
        $code = str_replace(ColumnNamesInterface::SENDCLOUD_CARRIER_PREFIX, '', $config);

        return Tools::strtolower($code);
    }
}
