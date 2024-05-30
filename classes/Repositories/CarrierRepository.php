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

use PrestaShop\PrestaShop\Adapter\Entity\Carrier;
use PrestaShop\PrestaShop\Adapter\Entity\Db;
use PrestaShop\PrestaShop\Adapter\Entity\Shop;
use Sendcloud\PrestaShop\Classes\Interfaces\ModuleInterface;

if (!defined('_PS_VERSION_')) {
    exit;
}

/**
 * Class CarrierRepository
 *
 * @package Sendcloud\PrestaShop\Classes\Repositories
 */
class CarrierRepository
{
    const CARRIER_TABLE = 'carrier';
    const CARRIER_GROUP_TABLE = 'carrier_group';
    const MODULE_CARRIER_TABLE = 'module_carrier';

    /**
     * Returns carrier id based on given reference id
     *
     * @param $referenceId
     *
     * @return string|null
     */
    public function getCarrierIdByReference($referenceId)
    {
        $carrierSQL = "SELECT id_carrier FROM `%s`
            WHERE external_module_name='%s'
            AND active=1 and deleted=0 and is_module=1 AND id_reference=%s";

        $carrier = Db::getInstance()->getValue(sprintf(
            $carrierSQL,
            pSQL(_DB_PREFIX_ . self::CARRIER_TABLE),
            pSQL(ModuleInterface::MODULE_NAME),
            (int)$referenceId
        ));

        return $carrier ?: null;
    }

    /**
     * Adds relation between Group and carrier.
     *
     * @param string $carrierId
     * @param array $carrierGroups
     *
     * @return void
     */
    public function addCarrierGroups($carrierId, array $carrierGroups)
    {
        $db = Db::getInstance();
        $carrierGroupsTable = _DB_PREFIX_ . self::CARRIER_GROUP_TABLE;
        $insertSql = 'INSERT INTO `%1$s` VALUES (%2$d, %3$d)';
        $existsSql = 'SELECT count(1) FROM `%1$s` WHERE id_group = %2$d and id_carrier = %3$d';

        foreach ($carrierGroups as $group) {
            $existsQuery = sprintf(
                $existsSql,
                pSQL($carrierGroupsTable),
                (int) $group['id_group'],
                (int) $carrierId
            );
            if ((int) $db->getValue($existsQuery) > 0) {
                // Skip if group already exists for carrier.
                continue;
            }
            $db->execute(sprintf(
                $insertSql,
                pSQL($carrierGroupsTable),
                (int) $carrierId,
                (int) $group['id_group']
            ));
        }
    }

    /**
     * As of PS 1.7 it's possible to change which payment modules are available per carrier
     *
     * http://forge.prestashop.com/browse/BOOM-3070
     * When adding a carrier in the webservice context, the payment
     * relations are not added, so we enable them for all installed payment
     * modules.
     *
     * @param $insertValues
     *
     * @return void
     */
    public function addCarrierRestrictions($insertValues)
    {
        $insert = sprintf(
            'INSERT INTO `%s` (id_module, id_shop, id_reference) VALUES %s',
            pSQL(_DB_PREFIX_ . self::MODULE_CARRIER_TABLE),
            join(', ', $insertValues)
        );

        Db::getInstance()->execute($insert);
    }

    /**
     * Check for carrier restriction in relation to Payment Methods.
     *
     * @param Carrier $carrier
     * @param $shop
     *
     * @return bool
     */
    public function isCarrierRestricted(Carrier $carrier, $shop)
    {
        $check = sprintf(
            'SELECT COUNT(1) FROM `%s` WHERE id_shop = %d AND (id_reference = %d OR id_reference = %d)',
            pSQL(_DB_PREFIX_ . self::MODULE_CARRIER_TABLE),
            (int) $shop->id,
            // Lookup using both carrier ID and Reference:
            // http://forge.prestashop.com/browse/BOOM-3071
            (int) $carrier->id,
            $carrier->id_reference
        );
        $exists = (bool) Db::getInstance()->getValue($check);

        // If there are no relation to payments we consider it as restricted.
        return !$exists;
    }

    /**
     * Returns Sendcloud carriers count
     *
     * @return int|null
     */
    public function getModuleCarriersCount()
    {
        $carriersCount = Db::getInstance()->getValue(sprintf(
            "SELECT COUNT(1) FROM `%s` WHERE external_module_name = '%s'",
            pSQL(_DB_PREFIX_ . self::CARRIER_TABLE),
            pSQL(ModuleInterface::MODULE_NAME)
        ));

        return $carriersCount ? (int)$carriersCount : null;
    }

    /**
     * Update carrier relation to the shop, if applicable.
     *
     * @param Carrier $carrier
     * @param Shop $shop
     *
     * @return bool `false` in case of failure to insert the new data
     */
    public function updateCarrierRelation(Carrier $carrier, $shop)
    {
        $shopExist = (int) Db::getInstance(false)->getValue(sprintf(
            'SELECT COUNT(1) FROM `' . _DB_PREFIX_ . 'carrier_shop`' .
            'WHERE id_carrier=%d and id_shop=%d',
            (int) $carrier->id,
            (int) $shop->id
        ));
        $relationSql = sprintf(
            'INSERT INTO `' . _DB_PREFIX_ . 'carrier_shop` (id_carrier, id_shop) VALUES (%d, %d)',
            (int) $carrier->id,
            (int) $shop->id
        );

        if (!$shopExist) {
            return Db::getInstance()->execute($relationSql);
        }

        return true;
    }
}
