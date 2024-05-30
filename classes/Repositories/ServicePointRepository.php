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

if (!defined('_PS_VERSION_')) {
    exit;
}

/**
 * Class ServicePointRepository
 *
 * @package Sendcloud\PrestaShop\Classes\Repositories
 */
class ServicePointRepository
{
    const TABLE_NAME = 'service_points_v2';

    /**
     * Retrieve a service point record based on cart id
     *
     * @param $cartId
     *
     * @return array|null
     */
    public function getByCartId($cartId)
    {
        $db = \Db::getInstance();
        $sql = "SELECT * FROM " . _DB_PREFIX_ . self::TABLE_NAME . " WHERE id_cart = '" . pSQL($cartId) . "'";

        try {
            $result = $db->executeS($sql);

            if (!empty($result)) {
                return $result[0];
            }
        } catch (\PrestaShopException $e) {
            // Handle any exceptions or errors here
        }

        return null;
    }

    /**
     * @param $data
     * @return int|null
     */
    public function saveServicePoint($data)
    {
        $db = \Db::getInstance();

        $cartId = (int)pSQL($data['id_cart']);
        $deliveryAddressId = (int)pSQL($data['id_address_delivery']);
        $details = pSQL($data['details']);
        $addedDate = pSQL(date('Y-m-d H:i:s'));
        $updateDate = pSQL(date('Y-m-d H:i:s'));

        $sql = "INSERT INTO " . _DB_PREFIX_ . self::TABLE_NAME . "
            (`id_cart`, `id_address_delivery`, `details`, `date_add`, `date_upd`)
            VALUES
            ('$cartId', '$deliveryAddressId', '$details', '$addedDate', '$updateDate')";

        $result = $db->execute($sql);

        return $result ? (int)$db->Insert_ID() : null;
    }

    /**
     * Delete service point record by cart id
     *
     * @param $cartId
     *
     * @return void
     */
    public function deleteByCartId($cartId)
    {
        $query = 'DELETE FROM `' . _DB_PREFIX_ . self::TABLE_NAME . '`
              WHERE id_cart=' . (int)$cartId;

        \Db::getInstance()->execute($query);
    }

    /**
     * Updates service point information
     *
     * @param $cartId
     * @param string $details
     *
     * @return bool
     */
    public function updateServicePoint($cartId, $details)
    {
        $cartId = (int)$cartId;
        $details = pSQL($details);
        $updatedTime = pSQL(date('Y-m-d H:i:s'));

        $sql = 'UPDATE ' . bqSQL(_DB_PREFIX_ . self::TABLE_NAME) . '
            SET `details` = \'' . $details . '\',
                `date_upd` = \'' . $updatedTime . '\'
            WHERE `id_cart` = ' . $cartId;

        return \Db::getInstance()->execute($sql);
    }
}
