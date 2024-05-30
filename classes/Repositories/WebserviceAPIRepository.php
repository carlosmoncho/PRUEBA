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

use PrestaShop\PrestaShop\Adapter\Entity\Db;
use PrestaShop\PrestaShop\Adapter\Entity\WebserviceKey;

if (!defined('_PS_VERSION_')) {
    exit;
}

/**
 * Class WebserviceAPIRepository
 *
 * @package Sendcloud\PrestaShop\Classes\Repositories
 */
class WebserviceAPIRepository
{
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
        WebserviceKey::setPermissionForAccount($id, $apiPermissions);
    }

    /**
     * @param string $key
     *
     * @return bool
     */
    public function keyExists($key)
    {
        return (bool)WebserviceKey::keyExists($key);
    }

    /**
     * Removes all webservice records from the Presta database
     *
     * @param int $webserviceAccountId
     *
     * @return void
     */
    public function eraseWebServiceAccountData($webserviceAccountId)
    {
        $db = Db::getInstance();

        // Delete records from ps_webservice_account_shop
        $query = "DELETE FROM " . _DB_PREFIX_ . "webservice_account_shop WHERE id_webservice_account = " . (int)$webserviceAccountId;
        $db->execute($query);

        // Delete records from ps_webservice_permission
        $query = "DELETE FROM " . _DB_PREFIX_ . "webservice_permission WHERE id_webservice_account = " . (int)$webserviceAccountId;
        $db->execute($query);

        // Delete record from ps_webservice_account
        $query = "DELETE FROM " . _DB_PREFIX_ . "webservice_account WHERE id_webservice_account = " . (int)$webserviceAccountId;
        $db->execute($query);
    }
}
