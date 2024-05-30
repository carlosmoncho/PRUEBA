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

namespace Sendcloud\PrestaShop\Classes\Core\Infrastructure\Repositories;

if (!defined('_PS_VERSION_')) {
    exit;
}

/**
 * Class ProcessEntityRepository
 *
 * @package Sendcloud\PrestaShop\Classes\Core\Infrastructure\Repositories
 */
class ProcessEntityRepository
{
    const PROCESS_TABLE = 'sendcloud_processes';

    /**
     * Create new process record
     *
     * @param string $guid
     * @param string $runner
     *
     * @return bool
     */
    public function createProcess($guid, $runner)
    {
        $db = \Db::getInstance();
        $sql = "INSERT INTO " . _DB_PREFIX_ . self::PROCESS_TABLE ." (`guid`, `runner`) VALUES ('" . pSQL($guid) . "', '" . pSQL($runner) . "')";

        try {
            return $db->execute($sql);
        } catch (\PrestaShopException $e) {
            // Handle any exceptions or errors here
        }

        return false;
    }

    /**
     * Update process record
     *
     * @param int $id
     * @param string $guid
     * @param string $runner
     *
     * @return bool
     */
    public function updateProcess($id, $guid, $runner)
    {
        $db = \Db::getInstance();
        $sql = "UPDATE " . _DB_PREFIX_ . self::PROCESS_TABLE . " 
            SET `guid` = '" . pSQL($guid) . "', `runner` = '" . pSQL($runner) . "' 
            WHERE `id` = " . (int)$id;

        try {
            return $db->execute($sql);
        } catch (\PrestaShopException $e) {
            // Handle any exceptions or errors here
        }

        return false;
    }


    /**
     * Fetch process by guid
     *
     * @param string $guid
     *
     * @return array|null
     */
    public function getProcessByGuid($guid)
    {
        $db = \Db::getInstance();
        $sql = "SELECT * FROM " . _DB_PREFIX_ . self::PROCESS_TABLE . " WHERE guid = '" . pSQL($guid) . "'";

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
     * Delete process by guid
     *
     * @param string $guid
     *
     * @return bool
     */
    public function deleteByGuid($guid)
    {
        $db = \Db::getInstance();
        $sql = "DELETE FROM " . _DB_PREFIX_ . self::PROCESS_TABLE . " WHERE guid = '" . pSQL($guid) . "'";

        try {
            return $db->execute($sql);
        } catch (\PrestaShopException $e) {
            // Handle any exceptions or errors here
        }

        return false;
    }
}
