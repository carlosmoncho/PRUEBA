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

namespace Sendcloud\PrestaShop\Classes\Utilities;

use PrestaShopDatabaseException;
use SendCloud\Infrastructure\Logger\Logger;
use Sendcloud\PrestaShop\Classes\Core\Infrastructure\Repositories\ProcessEntityRepository;
use Sendcloud\PrestaShop\Classes\Core\Infrastructure\Repositories\QueueItemRepository;
use Sendcloud\PrestaShop\Classes\Interfaces\ColumnNamesInterface;
use Sendcloud\PrestaShop\Classes\Interfaces\ModuleInterface;
use Sendcloud\PrestaShop\Classes\Repositories\ServicePointRepository;

if (!defined('_PS_VERSION_')) {
    exit;
}

/**
 * Class DBInitializer
 *
 * @package Sendcloud\PrestaShop\Classes\Utilities
 */
class DBInitializer
{
    const CARRIER_TABLE = 'carrier';
    const CARRIER_GROUP_TABLE = 'carrier_group';
    const CARRIER_LANG_TABLE = 'carrier_lang';
    const CARRIER_SHOP_TABLE = 'carrier_shop';
    const CARRIER_TAX_RULES_TABLE = 'carrier_tax_rules_group_shop';
    const CARRIER_ZONE_TABLE = 'carrier_zone';

    /**
     * Create queue items table
     *
     * @return bool
     */
    public function createSendCloudQueuesTable()
    {
        $sql = 'CREATE TABLE IF NOT EXISTS '
            . bqSQL(_DB_PREFIX_ . QueueItemRepository::QUEUE_TABLE)
            . '(
         `id` INT unsigned NOT NULL AUTO_INCREMENT,
         `status` VARCHAR(30) NOT NULL,
         `type` VARCHAR(100) NOT NULL,
         `queueName` VARCHAR(50) NOT NULL,
         `progress` INT NOT NULL DEFAULT 0,
         `lastExecutionProgress` INT DEFAULT 0,
         `retries` INT NOT NULL DEFAULT 0,
         `failureDescription` VARCHAR(255) DEFAULT NULL,
         `serializedTask` mediumtext NOT NULL,
         `createTimestamp` INT DEFAULT NULL,
         `queueTimestamp` INT DEFAULT NULL,
         `lastUpdateTimestamp` INT DEFAULT NULL,
         `startTimestamp` INT DEFAULT NULL,
         `finishTimestamp` INT DEFAULT NULL,
         `failTimestamp` INT DEFAULT NULL,
         PRIMARY KEY(`id`),
         INDEX `idx_type_queueName` (`type`, `queueName`),
         UNIQUE KEY `id` (`id`)
        )
        ENGINE=InnoDB DEFAULT CHARSET=utf8mb4';

        return \Db::getInstance()->execute($sql);
    }

    /**
     * Create processes table
     *
     * @return bool
     */
    public function createSendCloudProcessesTable()
    {
        $sql = 'CREATE TABLE IF NOT EXISTS '
            . bqSQL(_DB_PREFIX_ . ProcessEntityRepository::PROCESS_TABLE)
            . '(
             `id` INT NOT NULL AUTO_INCREMENT,
             `guid` VARCHAR(50),
             `runner` VARCHAR(500),
             PRIMARY KEY(`id`)
        )
        ENGINE=' . _MYSQL_ENGINE_ . ' DEFAULT CHARSET=utf8';

        return \Db::getInstance()->execute($sql);
    }

    /**
     * Create service points table
     *
     * @return bool
     */
    public function createServicePointTable()
    {
        $sql = 'CREATE TABLE IF NOT EXISTS ' . bqSQL(_DB_PREFIX_ . ServicePointRepository::TABLE_NAME) . '(
        `id_service_point` INT NOT NULL AUTO_INCREMENT,
        `id_cart` INT unsigned NOT NULL,
        `id_address_delivery` INT unsigned DEFAULT NULL,
        `details` TEXT DEFAULT NULL,
        `date_add` DATETIME NOT NULL,
        `date_upd` DATETIME DEFAULT NULL,
        PRIMARY KEY (`id_service_point`),
        UNIQUE KEY `id_service_point` (`id_service_point`)
        )
        ENGINE=InnoDB DEFAULT CHARSET=utf8mb4';

        return \Db::getInstance()->execute($sql);
    }

    /**
     * Adds a custom columns 'sc_hs_code' and 'sc_country_of_origin' to the 'ps_product' table.
     *
     * @return bool
     * @throws PrestaShopDatabaseException
     */
    public function updateProductTable()
    {
        $this->addInternationalShippingColumnToDatabase(ColumnNamesInterface::HS_CODE_FIELD);
        $this->addInternationalShippingColumnToDatabase(ColumnNamesInterface::COUNTRY_OF_ORIGIN_FIELD);

        return true;
    }

    /**
     * Drop Sendcloud tables
     *
     * @return bool
     */
    public function dropSendcloudTables()
    {
        $sql = 'DROP TABLE IF EXISTS ' . bqSQL(_DB_PREFIX_ . QueueItemRepository::QUEUE_TABLE);
        \Db::getInstance()->execute($sql);

        $sql = 'DROP TABLE IF EXISTS ' . bqSQL(_DB_PREFIX_ . ProcessEntityRepository::PROCESS_TABLE);
        \Db::getInstance()->execute($sql);

        $sql = 'DROP TABLE IF EXISTS ' . bqSQL(_DB_PREFIX_ . ServicePointRepository::TABLE_NAME);
        \Db::getInstance()->execute($sql);

        return true;
    }

    /**
     * @return bool
     */
    public function deleteCarriersByExternalModuleName()
    {
        $carrierIds = $this->getCarrierIdsByExternalModuleName();

        if (!empty($carrierIds)) {
            $this->deleteRecordsFromTable(self::CARRIER_GROUP_TABLE, ColumnNamesInterface::CARRIER_ID, $carrierIds);
            $this->deleteRecordsFromTable(self::CARRIER_LANG_TABLE, ColumnNamesInterface::CARRIER_ID, $carrierIds);
            $this->deleteRecordsFromTable(self::CARRIER_SHOP_TABLE, ColumnNamesInterface::CARRIER_ID, $carrierIds);
            $this->deleteRecordsFromTable(self::CARRIER_TAX_RULES_TABLE, ColumnNamesInterface::CARRIER_ID, $carrierIds);
            $this->deleteRecordsFromTable(self::CARRIER_ZONE_TABLE, ColumnNamesInterface::CARRIER_ID, $carrierIds);
            $this->deleteRecordsFromTable(self::CARRIER_TABLE, ColumnNamesInterface::CARRIER_ID, $carrierIds);
        }

        return true;
    }

    /**
     * Adds composite index(type, queueName) to the existing table
     *
     * @param string $tableName
     *
     * @return bool
     */
    public function addIndexesToExistingTable($tableName)
    {
        $db = \Db::getInstance();

        $tableName = _DB_PREFIX_ . $tableName;
        $indexSql = 'ALTER TABLE ' . $tableName . '
                 ADD INDEX `idx_type_queueName` (`type`, `queueName`);';

        return $db->execute($indexSql);
    }

    /**
     * @param string $columnName
     *
     * @return void
     *
     * @throws PrestaShopDatabaseException
     */
    public function changeProductHsCodeColumnType()
    {
        $sql = "ALTER TABLE `" . _DB_PREFIX_ . 'product' . "` MODIFY `" . pSQL(ColumnNamesInterface::HS_CODE_FIELD);
        $sql .= "` VARCHAR(10) DEFAULT NULL";
        \Db::getInstance()->Execute($sql);
    }

    /**
     * Get all module related carrier ids
     *
     * @return array
     */
    private function getCarrierIdsByExternalModuleName()
    {
        $db = \Db::getInstance();
        $sql = "SELECT id_carrier FROM " . _DB_PREFIX_ . self::CARRIER_TABLE . " WHERE external_module_name = '" . pSQL(ModuleInterface::MODULE_NAME) . "'";

        try {
            $results = $db->executeS($sql);
            return array_column($results, 'id_carrier');
        } catch (\PrestaShopException $e) {
            // Handle any exceptions or errors here
        }

        return [];
    }

    /**
     * Delete all module carrier related data
     *
     * @param string $table
     * @param string $conditionField
     * @param array $conditionValues
     *
     * @return bool
     */
    private function deleteRecordsFromTable($table, $conditionField, $conditionValues)
    {
        if (!empty($conditionValues)) {
            $db = \Db::getInstance();
            $conditionValues = implode(',', array_map('intval', $conditionValues));
            $sql = "DELETE FROM " . _DB_PREFIX_ . $table . " WHERE " . pSQL($conditionField) . " IN (" . $conditionValues . ")";

            try {
                return $db->execute($sql);
            } catch (\PrestaShopException $e) {
                Logger::logError('Failed to delete carrier data for ' . ModuleInterface::MODULE_NAME . ' module. ' . $e->getMessage());
            }
        }

        return false;
    }

    /**
     * @param string $columnName
     *
     * @return void
     *
     * @throws PrestaShopDatabaseException
     */
    private function addInternationalShippingColumnToDatabase($columnName)
    {
        $sql = "DESCRIBE `" . _DB_PREFIX_ . 'product' . "` `" . pSQL($columnName) . "`";
        $result = \Db::getInstance()->ExecuteS($sql);

        if (empty($result)) {
            $sql = "ALTER TABLE `" . _DB_PREFIX_ . 'product' . "` ADD `" . pSQL($columnName);
            if ($columnName === ColumnNamesInterface::COUNTRY_OF_ORIGIN_FIELD) {
                $sql .= "` VARCHAR(255) DEFAULT NULL";
            } else {
                $sql .= "` VARCHAR(10) DEFAULT NULL";
            }

            \Db::getInstance()->Execute($sql);
        }
    }
}
