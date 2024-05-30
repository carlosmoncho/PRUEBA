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

use SendCloud\Infrastructure\TaskExecution\QueueItem;

if (!defined('_PS_VERSION_')) {
    exit;
}

/**
 * Class QueueItemRepository
 *
 * @package Sendcloud\PrestaShop\Classes\Core\Infrastructure\Repositories
 */
class QueueItemRepository
{
    const QUEUE_TABLE = 'sendcloud_queues';

    /**
     * Create or update queue item
     *
     * @param int|null $id
     * @param array $data
     * @param array $additionalWhere
     *
     * @return int|null
     */
    public function save($id, array $data, array $additionalWhere)
    {
        if ($id !== null) {
            return $this->updateQueueItem($id, $data, $additionalWhere);
        }

        // ID doesn't exist or the record doesn't exist, save a new QueueItem record
        return $this->createQueueItem($data);
    }

    /**
     * Finds queue item by ID.
     *
     * @param int $id
     *
     * @return array|null
     */
    public function find($id)
    {
        $db = \Db::getInstance();

        return $db->getRow('SELECT * FROM ' . _DB_PREFIX_ . self::QUEUE_TABLE . ' WHERE `id` = ' . (int)$id);
    }

    /**
     * Finds latest queue item by type across all queues
     *
     * @param string $type
     *
     * @return array|null
     */
    public function findLatestByType($type)
    {
        $db = \Db::getInstance();
        $sql = 'SELECT * FROM ' . _DB_PREFIX_ . self::QUEUE_TABLE . ' 
                WHERE `type` = \'' . pSQL($type) . '\' 
                ORDER BY `queueTimestamp` DESC 
                ';

        return $db->getRow($sql);
    }

    /**
     * Finds latest queue item by type and queue name
     *
     * @param string $type
     *
     * @return array|null
     */
    public function findLatestByTypeAndQueue($type, $shopId)
    {
        $db = \Db::getInstance();
        $sql = 'SELECT * FROM ' . _DB_PREFIX_ . self::QUEUE_TABLE . ' 
                WHERE `type` = \'' . pSQL($type) . '\' 
                AND `queueName` = \'' . pSQL($shopId . '-prestashop_v2') . '\' 
                ORDER BY `queueTimestamp` DESC 
                ';

        return $db->getRow($sql);
    }

    /**
     * Finds list of earliest queued queue items per queue.
     *
     * @param int $limit
     *
     * @return array
     */
    public function findOldestQueuedItems(int $limit)
    {
        $db = \Db::getInstance();
        $runningQueuesQuery = 'SELECT DISTINCT `queueName` 
                               FROM ' . _DB_PREFIX_ . self::QUEUE_TABLE . ' qi2 
                               WHERE `status` = \'' . pSQL(QueueItem::IN_PROGRESS) . '\'';

        $sql = 'SELECT * 
                FROM (
                    SELECT `queueName`, MIN(`id`) AS `id`
                    FROM ' . _DB_PREFIX_ . self::QUEUE_TABLE . ' AS t
                    WHERE `status` = \'' . pSQL(QueueItem::QUEUED) . '\' 
                    AND `queueName` NOT IN (' . $runningQueuesQuery . ')
                    GROUP BY `queueName` LIMIT ' . (int)$limit . '
                ) AS queueView
                INNER JOIN ' . _DB_PREFIX_ .self::QUEUE_TABLE . ' AS qi ON queueView.`queueName` = qi.`queueName` 
                AND queueView.`id` = qi.`id`';

        try {
            $result = $db->executeS($sql);

            return $result ?: [];
        } catch (\PrestaShopException $e) {
            return [];
        }
    }

    /**
     * Finds all queue items from all queues
     *
     * @param array $filterBy
     * @param array $sortBy
     * @param int $start
     * @param int $limit
     *
     * @return array
     */
    public function findAll(array $filterBy, array $sortBy, int $start, int $limit): array
    {
        $db = \Db::getInstance();

        try {
            $sql = 'SELECT * FROM ' . _DB_PREFIX_ .self::QUEUE_TABLE;

            if (!empty($filterBy)) {
                $whereConditions = [];
                foreach ($filterBy as $column => $value) {
                    $whereConditions[] = '`' . pSQL($column) . '` = \'' . pSQL($value) . '\'';
                }
                $sql .= ' WHERE ' . implode(' AND ', $whereConditions);
            }

            if (!empty($sortBy)) {
                $orderBy = [];
                foreach ($sortBy as $column => $direction) {
                    $orderBy[] = '`' . pSQL($column) . '` ' . pSQL($direction);
                }

                if (!empty($orderBy)) {
                    $sql .= ' ORDER BY ' . implode(', ', $orderBy);
                }
            }
            $sql .= ' LIMIT ' . (int)$start . ', ' . (int)$limit;

            $result = $db->executeS($sql);

            return $result ?: [];
        } catch (\PrestaShopException $e) {
            return [];
        }
    }

    /**
     * Deletes queue items by provided type.
     *
     * @param string $type
     *
     * @return bool
     */
    public function deleteByType($type)
    {
        $db = \Db::getInstance();
        $sql = 'DELETE FROM ' . _DB_PREFIX_ . self::QUEUE_TABLE . ' 
                WHERE `type` = \'' . pSQL($type) . '\'';

        return $db->execute($sql);
    }

    /**
     * Deletes queue items older than provided time limit with optional additional simple filters  and limit
     *
     * @param \DateTime $timeBefore
     * @param array $filterBy
     * @param array $excludeTypes
     * @param int $limit
     *
     * @return int
     */
    public function deleteOldItemsBy(\DateTime $timeBefore, array $filterBy, array $excludeTypes, int $limit)
    {
        $db = \Db::getInstance();

        $sql = 'DELETE FROM ' . _DB_PREFIX_ . self::QUEUE_TABLE . ' 
                WHERE `createTimestamp` <= ' . (int)$timeBefore->getTimestamp();

        if (!empty($filterBy)) {
            $whereConditions = [];
            foreach ($filterBy as $column => $value) {
                $whereConditions[] = '`' . pSQL($column) . '` = \'' . pSQL($value) . '\'';
            }
            $sql .= ' AND ' . implode(' AND ', $whereConditions);
        }

        if (!empty($excludeTypes)) {
            $excludeConditions = [];
            foreach ($excludeTypes as $type) {
                $excludeConditions[] = '`type` != \'' . pSQL($type) . '\'';
            }
            $sql .= ' AND (' . implode(' OR ', $excludeConditions) . ')';
        }
        $sql .= ' LIMIT ' . $limit;
        $result = $db->execute($sql);

        return $result ? $db->numRows() : 0;
    }

    /**
     * @param array $data
     *
     * @return int
     */
    private function createQueueItem($data)
    {
        $db = \Db::getInstance();

        $serializedTask = pSQL($data['serializedTask']);
        $status = pSQL($data['status']);
        $type = pSQL($data['type']);
        $queueName = pSQL($data['queueName']);
        $progress = (int)$data['progress'];
        $lastExecutionProgress = (int)$data['lastExecutionProgress'];
        $retries = (int)$data['retries'];
        $failureDescription = pSQL($data['failureDescription']);
        $createTimestamp = (int)$data['createTimestamp'];
        $queueTimestamp = (int)$data['queueTimestamp'];
        $lastUpdateTimestamp = (int)$data['lastUpdateTimestamp'];
        $startTimestamp = (int)$data['startTimestamp'];
        $finishTimestamp = (int)$data['finishTimestamp'];
        $failTimestamp = (int)$data['failTimestamp'];

        $sql = "INSERT INTO " . _DB_PREFIX_ . self::QUEUE_TABLE . "
            (`status`, `type`, `queueName`, `progress`, `lastExecutionProgress`,
             `retries`, `failureDescription`, `serializedTask`, `createTimestamp`,
             `queueTimestamp`, `lastUpdateTimestamp`, `startTimestamp`,
             `finishTimestamp`, `failTimestamp`)
            VALUES
            ('$status', '$type', '$queueName', $progress, $lastExecutionProgress,
             $retries, '$failureDescription', '$serializedTask', $createTimestamp,
             $queueTimestamp, $lastUpdateTimestamp, $startTimestamp,
             $finishTimestamp, $failTimestamp)";

        $result = $db->execute($sql);

        return $result ? (int)$db->Insert_ID() : null;
    }

    /**
     * Update QueueItem database record
     *
     * @param int $id
     * @param array $dataToUpdate
     * @param array $additionalWhere
     *
     * @return int|null
     */
    private function updateQueueItem(int $id, array $dataToUpdate, array $additionalWhere)
    {
        $db = \Db::getInstance();

        $conditions = ['id = ' . $id];
        foreach ($additionalWhere as $column => $value) {
            if ($value === null) {
                $conditions[] = '(' . '`' . pSQL($column) . '` = \'0\' OR `' . pSQL($column) . '` IS NULL)';
            } else {
                $conditions[] = '`' . pSQL($column) . '` = \'' . pSQL($value) . '\'';
            }
        }

        $whereClause = implode(' AND ', $conditions);
        $existingRecord = $db->getRow('SELECT * FROM ' . _DB_PREFIX_ . self::QUEUE_TABLE . ' WHERE ' . $whereClause);

        if ($existingRecord) {
            $updateData = [];
            foreach ($dataToUpdate as $column => $value) {
                $updateData[] = '`' . pSQL($column) . '` = \'' . pSQL($value) . '\'';
            }
            $setClause = implode(', ', $updateData);

            $sql = "UPDATE " . _DB_PREFIX_ . self::QUEUE_TABLE . " SET $setClause WHERE $whereClause";
            $result = $db->execute($sql);

            return $result ? $id : null;
        }

        return null;
    }
}
