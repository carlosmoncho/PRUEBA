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

namespace Sendcloud\PrestaShop\Classes\Core\Infrastructure\Services;

use SendCloud\Infrastructure\Interfaces\Required\TaskQueueStorage;
use SendCloud\Infrastructure\TaskExecution\Exceptions\QueueItemDeserializationException;
use SendCloud\Infrastructure\TaskExecution\QueueItem;
use Sendcloud\PrestaShop\Classes\Bootstrap\ServiceRegister;
use Sendcloud\PrestaShop\Classes\Core\Infrastructure\Repositories\QueueItemRepository;

if (!defined('_PS_VERSION_')) {
    exit;
}

/**
 * Class TaskQueueStorageService
 *
 * @package Sendcloud\PrestaShop\Classes\Core\Infrastructure\Services
 */
class TaskQueueStorageService implements TaskQueueStorage
{
    /**
     * @var QueueItemRepository
     */
    private $queueItemRepository;

    /**
     * Creates or updates given queue item. If queue item id is not set, new queue item will be created otherwise update will be performed.
     *
     * @param QueueItem $queueItem
     * @param array $additionalWhere
     *
     * @return int
     * @throws QueueItemDeserializationException
     * @throws \PrestaShopException
     */
    public function save(QueueItem $queueItem, array $additionalWhere = [])
    {
        $result = $this->getQueueItemRepository()->save($queueItem->getId(), $this->toArray($queueItem), $additionalWhere);

        if ($result === null) {
            throw new \PrestaShopException('Failed to save queue item into database');
        }

        return $result;
    }

    /**
     * Finds queue item by ID.
     *
     * @param int $id
     *
     * @return QueueItem|null
     */
    public function find($id)
    {
        $queueItem = $this->getQueueItemRepository()->find($id);

        return $queueItem ? $this->fromDatabaseEntity($queueItem) : null;
    }

    /**
     * Finds latest queue item by type across all queues
     *
     * @param string $type
     * @param string $context
     *
     * @return QueueItem|null
     */
    public function findLatestByType($type, $context = '')
    {
        $queueItem = $this->getQueueItemRepository()->findLatestByType($type);

        return $queueItem ? $this->fromDatabaseEntity($queueItem) : null;
    }

    /**
     * Finds list of earliest queued queue items per queue.
     *
     * Following list of criteria for searching must be satisfied:
     *   - Queue must be without already running queue items
     *   - For one queue only one (oldest queued) item should be returned
     *
     * @param int $limit
     *
     * @return QueueItem[]
     */
    public function findOldestQueuedItems($limit = 10)
    {
        $result = $this->getQueueItemRepository()->findOldestQueuedItems($limit);
        $queuedItems = [];

        foreach ($result as $row) {
            $queuedItems[] = $this->fromDatabaseEntity($row);
        }

        return $queuedItems;
    }

    /**
     * Finds all queue items from all queues
     *
     * @param array $filterBy List of simple search filters, where key is queue item property and
     *       value is condition value for that property. Leave empty for unfiltered result.
     * @param array $sortBy List of sorting options where key is queue item property and value
     *       sort direction ("ASC" or "DESC"). Leave empty for default sorting.
     * @param int $start From which record index result set should start.
     * @param int $limit Max number of records that should be returned (default is 10).
     *
     * @return QueueItem[]
     */
    public function findAll(array $filterBy = [], array $sortBy = [], $start = 0, $limit = 10): array
    {
        $result = $this->getQueueItemRepository()->findAll($filterBy, $sortBy, $start, $limit);
        $queueItems = [];

        foreach ($result as $row) {
            $queueItems[] = $this->fromDatabaseEntity($row);
        }

        return $queueItems;
    }

    /**
     * Deletes queue items by provided type.
     *
     * @param string $type Type of queue item to find.
     * @param string $context Task context restriction if provided search will be limited to given task context. Leave
     *                         empty for search across all task contexts.
     *
     * @return bool
     */
    public function deleteByType($type, $context = '')
    {
        return $this->getQueueItemRepository()->deleteByType($type);
    }

    /**
     * Deletes queue items older than provided time limit with optional additional simple filters  and limit
     *
     * @param \DateTime $timeBefore Time boundary for delete operation. All queue items older than this time
     *       should be removed
     * @param array $filterBy List of simple search filters, where key is queue item property and value is condition
     *       value for that property. Leave empty for unfiltered removal.
     * @param array $excludeTypes List of queue item types to be excluded from the delete operation
     * @param int $limit How many queue items should be removed at most
     *
     * @return int
     */
    public function deleteOldItemsBy(\DateTime $timeBefore, array $filterBy = [], array $excludeTypes = [], $limit = 1000)
    {
        return $this->getQueueItemRepository()->deleteOldItemsBy($timeBefore, $filterBy, $excludeTypes, $limit);
    }

    /**
     * Transform queue item object to array
     *
     * @param QueueItem $queueItem
     *
     * @return array
     * @throws QueueItemDeserializationException
     */
    private function toArray(QueueItem $queueItem): array
    {
        return [
            'status' => $queueItem->getStatus(),
            'type' => $queueItem->getTaskType(),
            'queueName' => $queueItem->getQueueName(),
            'progress' => $queueItem->getProgressBasePoints(),
            'lastExecutionProgress' => $queueItem->getLastExecutionProgressBasePoints(),
            'retries' => $queueItem->getRetries(),
            'failureDescription' => $queueItem->getFailureDescription(),
            'serializedTask' => $queueItem->getSerializedTask(),
            'createTimestamp' => $queueItem->getCreateTimestamp(),
            'queueTimestamp' => $queueItem->getQueueTimestamp(),
            'lastUpdateTimestamp' => $queueItem->getLastUpdateTimestamp(),
            'startTimestamp' => $queueItem->getStartTimestamp(),
            'finishTimestamp' => $queueItem->getFinishTimestamp(),
            'failTimestamp' => $queueItem->getFailTimestamp(),
        ];
    }

    /**
     * Create QueueItem object from database entity
     *
     * @param array $data
     *
     * @return QueueItem
     */
    private function fromDatabaseEntity(array $data): QueueItem
    {
        $queueItem = new QueueItem();

        $queueItem->setId((int)$data['id']);
        $queueItem->setStatus($data['status']);
        $queueItem->setQueueName($data['queueName']);
        $queueItem->setProgressBasePoints((int)$data['progress']);
        $queueItem->setLastExecutionProgressBasePoints((int)$data['lastExecutionProgress']);
        $queueItem->setRetries((int)$data['retries']);
        $queueItem->setFailureDescription($data['failureDescription']);
        $queueItem->setSerializedTask($data['serializedTask']);
        $queueItem->setCreateTimestamp((int)$data['createTimestamp']);
        $queueItem->setQueueTimestamp((int)$data['queueTimestamp']);
        $queueItem->setLastUpdateTimestamp((int)$data['lastUpdateTimestamp']);
        $queueItem->setStartTimestamp((int)$data['startTimestamp']);
        $queueItem->setFinishTimestamp((int)$data['finishTimestamp']);
        $queueItem->setFailTimestamp((int)$data['failTimestamp']);

        return $queueItem;
    }

    /**
     * @return QueueItemRepository
     */
    private function getQueueItemRepository()
    {
        if ($this->queueItemRepository === null) {
            $this->queueItemRepository = ServiceRegister::getService(QueueItemRepository::class);
        }

        return $this->queueItemRepository;
    }
}
