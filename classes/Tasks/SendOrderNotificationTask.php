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

namespace Sendcloud\PrestaShop\Classes\Tasks;

use SendCloud\BusinessLogic\Sync\SerializedTask;
use SendCloud\Infrastructure\Logger\Logger;
use SendCloud\Infrastructure\Utility\Exceptions\HttpAuthenticationException;
use SendCloud\Infrastructure\Utility\Exceptions\HttpCommunicationException;
use SendCloud\Infrastructure\Utility\Exceptions\HttpRequestException;
use Sendcloud\PrestaShop\Classes\Bootstrap\ServiceRegister;
use Sendcloud\PrestaShop\Classes\Exceptions\MissingAPIKeyException;
use Sendcloud\PrestaShop\Classes\Services\Webhooks\WebhookService;

if (!defined('_PS_VERSION_')) {
    exit;
}

/**
 * Class SendOrderNotificationTask
 *
 * @package Sendcloud\PrestaShop\Classes\Tasks
 */
class SendOrderNotificationTask extends SerializedTask
{
    const INITIAL_PROGRESS_PERCENT = 5;

    /**
     * @var WebhookService
     */
    private $webhookService;
    /**
     * @var int
     */
    private $orderId;
    /**
     * @var int
     */
    private $statusId;
    /**
     * @var int
     */
    private $shopId;

    /**
     * SendOrderNotificationTask constructor
     *
     * @param int $orderId
     * @param int $statusId
     * @param int $shopId
     */
    public function __construct($orderId, $statusId, $shopId)
    {
        $this->orderId = $orderId;
        $this->statusId = $statusId;
        $this->shopId = $shopId;
    }

    /**
     * Runs task logic
     *
     * @return void
     *
     * @throws HttpAuthenticationException
     * @throws HttpCommunicationException
     * @throws HttpRequestException
     * @throws MissingAPIKeyException
     */
    public function execute()
    {
        try {
            $this->reportProgress(self::INITIAL_PROGRESS_PERCENT);

            $this->getWebhookService()->sendOrderNotifications($this->orderId, $this->statusId, $this->shopId);
        } catch (\Exception $e) {
            Logger::logError('Could not send order notifications' . $e->getMessage());

            throw $e;
        }

        $this->reportProgress(100);
    }

    /**
     * @return int
     */
    public function getOrderId()
    {
        return $this->orderId;
    }

    /**
     * @return int
     */
    public function getStatusId()
    {
        return $this->statusId;
    }

    /**
     * @return int
     */
    public function getShopId()
    {
        return $this->shopId;
    }

    /**
     * Convert object to array
     *
     * @return array
     */
    protected function toArray()
    {
        return [$this->orderId, $this->statusId, $this->shopId];
    }

    /**
     * Set object properties from array
     *
     * @param array $data
     */
    protected function fromArray(array $data)
    {
        list($this->orderId, $this->statusId, $this->shopId) = $data;
    }

    /**
     * @return array
     */
    protected function toAssocArray()
    {
        return [
            'orderId' => $this->orderId,
            'statusId' => $this->statusId,
            'shopId' => $this->shopId
        ];
    }

    /**
     * @param array $data
     *
     * @return void
     */
    protected function fromAssocArray(array $data)
    {
        $this->orderId = $data['orderId'];
        $this->statusId = $data['statusId'];
        $this->shopId = $data['shopId'];
    }


    /**
     * @return WebhookService
     */
    private function getWebhookService()
    {
        if ($this->webhookService === null) {
            $this->webhookService = ServiceRegister::getService(WebhookService::class);
        }

        return $this->webhookService;
    }
}
