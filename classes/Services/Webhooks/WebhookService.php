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

namespace Sendcloud\PrestaShop\Classes\Services\Webhooks;

use PrestaShop\PrestaShop\Adapter\Entity\Shop;
use SendCloud\Infrastructure\Logger\Logger;
use SendCloud\Infrastructure\Utility\Exceptions\HttpAuthenticationException;
use SendCloud\Infrastructure\Utility\Exceptions\HttpCommunicationException;
use SendCloud\Infrastructure\Utility\Exceptions\HttpRequestException;
use Sendcloud\PrestaShop\Classes\DTO\Webhooks\WebhookNotification;
use Sendcloud\PrestaShop\Classes\Exceptions\MissingAPIKeyException;
use Sendcloud\PrestaShop\Classes\Interfaces\ColumnNamesInterface;
use Sendcloud\PrestaShop\Classes\Proxies\SendcloudProxy;
use Sendcloud\PrestaShop\Classes\Services\ConfigService;
use Sendcloud\PrestaShop\Classes\Utilities\SHA256SignatureGenerator;

if (!defined('_PS_VERSION_')) {
    exit;
}

/**
 * Class WebhookService
 *
 * @package Sendcloud\PrestaShop\Classes\Services\Webhooks
 */
class WebhookService
{
    /**
     * @var SendcloudProxy
     */
    private $proxy;
    /**
     * @var ConfigService
     */
    private $configService;
    /**
     * @var string
     */
    private $webhookEndpoint;

    /**
     * @param SendcloudProxy $proxy
     * @param ConfigService $configService
     */
    public function __construct(SendcloudProxy $proxy, ConfigService $configService)
    {
        $this->proxy = $proxy;
        $this->configService = $configService;
    }

    /**
     * @param int $orderId
     * @param int $statusId
     * @param int $shopId
     *
     * @return void
     *
     * @throws HttpAuthenticationException
     * @throws HttpCommunicationException
     * @throws HttpRequestException
     * @throws MissingAPIKeyException
     */
    public function sendOrderNotifications($orderId, $statusId, $shopId)
    {
        $connectionSettings = $this->getConnectionSettings();
        $integrationId = $this->getIntegrationId($shopId);
        $this->validateData($connectionSettings, $integrationId);
        $this->setWebhookEndpoint('v1/webhooks/fetch-order/' . $integrationId);

        $payload = [
            'order_id' => $orderId,
            'order_status' => $statusId
        ];

        $this->sendNotification($connectionSettings, $integrationId, $payload, $shopId);
    }

    /**
     * @return void
     */
    public function sendUninstallOrderNotification()
    {
        try {
            $connectionSettings = $this->getConnectionSettings();
            $integrationId = $this->getIntegrationId();
            $this->validateData($connectionSettings, $integrationId);
            $this->setWebhookEndpoint('v1/auth/uninstall/');

            $payload = ['integration_id' => $integrationId];

            $this->sendNotification($connectionSettings, $integrationId, $payload);
        } catch (\Throwable $throwable) {
            Logger::logError("Error during sending the uninstallation notification: {$throwable->getMessage()}");
        }
    }

    /**
     * @param array $connectionSettings
     * @param string $integrationId
     * @param array $payload
     * @param int|null $shopId
     *
     * @return void
     * @throws HttpAuthenticationException
     * @throws HttpCommunicationException
     * @throws HttpRequestException
     */
    private function sendNotification(array $connectionSettings, $integrationId, array $payload, $shopId = null)
    {
        $signature = SHA256SignatureGenerator::generateSignature($connectionSettings['key'], $integrationId, $payload);
        $webhookNotification = new WebhookNotification(
            $this->createEventUrl($shopId),
            $signature,
            $payload
        );

        $this->proxy->sendNotificationsData($webhookNotification);
    }

    /**
     * Builds endpoint url for order events (order create and update events)
     *
     * @param int|null $shopId
     *
     * @return string
     */
    private function createEventUrl($shopId = null)
    {
        $currentShopId = $shopId ?: (int)Shop::getContextShopID(false);
        $webhookUrl = $this->configService->getConfigValueByShopIdAndName($currentShopId, ColumnNamesInterface::WEBHOOK_URL);

        return rtrim($webhookUrl, '/') . '/' . ltrim($this->webhookEndpoint, '/');
    }

    /**
     * @return array
     */
    private function getConnectionSettings(): array
    {
        return (array)json_decode($this->configService->getConfigValue(ColumnNamesInterface::CONNECT_SETTINGS), true);
    }

    /**
     * @param string $endpoint
     *
     * @return void
     */
    private function setWebhookEndpoint($endpoint)
    {
        $this->webhookEndpoint = $endpoint;
    }

    /**
     * @param int|null $shopId
     *
     * @return string
     */
    private function getIntegrationId($shopId = null)
    {
        $currentShopId = $shopId ?: (int)Shop::getContextShopID(false);

        return $this->configService->getConfigValueByShopIdAndName($currentShopId,ColumnNamesInterface::INTEGRATION_ID);
    }

    /**
     * @param array $connectionSettings
     * @param string $integrationId
     * @return void
     * @throws MissingAPIKeyException
     */
    private function validateData(array $connectionSettings, $integrationId)
    {
        if (empty($connectionSettings) || empty($connectionSettings['key']) || !$integrationId) {
            $message = 'Invalid api key or integration id when trying to send order notifications';
            Logger::logError($message);
            throw new MissingAPIKeyException($message);
        }
    }
}
