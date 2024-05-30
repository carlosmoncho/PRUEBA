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

namespace Sendcloud\PrestaShop\Classes\Core\Business\Services;

use PrestaShop\PrestaShop\Adapter\Entity\Shop;
use PrestaShop\PrestaShop\Adapter\Entity\Tools;
use SendCloud\BusinessLogic\Interfaces\Configuration;
use SendCloud\Infrastructure\Logger\Logger;
use SendCloud\Infrastructure\TaskExecution\TaskRunnerStatus;
use Sendcloud\PrestaShop\Classes\Bootstrap\ServiceRegister;
use Sendcloud\PrestaShop\Classes\Interfaces\ColumnNamesInterface;
use Sendcloud\PrestaShop\Classes\Repositories\ConfigRepository;

if (!defined('_PS_VERSION_')) {
    exit;
}

/**
 * Class ConfigService
 *
 * @package Sendcloud\PrestaShop\Classes\Core\Business\Services
 */
class ConfigService implements Configuration
{
    const INTEGRATION_NAME = 'prestashop_v2';
    const ASYNC_PROCESS_TIMEOUT = 1000;
    const DEFAULT_BATCH_SIZE = 100;
    const TOKEN_VALID_FOR = 3600;
    const COMPLETED_TASKS_RETENTION_PERIOD = 604800;
    const FAILED_TASKS_RETENTION_PERIOD = 2592000;
    const OLD_TASKS_CLEANUP_THRESHOLD = 86400;
    const DEFAULT_MAX_STARTED_TASK_LIMIT = 64;

    /**
     * @var ConfigRepository
     */
    private $configRepository;
    /**
     * @var string
     */
    private $context;
    /**
     * @var array
     */
    private $userInfo;

    /**
     * Sets task execution context.
     *
     * When integration supports multiple accounts (middleware integration) proper context must be set based on
     * middleware account that is using core library functionality. This context should then be used by business
     * services to fetch account specific data.Core will set context provided upon task enqueueing before task
     * execution.
     *
     * @param string $context Context to set
     */
    public function setContext($context)
    {
        $this->context = $context;
    }

    /**
     * Gets task execution context
     *
     * @return string Context in which task is being executed. If no context is provided empty string is returned
     *     (global context)
     */
    public function getContext()
    {
        return $this->context;
    }

    /**
     * Gets integration queue name
     *
     * @return string
     */
    public function getQueueName(): string
    {
        $prefix = !empty($this->getContext()) ? $this->getContext() : '';

        return substr($prefix . '-' . $this->getIntegrationName(), 0, 50);
    }

    /**
     * Saves min log level in integration database
     *
     * @param int $minLogLevel
     * @return void
     */
    public function saveMinLogLevel($minLogLevel)
    {
        $this->getConfigRepository()->saveConfigValue('SENDCLOUD_MIN_LOG_LEVEL', $minLogLevel);
    }

    /**
     * Retrieves min log level from integration database
     *
     * @return int
     */
    public function getMinLogLevel()
    {
        $configValue = $this->getConfigRepository()->getValue('SENDCLOUD_MIN_LOG_LEVEL');

        return $configValue ? (int)$configValue : Logger::INFO;
    }

    /**
     * Save user information in integration database
     *
     * @param array $userInfo
     *
     * @return void
     */
    public function setUserInfo($userInfo)
    {
        $this->getConfigRepository()->saveConfigValue('SENDCLOUD_USER_INFO', json_encode($userInfo));
        $this->userInfo = $userInfo;
    }

    /**
     * Retrieves integration name
     *
     * @return string
     */
    public function getIntegrationName()
    {
        return self::INTEGRATION_NAME;
    }

    /**
     * Returns default batch size
     *
     * @return int
     */
    public function getDefaultBatchSize()
    {
        return (int)$this->getConfigRepository()->getValue('SENDCLOUD_BATCH_SIZE') ?: self::DEFAULT_BATCH_SIZE;
    }

    /**
     * Sets synchronization batch size.
     *
     * @param int $batchSize
     *
     * @return void
     */
    public function setDefaultBatchSize($batchSize)
    {
        $this->getConfigRepository()->saveConfigValue('SENDCLOUD_BATCH_SIZE', $batchSize);
    }

    public function resetAuthorizationCredentials()
    {
        // TODO: Implement resetAuthorizationCredentials() method.
    }

    /**
     * Set default logger status (enabled/disabled)
     *
     * @param bool $status
     *
     * @return void
     */
    public function setDefaultLoggerEnabled($status)
    {
        $this->getConfigRepository()->saveConfigValue('SENDCLOUD_DEFAULT_LOGGER_STATUS', $status);
    }

    /**
     * Return whether default logger is enabled or not
     *
     * @return bool
     */
    public function isDefaultLoggerEnabled()
    {
        return ((int)$this->getConfigRepository()->getValue('SENDCLOUD_DEFAULT_LOGGER_STATUS')) === 1;
    }

    public function getMaxStartedTasksLimit()
    {
        $maxStartedTaskLimit = $this->getConfigRepository()->getValue('maxStartedTasksLimit');

        return $maxStartedTaskLimit ?: static::DEFAULT_MAX_STARTED_TASK_LIMIT;
    }

    public function getTaskRunnerWakeupDelay()
    {
        // TODO: Implement getTaskRunnerWakeupDelay() method.
    }

    public function getTaskRunnerMaxAliveTime()
    {
        // TODO: Implement getTaskRunnerMaxAliveTime() method.
    }

    public function getMaxTaskExecutionRetries()
    {
        // TODO: Implement getMaxTaskExecutionRetries() method.
    }

    public function getMaxTaskInactivityPeriod()
    {
        // TODO: Implement getMaxTaskInactivityPeriod() method.
    }

    /**
     * @return array
     */
    public function getTaskRunnerStatus()
    {
        $status = json_decode($this->getConfigRepository()->getGlobalValue(ColumnNamesInterface::TASK_RUNNER_STATUS), true);

        if ($status === null) {
            $status = TaskRunnerStatus::createNullStatus();
        }

        return (array)$status;
    }

    /**
     * Sets task runner status information as JSON encoded string.
     *
     * @param string $guid
     * @param int $timestamp
     *
     * @return void
     */
    public function setTaskRunnerStatus($guid, $timestamp)
    {
        $taskRunnerStatus = json_encode(['guid' => $guid, 'timestamp' => $timestamp]);
        $this->getConfigRepository()->updateGlobalValue(ColumnNamesInterface::TASK_RUNNER_STATUS, $taskRunnerStatus);
    }

    /**
     * @return string
     */
    public function getSendCloudPanelUrl()
    {
        return 'https://panel.sendcloud.sc/';
    }

    /**
     * Retrieves integration id
     *
     * @return int
     */
    public function getIntegrationId()
    {
        return (int)$this->getConfigRepository()->getValue('SENDCLOUD_INTEGRATION_ID');
    }

    public function setIntegrationId($id)
    {
        // TODO: Implement setIntegrationId() method.
    }

    public function getPublicKey()
    {
        // TODO: Implement getPublicKey() method.
    }

    public function setPublicKey($publicKey)
    {
        // TODO: Implement setPublicKey() method.
    }

    public function getSecretKey()
    {
        // TODO: Implement getSecretKey() method.
    }

    public function setSecretKey($secretKey)
    {
        // TODO: Implement setSecretKey() method.
    }

    /**
     * Return base shop url
     *
     * @return string
     */
    public function getBaseUrl()
    {
        return Tools::getShopDomain(Shop::getContextShopID(), null);
    }

    public function getShopName()
    {
        // TODO: Implement getShopName() method.
    }

    public function getWebHookEndpoint($addToken = false)
    {
        // TODO: Implement getWebHookEndpoint() method.
    }

    public function getWebHookToken()
    {
        // TODO: Implement getWebHookToken() method.
    }

    /**
     * Checks if webhook token is valid
     *
     * @param string $token
     *
     * @return bool
     */
    public function isWebHookTokenValid($token)
    {
        $savedToken = $this->getConfigRepository()->getValue('WEBHOOK_TOKEN');
        $tokenTime = (int)$this->getConfigRepository()->getValue('WEBHOOK_TOKEN_TIME');

        $tokenValidUntil = $tokenTime + self::TOKEN_VALID_FOR;

        return $token === $savedToken && $tokenValidUntil >= time();
    }

    /**
     * Sets webhook token in configuration.
     *
     * @param string $token
     *
     * @return void
     */
    public function setWebHookToken($token)
    {
        $this->getConfigRepository()->saveConfigValue('WEBHOOK_TOKEN', $token);
    }

    /**
     * Sets webhook token time in configuration.
     *
     * @param int $time
     *
     * @return void
     */
    public function setWebHookTokenTime($time)
    {
        $this->getConfigRepository()->saveConfigValue('WEBHOOK_TOKEN_TIME', $time);
    }

    public function isServicePointEnabled()
    {
        // TODO: Implement isServicePointEnabled() method.
    }

    public function setServicePointEnabled($enabled)
    {
        // TODO: Implement setServicePointEnabled() method.
    }

    public function getCarriers()
    {
        // TODO: Implement getCarriers() method.
    }

    /**
     * Sets a list of available carriers
     *
     * @param array $carriers
     *
     * @return void
     */
    public function setCarriers(array $carriers = array())
    {
        $this->getConfigRepository()->saveConfigValue('SENDCLOUD_CARRIERS', json_encode($carriers));
        $this->getConfigRepository()->saveConfigValue('SENDCLOUD_CONFIG_UPDATE_DATE', time());
    }

    /**
     * @inheritDoc
     */
    public function getCompletedTasksRetentionPeriod()
    {
        $configValue = $this->getConfigRepository()->getValue('SENDCLOUD_COMPLETED_TASKS_RETENTION_PERIOD');

        return $configValue ?? self::COMPLETED_TASKS_RETENTION_PERIOD;
    }

    /**
     * @inheritDoc
     */
    public function getFailedTasksRetentionPeriod()
    {
        $configValue = $this->getConfigRepository()->getValue('SENDCLOUD_FAILED_TASKS_RETENTION_PERIOD');

        return $configValue ?? self::FAILED_TASKS_RETENTION_PERIOD;
    }

    /**
     * @inheritDoc
     */
    public function getOldTaskCleanupTimeThreshold()
    {
        $configValue = $this->getConfigRepository()->getValue('SENDCLOUD_OLD_TASKS_CLEANUP_THRESHOLD');

        return $configValue ?? self::OLD_TASKS_CLEANUP_THRESHOLD;
    }

    /**
     * @inheritDoc
     */
    public function getOldTaskCleanupQueueName()
    {
        return 'oldTaskCleanup';
    }

    /**
     * Returns timeout for async request
     *
     * @return int
     */
    public function getAsyncRequestTimeout(): int
    {
        try {
            $configValue = $this->getConfigRepository()->getValue('SENDCLOUD_ASYNC_REQUEST_TIMEOUT');

            return $configValue ? (int)$configValue : self::ASYNC_PROCESS_TIMEOUT;
        } catch (\Exception $exception) {
            Logger::logError(
                "An error occurred when reading async request timeout from config table: {$exception->getMessage()}",
                'Integration'
            );

            return self::ASYNC_PROCESS_TIMEOUT;
        }
    }

    /**
     * @return string
     */
    public function getBaseApiUrl()
    {
        return 'https://panel.sendcloud.sc/';
    }

    /**
     * @return string
     */
    public function getConnectUrl()
    {
        return 'https://panel.sendcloud.sc/';
    }

    /**
     * @return string
     */
    public function getSendcloudBackendUrl()
    {
        return 'https://panel.sendcloud.sc/';
    }

    /**
     * Return instance of ConfigRepository
     *
     * @return ConfigRepository
     */
    private function getConfigRepository()
    {
        if ($this->configRepository === null) {
            $this->configRepository = ServiceRegister::getService(ConfigRepository::class);
        }

        return $this->configRepository;
    }
}
