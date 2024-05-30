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

namespace Sendcloud\PrestaShop\Classes\Bootstrap;

use SendCloud\BusinessLogic\Logger\DefaultLogger;
use SendCloud\BusinessLogic\Serializer\NativeSerializer;
use SendCloud\BusinessLogic\Serializer\Serializer;
use SendCloud\Infrastructure\Interfaces\Required\AsyncProcessStarter;
use SendCloud\Infrastructure\Interfaces\Required\Configuration;
use SendCloud\Infrastructure\Interfaces\Required\ShopLoggerAdapter;
use SendCloud\Infrastructure\Interfaces\Required\TaskQueueStorage;
use SendCloud\Infrastructure\Logger\Logger;
use SendCloud\Infrastructure\TaskExecution\Queue;
use SendCloud\Infrastructure\TaskExecution\TaskRunner;
use SendCloud\Infrastructure\TaskExecution\TaskRunnerStatusStorage;
use SendCloud\Infrastructure\TaskExecution\TaskRunnerWakeup;
use SendCloud\Infrastructure\Utility\Events\EventBus;
use SendCloud\Infrastructure\Utility\TimeProvider;
use Sendcloud\PrestaShop\Classes\Core\Infrastructure\Repositories\ProcessEntityRepository;
use Sendcloud\PrestaShop\Classes\Core\Infrastructure\Repositories\QueueItemRepository;
use Sendcloud\PrestaShop\Classes\Core\Infrastructure\Services\AsyncProcessStarterService;
use Sendcloud\PrestaShop\Classes\Core\Infrastructure\Services\HttpClientService;
use Sendcloud\PrestaShop\Classes\Core\Infrastructure\Services\LoggerService;
use Sendcloud\PrestaShop\Classes\Core\Infrastructure\Services\ProcessService;
use Sendcloud\PrestaShop\Classes\Core\Infrastructure\Services\TaskQueueStorageService;
use Sendcloud\PrestaShop\Classes\Proxies\SendcloudProxy;
use Sendcloud\PrestaShop\Classes\Repositories\CarrierRepository;
use Sendcloud\PrestaShop\Classes\Repositories\ConfigRepository;
use Sendcloud\PrestaShop\Classes\Repositories\ServicePointRepository;
use Sendcloud\PrestaShop\Classes\Repositories\WebserviceAPIRepository;
use Sendcloud\PrestaShop\Classes\Services\ApiWebService;
use Sendcloud\PrestaShop\Classes\Services\AuthService;
use Sendcloud\PrestaShop\Classes\Services\Carriers\CarrierService;
use Sendcloud\PrestaShop\Classes\Services\ConfigService;
use Sendcloud\PrestaShop\Classes\Services\ConnectService;
use SendCloud\Infrastructure\Interfaces\DefaultLoggerAdapter;
use Sendcloud\PrestaShop\Classes\Core\Business\Services\ConfigService as CoreConfigService;
use SendCloud\Infrastructure\Interfaces\Exposed\TaskRunnerWakeup as TaskRunnerWakeupInterface;
use SendCloud\Infrastructure\Interfaces\Exposed\TaskRunnerStatusStorage as TaskRunnerStatusStorageInterface;
use SendCloud\Infrastructure\ServiceRegister as CoreServiceRegister;
use Sendcloud\PrestaShop\Classes\Services\ServicePoints\ServicePointService;
use Sendcloud\PrestaShop\Classes\Services\Webhooks\WebhookService;
use SendCloud\Infrastructure\Utility\GuidProvider;
use Sendcloud\PrestaShop\Classes\Utilities\DBInitializer;

if (!defined('_PS_VERSION_')) {
    exit;
}

/**
 * Class Bootstrap
 *
 * @package Sendcloud\PrestaShop\Classes\Bootstrap
 */
class Bootstrap
{
    /**
     * Bootstrap init
     *
     * @return void
     */
    public static function init()
    {
        self::initCoreServices();
        self::initCoreRepositories();
        self::initServices();
        self::initRepositories();
        self::registerProxies();
    }

    /**
     * Register services
     *
     * @return void
     */
    public static function initServices()
    {
        ServiceRegister::registerService(ConfigService::class, function () {
            return new ConfigService();
        });
        ServiceRegister::registerService(AuthService::class, function () {
            return new AuthService();
        });
        ServiceRegister::registerService(ConnectService::class, function () {
            return new ConnectService();
        });
        ServiceRegister::registerService(ApiWebService::class, function () {
            return new ApiWebService();
        });
        ServiceRegister::registerService(WebhookService::class, function () {
            return new WebhookService(
                ServiceRegister::getService(SendcloudProxy::class),
                ServiceRegister::getService(ConfigService::class)
            );
        });
        ServiceRegister::registerService(ServicePointService::class, function () {
            return new ServicePointService();
        });
        ServiceRegister::registerService(CarrierService::class, function () {
            return new CarrierService();
        });
        ServiceRegister::registerService(DBInitializer::class, function () {
            return new DBInitializer();
        });
    }

    /**
     * Register repositories
     *
     * @return void
     */
    public static function initRepositories()
    {
        ServiceRegister::registerService(ConfigRepository::class, function () {
            return new ConfigRepository();
        });
        ServiceRegister::registerService(WebserviceAPIRepository::class, function () {
            return new WebserviceAPIRepository();
        });
        ServiceRegister::registerService(CarrierRepository::class, function () {
            return new CarrierRepository();
        });
        ServiceRegister::registerService(ServicePointRepository::class, function () {
            return new ServicePointRepository();
        });
    }

    /**
     * Register core services
     *
     * @return void
     */
    public static function initCoreServices()
    {
        ServiceRegister::registerService(ProcessService::class, function () {
            return new ProcessService();
        });
        ServiceRegister::registerService(LoggerService::class, function () {
            return new LoggerService();
        });
        CoreServiceRegister::registerService(AsyncProcessStarter::class, function () {
            return new AsyncProcessStarterService();
        });
        CoreServiceRegister::registerService(Serializer::class, function () {
            return new NativeSerializer();
        });
        ServiceRegister::registerService(HttpClientService::class, function () {
            return new HttpClientService();
        });
        ServiceRegister::registerService(CoreConfigService::class, function () {
            return new CoreConfigService();
        });
        CoreServiceRegister::registerService(Configuration::class, function () {
            return new CoreConfigService();
        });
        ServiceRegister::registerService(Logger::class, function () {
            return new Logger();
        });
        CoreServiceRegister::registerService(DefaultLoggerAdapter::class, function () {
            return new DefaultLogger;
        });
        CoreServiceRegister::registerService(ShopLoggerAdapter::class, function () {
            return new LoggerService();
        });
        CoreServiceRegister::registerService(TimeProvider::class, function () {
            return new TimeProvider();
        });
        ServiceRegister::registerService(Queue::class, function () {
            return new Queue();
        });
        CoreServiceRegister::registerService(TaskQueueStorage::class, function () {
            return new TaskQueueStorageService();
        });
        CoreServiceRegister::registerService(TaskRunnerWakeupInterface::class, function () {
            return new TaskRunnerWakeup();
        });
        CoreServiceRegister::registerService(TaskRunnerStatusStorageInterface::class, function () {
            return new TaskRunnerStatusStorage();
        });
        CoreServiceRegister::registerService(GuidProvider::class, function () {
            return new GuidProvider();
        });
        CoreServiceRegister::registerService(TaskRunner::class, function () {
            return new TaskRunner();
        });
        CoreServiceRegister::registerService(EventBus::class, function () {
            return EventBus::getInstance();
        });
        CoreServiceRegister::registerService(Queue::class, function () {
            return new Queue();
        });
    }

    /**
     * Register core repositories
     *
     * @return void
     */
    public static function initCoreRepositories()
    {
        ServiceRegister::registerService(ProcessEntityRepository::class, function () {
            return new ProcessEntityRepository();
        });
        ServiceRegister::registerService(QueueItemRepository::class, function () {
            return new QueueItemRepository();
        });
    }

    /**
     * Register proxies
     *
     * @return void
     */
    public static function registerProxies()
    {
        ServiceRegister::registerService(SendcloudProxy::class, function () {
            return new SendcloudProxy();
        });
    }
}
