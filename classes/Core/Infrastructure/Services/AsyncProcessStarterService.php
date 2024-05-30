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

use PrestaShop\PrestaShop\Adapter\Entity\Shop;
use PrestaShop\PrestaShop\Adapter\Entity\Tools;
use SendCloud\Infrastructure\Interfaces\Exposed\Runnable;
use SendCloud\Infrastructure\Interfaces\Required\HttpClient;
use SendCloud\Infrastructure\Interfaces\Required\AsyncProcessStarter;
use SendCloud\Infrastructure\TaskExecution\Exceptions\ProcessStarterSaveException;
use SendCloud\Infrastructure\Utility\Exceptions\HttpRequestException;
use SendCloud\Infrastructure\Utility\GuidProvider;
use Sendcloud\PrestaShop\Classes\Bootstrap\ServiceRegister;
use Sendcloud\PrestaShop\Classes\Core\Infrastructure\Repositories\ProcessEntityRepository;
use Sendcloud\PrestaShop\Classes\Interfaces\ModuleInterface;
use SendCloud\BusinessLogic\Serializer\Serializer;

if (!defined('_PS_VERSION_')) {
    exit;
}

/**
 * Class AsyncProcessStarterService
 *
 * @package Sendcloud\PrestaShop\Classes\Core\Infrastructure\Services
 */
class AsyncProcessStarterService implements AsyncProcessStarter
{
    const ASYNC_PROCESS_CONTROLLER = 'AsyncProcess';

    /**
     * @var ProcessEntityRepository
     */
    private $processRepository;
    /**
     * @var HttpClient
     */
    private $httpClient;

    /**
     * Starts given runner asynchronously (in new process/web request or similar)
     *
     * @param Runnable $runner
     * @return void
     *
     * @throws HttpRequestException
     * @throws ProcessStarterSaveException
     */
    public function start(Runnable $runner)
    {
        $guidProvider = new GuidProvider();
        $guid = trim($guidProvider->generateGuid());

        $this->saveGuidAndRunner($guid, $runner);
        $this->startRunnerAsynchronously($guid);
    }

    /**
     * Sends async request to AsyncProcessController with guid as query parameter
     *
     * @param string $guid
     *
     * @return void
     * @throws HttpRequestException
     */
    public function startRunnerAsynchronously(string $guid)
    {
        try {
            $this->getHttpClientService()->requestAsync('GET', $this->formatAsyncProcessStartUrl($guid));
        } catch (\Exception $e) {
            throw new HttpRequestException($e->getMessage());
        }
    }

    /**
     * Saves guid and runner into process table
     *
     * @param string $guid
     * @param Runnable $runner
     *
     * @return void
     * @throws ProcessStarterSaveException
     */
    private function saveGuidAndRunner(string $guid, Runnable $runner)
    {
        try {
            $process = $this->getProcessEntityRepository()->getProcessByGuid($guid);

            if (!$process) {
                $this->getProcessEntityRepository()->createProcess($guid, Serializer::serialize($runner));
            } else {
                $this->getProcessEntityRepository()->updateProcess($process['id'], $guid, Serializer::serialize($runner));
            }
        } catch (\Exception $e) {
            throw new ProcessStarterSaveException($e->getMessage());
        }
    }

    /**
     * Returns async process controller url
     *
     * @param string $guid
     *
     * @return string
     */
    private function formatAsyncProcessStartUrl(string $guid): string
    {
        $shopId = Shop::getContextShopID();
        $shopDomain = Tools::getShopDomain($shopId, null);

        return $shopDomain . '/index.php?fc=module&module=' . ModuleInterface::MODULE_NAME
            . '&controller=' . self::ASYNC_PROCESS_CONTROLLER . '&guid=' . $guid;
    }

    /**
     * Return HttpClient service instance
     *
     * @return HttpClient
     */
    private function getHttpClientService()
    {
        if ($this->httpClient === null) {
            $this->httpClient = ServiceRegister::getService(HttpClientService::class);
        }

        return $this->httpClient;
    }

    /**
     * Return ProcessEntity repository instance
     *
     * @return ProcessEntityRepository
     */
    private function getProcessEntityRepository()
    {
        if ($this->processRepository === null) {
            $this->processRepository = ServiceRegister::getService(ProcessEntityRepository::class);
        }

        return $this->processRepository;
    }
}
