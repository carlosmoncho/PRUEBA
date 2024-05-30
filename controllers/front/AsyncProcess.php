<?php
/**
 * SendCloud | Smart Shipping Service
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

use SendCloud\Infrastructure\Interfaces\Exposed\Runnable;
use SendCloud\Infrastructure\Logger\Logger;
use Sendcloud\PrestaShop\Classes\Bootstrap\Bootstrap;
use Sendcloud\PrestaShop\Classes\Bootstrap\ServiceRegister;
use Sendcloud\PrestaShop\Classes\Core\Infrastructure\Services\ProcessService;
use SendCloud\BusinessLogic\Serializer\Serializer;

if (!defined('_PS_VERSION_')) {
    exit;
}

/**
 * Class AsyncProcessController
 */
class Sendcloudv2AsyncProcessModuleFrontController extends ModuleFrontController
{
    /**
     * @var ProcessService
     */
    private $processService;

    /**
     * AsyncProcess constructor
     */
    public function __construct()
    {
        parent::__construct();

        Bootstrap::init();
    }

    /**
     * Handle initial request
     *
     * @return void
     */
    public function init()
    {
        try {
            $guid = Tools::getValue('guid');
            $processEntity = $this->getProcessService()->getProcessByGuid($guid);
            if ($processEntity) {
                /** @var Runnable $runner */
                $runner = Serializer::unserialize($processEntity['runner']);
                $runner->run();
            }

            $this->getProcessService()->deleteByGuid($guid);
        } catch (Exception $exception) {
            Logger::logError('Error occurred while trying to start task runner: ' . $exception->getMessage());
        }

        // Set the JSON header and output the response
        header('Content-Type: application/json');
        echo json_encode(['success' => true]);

        exit;
    }

    /**
     * Return instance of ProcessService
     *
     * @return ProcessService
     */
    private function getProcessService()
    {
        if ($this->processService === null) {
            $this->processService = ServiceRegister::getService(ProcessService::class);
        }

        return $this->processService;
    }
}
