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

use SendCloud\Infrastructure\Logger\Logger;
use Sendcloud\PrestaShop\Classes\Bootstrap\Bootstrap;
use Sendcloud\PrestaShop\Classes\Bootstrap\ServiceRegister;
use Sendcloud\PrestaShop\Classes\Services\ServicePoints\ServicePointService;
use Sendcloud\PrestaShop\Classes\Utilities\UtilityTools;

if (!defined('_PS_VERSION_')) {
    exit;
}

/**
 * Class ServicePointSelection
 */
class Sendcloudv2ServicePointSelectionModuleFrontController extends ModuleFrontController
{
    /**
     * @var ServicePointService
     */
    private $servicePointService;

    /**
     * ServicePointSelection constructor
     */
    public function __construct()
    {
        parent::__construct();

        Bootstrap::init();
    }

    /**
     * Handles request
     *
     * @return void
     *
     * @throws PrestaShopException
     */
    public function init()
    {
        parent::init();

        $cart = $this->context->cart;
        $this->isSubmitAction($cart);

        $module = $this->module;
        $action = Tools::getValue('action', 'save');
        $details = Tools::getValue('service_point_data');
        $this->checkSubmitData($module, $action, $details);

        if (Tools::version_compare(_PS_VERSION_, '1.8.0.0', '>=')) {
            $pointData = json_decode($details);
        } else {
            $pointData = Tools::jsonDecode($details);
        }
        $this->checkPointData($module, $pointData, $action);
        $this->getServicePointService()->saveOrDeleteServicePoint($cart->id, $action, $details);

        UtilityTools::httpResponseCode(204); // No content
        $this->ajaxDie('');
    }

    /**
     * @param $cart
     *
     * @return void
     * @throws PrestaShopException
     */
    private function isSubmitAction($cart)
    {
        if (!Tools::isSubmit('ajax') || !$cart) {
            Logger::logError('Have not saved service point. Form is not submitted.');

            UtilityTools::httpResponseCode(404);
            $this->ajaxDie(false);
        }
    }

    /**
     * @param $module
     * @param string $action
     * @param string $details
     *
     * @return void
     * @throws PrestaShopException
     */
    private function checkSubmitData($module, $action, $details)
    {
        if (!$details && $action === 'save') {
            UtilityTools::httpResponseCode(400);
            Logger::logError('Could not save service point data. Submitted values are not valid');

            if (Tools::version_compare(_PS_VERSION_, '1.8.0.0', '>=')) {
                $this->ajaxDie(json_encode([
                    'error' => $module->getMessage('no_service_point'),
                ]));
            } else {
                $this->ajaxDie(Tools::jsonEncode([
                    'error' => $module->getMessage('no_service_point'),
                ]));
            }
        }
    }

    /**
     * @param $module
     * @param array $pointData
     * @param string $action
     *
     * @return void
     * @throws PrestaShopException
     */
    private function checkPointData($module, $pointData, $action)
    {
        if (!$pointData && $action === 'save') {
            UtilityTools::httpResponseCode(400);
            Logger::logError('Could not save service point data. Unable to parse service point data');

            if (Tools::version_compare(_PS_VERSION_, '1.8.0.0', '>=')) {
                $this->ajaxDie(json_encode([
                    'error' => $module->getMessage('unable_to_parse'),
                ]));
            } else {
                $this->ajaxDie(Tools::jsonEncode([
                    'error' => $module->getMessage('unable_to_parse'),
                ]));
            }
        }
    }

    /**
     * Returns an instance of ServicePointService
     *
     * @return ServicePointService
     */
    private function getServicePointService()
    {
        if ($this->servicePointService === null) {
            $this->servicePointService = ServiceRegister::getService(ServicePointService::class);
        }

        return $this->servicePointService;
    }
}
