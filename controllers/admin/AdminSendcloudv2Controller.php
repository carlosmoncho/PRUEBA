<?php
/**
 * Holds the main administration screen controller of the module.
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

use Sendcloud\PrestaShop\Classes\Bootstrap\Bootstrap;
use Sendcloud\PrestaShop\Classes\Bootstrap\ServiceRegister;
use Sendcloud\PrestaShop\Classes\Services\AuthService;
use Sendcloud\PrestaShop\Classes\Services\Carriers\CarrierService;
use Sendcloud\PrestaShop\Classes\Services\ConnectService;
use Sendcloud\PrestaShop\Classes\Utilities\UtilityTools;

if (!defined('_PS_VERSION_')) {
    exit;
}

/**
 * Class AdminSendcloudv2Controller
 */
class AdminSendcloudv2Controller extends ModuleAdminController
{
    /**
     * @var ConnectService
     */
    private $connectService;
    /**
     * @var AuthService $authService
     */
    private $authService;
    /**
     * @var CarrierService
     */
    private $carrierService;

    /**
     * Configure the administration controller and define some sane defaults.
     */
    public function __construct()
    {
        $this->bootstrap = true;
        $this->display = 'view';
        parent::__construct();

        // Set the page title using PrestaShop's translation system
        $this->meta_title = $this->module->getMessage('smart_shipping');

        Bootstrap::init();
    }

    /**
     * Render either Welcome or Dashboard page based on whether integration is connected or not
     *
     * @return string
     * @throws PrestaShopException
     * @see    views/templates/admin/sendcloud/helpers/view/view.tpl
     */
    public function renderView()
    {
        $canConnect = !$this->getConnectService()->isIntegrationConnected();
        $connectUrl = $this->getConnectService()->getConnectUrl($this->context->shop);
        $goToPanelUrl = UtilityTools::getPanelURL();
        $adminJsFilePath = UtilityTools::getBaseShopUrl($_SERVER) . '/modules/' . $this->context->controller->module->name . '/views/js/admin/';
        $checkStatusControllerUrl = $this->context->link->getAdminLink('AdminCheckStatus');
        $carriers = $this->getCarrierService()->displayCarriersOnPluginPage($this->context->link->getAdminLink('AdminCarrierWizard'));
        $servicePointWarning = $this->getCarrierService()->getCarrierWarningMessage($carriers, $this->module, !$canConnect);

        $this->base_tpl_view = 'view.tpl';

        $this->tpl_view_vars = [
            'can_connect' => $canConnect,
            'prestashop_version' => UtilityTools::getPrestashopVersion(),
            'prestashop_webservice_docs' => UtilityTools::getDocumentationLinks(),
            'sendcloud_panel_url' => $goToPanelUrl,
            'connect_url' => $connectUrl,
            'api_resources' => $this->getAuthService()->getApiResources(),
            'admin_js_file_path' => $adminJsFilePath,
            'controller_url' => $checkStatusControllerUrl,
            'multishop_warning' => $this->module->getMultishopWarningImage(),
            'is_module_active' => $this->module->active,
            'service_point_carriers' => $carriers,
            'service_point_warning' => $servicePointWarning
        ];

        return parent::renderView();
    }

    /**
     * Change the toolbar title to not include anything other than what's explicitly
     * set here.
     *
     * @return void
     */
    public function initToolbarTitle()
    {
        $this->toolbar_title[] = 'SendCloud V2';
    }

    /**
     * Injects assets in the administration page.
     *
     * @return string
     */
    public function setMedia($isNewTheme = false)
    {
        $assetsBase = _MODULE_DIR_ . $this->module->name;

        $this->addJS($assetsBase . '/views/js/admin/ajax.js');
        $this->addJS($assetsBase . '/views/js/admin/form.js');
        $this->addCSS(
            [
                $assetsBase . '/views/css/backoffice.css'
            ]
        );

        return parent::setMedia($isNewTheme);
    }

    /**
     * Returns an instance of ConnectService
     *
     * @return ConnectService
     */
    private function getConnectService()
    {
        if ($this->connectService === null) {
            $this->connectService = ServiceRegister::getService(ConnectService::class);
        }

        return $this->connectService;
    }

    /**
     * Returns an instance of AuthService
     *
     * @return AuthService
     */
    private function getAuthService()
    {
        if ($this->authService === null) {
            $this->authService = ServiceRegister::getService(AuthService::class);
        }

        return $this->authService;
    }

    /**
     * Returns an instance of CarrierService
     *
     * @return CarrierService
     */
    private function getCarrierService()
    {
        if ($this->carrierService === null) {
            $this->carrierService = ServiceRegister::getService(CarrierService::class);
        }

        return $this->carrierService;
    }
}
