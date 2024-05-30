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

use PrestaShop\PrestaShop\Adapter\Entity\Shop;
use PrestaShop\PrestaShop\Adapter\Entity\Tools;
use SendCloud\Infrastructure\Logger\Logger;
use SendCloud\Infrastructure\TaskExecution\Exceptions\QueueStorageUnavailableException;
use SendCloud\Infrastructure\TaskExecution\Queue;
use SendCloud\Infrastructure\TaskExecution\QueueItem;
use Sendcloud\PrestaShop\Classes\Bootstrap\Bootstrap;
use Sendcloud\PrestaShop\Classes\Bootstrap\ServiceRegister;
use Sendcloud\PrestaShop\Classes\Core\Infrastructure\Repositories\QueueItemRepository;
use Sendcloud\PrestaShop\Classes\Interfaces\ColumnNamesInterface;
use Sendcloud\PrestaShop\Classes\Interfaces\HooksInterface;
use Sendcloud\PrestaShop\Classes\Services\Carriers\CarrierService;
use Sendcloud\PrestaShop\Classes\Services\ConfigService;
use Sendcloud\PrestaShop\Classes\Services\ApiWebService;
use Sendcloud\PrestaShop\Classes\Services\ServicePoints\ServicePointService;
use Sendcloud\PrestaShop\Classes\Services\Webhooks\WebhookService;
use Sendcloud\PrestaShop\Classes\Tasks\SendOrderNotificationTask;
use Sendcloud\PrestaShop\Classes\Core\Business\Services\ConfigService as CoreConfigService;
use Sendcloud\PrestaShop\Classes\Utilities\DBInitializer;
use Sendcloud\PrestaShop\Classes\Utilities\OverrideInstaller;
use Sendcloud\PrestaShop\Classes\Utilities\UtilityTools;
use SendCloud\BusinessLogic\Serializer\Serializer;

if (!defined('_PS_VERSION_')) {
    exit;
}

/** @noinspection PhpIncludeInspection */
require_once rtrim(_PS_MODULE_DIR_, '/') . '/sendcloudv2/vendor/autoload.php';

/**
 * Main SendCloud Shipping module class.
 *
 * It coordinates the module screens, installation, updgrades, activation and
 * deactivation of the Module.
 *
 * @author    SendCloud Global B.V. <contact@sendcloud.eu>
 * @copyright 2023 SendCloud Global B.V.
 * @license   http://opensource.org/licenses/afl-3.0.php  Academic Free License (AFL 3.0)
 *
 * @category  Shipping
 *
 * @see      https://sendcloud.eu
 */
class SendCloudv2 extends CarrierModule
{
    /**
     * @var CoreConfigService
     */
    private $coreConfigService;
    /**
     * @var ApiWebService
     */
    private $apiWebService;
    /**
     * @var ServicePointService
     */
    private $servicePointService;
    /**
     * @var CarrierService
     */
    private $carrierService;
    /**
     * @var DBInitializer
     */
    private $dbInitializer;
    /**
     * @var OverrideInstaller
     */
    private $overrideInstaller;
    /**
     * @var array
     */
    private $messages;

    /**
     * Module constructor
     */
    public function __construct()
    {
        $this->name = 'sendcloudv2';
        $this->tab = 'shipping_logistics';
        $this->version = '2.0.10';
        $this->author = 'Sendcloud';
        $this->author_uri = 'https://sendcloud.com';
        $this->need_instance = false;
        $this->ps_versions_compliancy = ['min' => '1.7', 'max' => '8.2.0'];
        $this->module_key = 'a0a8c0fad4fa55c40536e7aa8110dc99';

        parent::__construct();

        $this->displayName = $this->l('SendCloud | Europe\'s Number 1 Shipping Tool');

        /**
         * Using line breaks makes translations to _not_ work properly. We centralize most
         * translatable strings here to avoid spreading them in the module and to ease code review
         * and limit usage of the coding standards ignore comment below.
         * @codingStandardsIgnoreStart
         */
        $this->messages = [
            'smart_shipping' => $this->l('Smart shipping service for your online store. Save time and shipping costs.', $this->name),
            'warning_no_connection' => $this->l('You must connect with SendCloud before using this feature.', $this->name),
            'warning_carrier_not_found' => $this->l('Service Points were enabled but are not configured properly. Activate Service Points from the SendCloud Panel before using this feature.', $this->name),
            'warning_no_configuration' => $this->l('Service Points are not enabled. Please enable them on your SendCloud Panel before using this feature.', $this->name),
            'warning_carrier_inactive' => $this->l('Service Point Delivery carrier is not active. Activate the Carrier before using this feature.', $this->name),
            'warning_carrier_deleted' => $this->l('Service Point Delivery carrier is not active. Activate the Carrier before using this feature.', $this->name),
            'warning_carrier_zones' => $this->l('You must enable at least one shipping location for the Service Point Delivery carrier before using this feature.', $this->name),
            'warning_carrier_disabled_for_shop' => $this->l('The Service Point Delivery carrier is not enabled for the current active Shop.', $this->name),
            'warning_carrier_restricted' => $this->l('There are no Payment Methods associated with the Service Point Delivery carrier. Customers will not be able to select it during checkout', $this->name),
            'no_service_point' => $this->l('No service point data found.', $this->name),
            'unable_to_parse' => $this->l('Unable to parse service point data.', $this->name),
            'service_point_details' => $this->l('Service Point Details', $this->name)
        ];

        $this->description = $this->l('SendCloud helps to grow your online store by optimizing the shipping process. Shipping packages have never been that easy!');
        $this->confirmUninstall = $this->l('Are you sure you want to uninstall SendCloud?');

        Bootstrap::init();
    }

    /**
     * @param string $identifier
     *
     * @return mixed
     */
    public function getMessage($identifier)
    {
        if (!isset($this->messages[$identifier])) {
            // Explicitly forbid someone to retrieve any non-defined message
            throw new PrestaShopException('Message identifier not found.');
        }

        return $this->messages[$identifier];
    }

    /**
     * Install this module
     *
     * @return bool
     *
     * @throws PrestaShopDatabaseException
     */
    public function install()
    {
        return parent::install()
            && $this->installTab()
            && $this->createDatabaseTables()
            && $this->registerHooks();
    }

    /**
     * Install overridden files from the module.
     *
     * @return bool|int
     */
    public function installOverrides()
    {
        $this->uninstallOverrides();
        $installer = $this->getOverrideInstaller();
        if (!$installer->shouldInstallOverrides()) {
            return true;
        }

        return parent::installOverrides();
    }

    /**
     * Uninstall this module.
     *
     * @return bool
     */
    public function uninstall()
    {
        /** @var WebhookService $webhookService */
        $webhookService = ServiceRegister::getService(WebhookService::class);
        $webhookService->sendUninstallOrderNotification();

        return parent::uninstall()
            && $this->uninstallTab()
            && $this->eraseWebServiceAccountData()
            && $this->deleteConfiguration()
            && $this->deleteCarrierData()
            && $this->dropSendcloudTables()
            && $this->unregisterHooks();
    }


    /**
     * Standard settings page. It redirects to the administration screen
     * using `AdminSendcloudv2Controller`
     *
     * @return null
     */
    public function getContent()
    {
        Tools::redirectAdmin(
            $this->context->link->getAdminLink('AdminSendcloudv2')
        );
    }

    /**
     * SendCloud connection is shop-specific. If the end user opens the module configuration page
     * with any context other than an explicit shop (e.g: All shops, Shop Group), then we display a
     * message with instructions to switch to a Shop-specific view.
     *
     * @return string the image URL (according to the employee language definition)
     */
    public function getMultishopWarningImage()
    {
        if (Shop::getContextShopID(false) !== null) {
            return '';
        }

        $lang = new Language($this->context->employee->id_lang);
        $image = $this->_path . 'views/img/demo-select-shop.png';
        $file = sprintf('views/img/demo-select-shop-%s.png', $lang->language_code);

        $path = dirname(__FILE__) . '/' . $file;
        if (file_exists($path)) {
            $image = $this->_path . $file;
        }

        return $image;
    }

    /**
     * Hook for order creation.
     *
     * @param array $params
     *
     * @return void
     * @throws QueueStorageUnavailableException
     */
    public function hookActionValidateOrder($params)
    {
        $shopId = $params['order']->id_shop ?: Shop::getContextShopID();
        $webhookUrl = $this->getWebhookUrl($shopId);

        if ($webhookUrl && $this->isCreateDataValid($params)
            && $this->shouldTaskBeQueued($shopId, $params['order']->id, $params['orderStatus']->id)) {
            $this->getCoreConfigService()->setContext($shopId);
            /** @var Queue $queue */
            $queue = ServiceRegister::getService(Queue::CLASS_NAME);
            $task = new SendOrderNotificationTask($params['order']->id, $params['orderStatus']->id, $shopId);

            $queue->enqueue($this->getCoreConfigService()->getQueueName(), $task);
        }
    }

    /**
     * Hook for order update
     *
     * @param array $params
     *
     * @return void
     *
     * @throws QueueStorageUnavailableException
     */
    public function hookActionObjectOrderUpdateAfter($params)
    {
        $shopId = $params['object']->id_shop ? (int)$params['object']->id_shop : Shop::getContextShopID();
        $webhookUrl = $this->getWebhookUrl($shopId);

        if ($webhookUrl && $this->isUpdateDataValid($params)
            && $this->shouldTaskBeQueued($shopId, $params['object']->id, $params['object']->current_state)) {
            $this->getCoreConfigService()->setContext($shopId);
            /** @var Queue $queue */
            $queue = ServiceRegister::getService(Queue::CLASS_NAME);
            $task = new SendOrderNotificationTask($params['object']->id, $params['object']->current_state, $shopId);

            $queue->enqueue($this->getCoreConfigService()->getQueueName(), $task);
        }
    }

    /**
     * Hook after a new entity is added. Whenever a new `Configuration` entity is created we try
     * to activate service points. If the configuration is not service point-related, then
     * this hook is a noop.
     *
     * @param array $params parameters received by the hook, contain the target ` $object`
     *
     * @return void
     */
    public function hookActionObjectAddAfter(array $params)
    {
        $object = $params['object'] ?? null;
        $shop = $this->context->shop;

        try {
            $this->getServicePointService()->activateServicePoints($shop, $object);
        } catch (Exception $e) {
            Logger::logError('Unable to activate service points.' . $e->getMessage());
        }
    }

    /**
     * Inject some fixed metadata in the template used by all service point-based carriers.
     *
     * @param array $params
     * @return false|string
     */
    public function hookDisplayBeforeCarrier(array $params)
    {
        $cart = $params['cart'] ?? null;
        try {
            if ($cart === null || !$cart->id_address_delivery || !$this->getServicePointService()->servicePointsAvailable()) {
                return '';
            }

            $address = new Address($cart->id_address_delivery);
            $country = new Country($address->id_country);
            $context = $this->context;

            $servicePointData = $this->getServicePointService()->getByCartId($cart->id);

            $this->smarty->assign([
                'prestashop_flavor' => UtilityTools::getPrestashopVersion(),
                'cart' => $cart,
                'to_country' => $country->iso_code,
                'to_postal_code' => $address->postcode,
                'language' => $context->language->language_code,
                'service_point_details' => $servicePointData['details'],
                'save_endpoint' => $context->link->getModuleLink($this->name, 'ServicePointSelection'),
            ]);

            return $this->display(__FILE__, 'views/templates/hook/display-before-carrier.tpl');
        } catch (Exception $e) {
            Logger::logError('Could not save metadata.' . $e->getMessage());
        }

        return false;
    }

    /**
     * Track changes in the installed service point carrier (post 1.7)
     *
     * @param array $params
     *
     * @return bool
     * @throws \PrestaShop\PrestaShop\Adapter\Entity\PrestaShopException
     */
    public function hookActionCarrierUpdate(array $params)
    {
        $carrier = $params['carrier'] ?? null;

        if (is_null($carrier)) {
            $carrier = $params['new_carrier'] ?? null;
        }
        $this->getCarrierService()->updateCarrier($params['id_carrier'], $carrier);

        return true;
    }

    /**
     * Inject the required front office assets (CSS and JavaScript) to enable
     * make the service point selection work in the checkout page.
     *
     * @param array $params
     *
     * @return string additional header HTML to be added in the front office
     */
    public function hookDisplayHeader($params)
    {
        $cart = $params['cart'] ?? null;
        $controller = $this->context->controller ?? null;

        $allowedControllers = [
            'HistoryController',
            'OrderConfirmationController',
            'OrderController',
            'OrderOpcController',
        ];
        $isAllowed = !is_null($controller) && in_array(get_class($controller), $allowedControllers);

        if (!$isAllowed || !$cart) {
            // Load assets just in the order-related controllers.
            return '';
        }

        try {
            if (!$this->getServicePointService()->servicePointsAvailable()) {
                return '';
            }

            $script = $this->getConfigService()->getConfigValueByShopIdAndName((int)Shop::getContextShopID(false), ColumnNamesInterface::SENDCLOUD_SCRIPT);
            $controller->registerStylesheet(
                'module-sendcloud-frontstyles',
                'modules/' . $this->name . '/views/css/front.css',
                ['media' => 'screen']
            );

            $controller->registerJavascript(
                'module-sendcloud-script',
                $script,
                ['server' => 'remote']
            );
        } catch (Exception $e) {
            Logger::logError('Could not add service point script to checkout page.' . $e->getMessage());
        }

        return '';
    }

    /**
     * After the payment being successfuly accepted the order is created and
     * a confirmation screen is shown. We use it to send the service
     * point and order details back to SendCloud.
     *
     * @param array $params
     *
     * @return string
     *
     * @throws PrestaShopDatabaseException
     * @throws PrestaShopException
     * @throws \PrestaShop\PrestaShop\Adapter\Entity\PrestaShopException
     */
    public function hookDisplayOrderConfirmation(array $params)
    {
        $order = $params['objOrder'] ?? null;
        $order = $params['order'] ?? $order;

        if (!$order || !$this->getServicePointService()->servicePointsAvailable()) {
            return '';
        }
        $carrierIDs = $this->getCarrierService()->getSyncedCarriers(true);
        $cart = new Cart($order->id_cart);
        if (!$cart || !in_array($cart->id_carrier, $carrierIDs)) {
            return '';
        }

        $shop = $this->context->shop;
        $point = $this->getServicePointService()->getByCartId($order->id_cart);
        $deliveryAddress = new Address($order->id_address_delivery);
        $this->smarty->assign([
            'order' => $order,
            'shop_url' => $shop->getBaseURL(),
            'prestashop_flavor' => UtilityTools::getPrestashopVersion(),
            'delivery_address' => $deliveryAddress,
            'point_details' => json_decode($point['details']),
            'txt_service_point_details' => $this->getMessage('service_point_details'),
        ]);

        return $this->display(
            __FILE__,
            'views/templates/hook/order-confirmation.tpl'
        );
    }

    /**
     * Display the service point button
     *
     * @param array $params
     *
     * @return string
     */
    public function hookDisplayCarrierExtraContent(array $params)
    {
        $carrier = isset($params['carrier']) ? new Carrier($params['carrier']['id']) : null;
        $cart = $params['cart'] ?? null;
        try {
            if ($cart === null || $carrier === null || !$cart->id_address_delivery || !$this->getServicePointService()->servicePointsAvailable()) {
                return '';
            }
        } catch (Exception $e) {
            Logger::logError($e->getMessage());
        }

        $carrierCode = $this->getConfigService()->getCarrierCode($carrier);
        if ($carrierCode === null) {
            return '';
        }

        return $this->renderSelectionButton($carrier, $carrierCode);
    }

    /**
     * @param array $params
     *
     * @return string
     * @throws PrestaShopDatabaseException
     * @throws PrestaShopException
     * @throws \PrestaShop\PrestaShop\Adapter\Entity\PrestaShopException
     */
    public function hookDisplayAdminOrderMain($params)
    {
        $id_order = $params['id_order'] ?? null;
        $order = new Order($id_order);

        return $this->displayAdminOrderServicePoint($order);
    }

    /**
     * Add the service point details to the order confirmation e-mail
     * sent to the customer.
     *
     * @param array $params
     *
     * @return void
     */
    public function hookActionEmailAddAfterContent(array $params)
    {
        $template = $params['template'];
        if ($template !== 'order_conf') {
            return;
        }

        $cart = $this->context->cart;
        $point = $this->getServicePointService()->getByCartId($cart->id);
        if (!$point || !$point['id_service_point'] || !$point['details']) {
            return;
        }

        $this->smarty->assign(['point_details' => json_decode($point['details'])]);

        $detailsHtml = $this->display(
            __FILE__,
            'views/templates/hook/mail-order-confirmation.html'
        );

        $detailsTxt = $this->display(
            __FILE__,
            'views/templates/hook/mail-order-confirmation.txt'
        );

        $templateHtml = str_replace(
            '{delivery_block_html}',
            '{delivery_block_html}' . $detailsHtml,
            $params['template_html']
        );

        $templateTxt = str_replace(
            '{delivery_block_txt}',
            '{delivery_block_txt}' . $detailsTxt,
            $params['template_txt']
        );

        $this->setEmailTemplates($params, $templateHtml, $templateTxt);
    }

    /**
     * Adds hs_code and country_of_origin fields to Product page on Prestashop version < 8.1
     *
     * @param array $params
     *
     * @return false|string
     */
    public function hookDisplayAdminProductsMainStepLeftColumnMiddle($params)
    {
        $id = $params['id_product'];
        if (empty($id)) {
            return '';
        }
        $product = new Product($id);
        $this->context->smarty->assign('hs_code', $product->sc_hs_code);
        $this->context->smarty->assign('country_of_origin', $product->sc_country_of_origin);

        return $this->display(__FILE__, 'views/templates/admin/sendcloudv2/helpers/view/international-shipping.tpl');
    }

    /**
     * Adds hs_code and country_of_origin fields to Product page on Prestashop version >= 8.1
     *
     * @param array $params
     *
     * @return false|string
     */
    public function hookDisplayAdminProductsExtra($params)
    {
        if (Tools::version_compare(_PS_VERSION_, '8.1.0', '>=')) {
            $id = $params['id_product'];
            if (empty($id)) {
                return '';
            }
            $product = new Product($id);
            $this->context->smarty->assign('hs_code', $product->sc_hs_code);
            $this->context->smarty->assign('country_of_origin', $product->sc_country_of_origin);

            return $this->display(__FILE__, 'views/templates/admin/sendcloudv2/helpers/view/international-shipping.tpl');
        }

        return '';
    }

    /**
     * Saves hs_code and country_of_origin values on product
     *
     * @param array $params
     *
     * @return void
     * @throws PrestaShopException
     */
    public function hookActionProductUpdate($params)
    {
        $id = Tools::getValue('id_product');

        if ($id) {
            $product = new Product($id);

            $hsCode = Tools::getValue(ColumnNamesInterface::HS_CODE_FIELD);
            $countryOfOrigin = Tools::getValue(ColumnNamesInterface::COUNTRY_OF_ORIGIN_FIELD);

            //save hs code and country of origin on product
            if ($hsCode
                && $countryOfOrigin
                && ((int)$hsCode !== (int)$product->sc_hs_code || $countryOfOrigin !== $product->sc_country_of_origin)) {
                $product->sc_hs_code = (int)$hsCode;
                $product->sc_country_of_origin = $countryOfOrigin;

                $product->save();
            }
        }
    }

    /**
     * Do not apply any special rules to the shipping cost calculations but
     * ensure that service point configuration was done before to make this a
     * valid choice for the end user.
     *
     * @param Cart $cart
     * @param float $shipping_cost
     *
     * @return float The shipping costs. `false` if service points were not enabled.
     * @throws PrestaShopDatabaseException
     * @throws PrestaShopException
     */
    public function getOrderShippingCost($cart, $shipping_cost)
    {
        if (!$this->active || !$this->getServicePointService()->servicePointsAvailable() || !$cart->id_address_delivery) {
            return false;
        }

        return (float)$shipping_cost;
    }

    /**
     * Apply the same rules found in `SendcloudShipping::getOrderShippingCost()`
     *
     * @param object $params order params
     *
     * @return float
     * @throws PrestaShopDatabaseException
     * @throws PrestaShopException
     */
    public function getOrderShippingCostExternal($params)
    {
        return $this->getOrderShippingCost($params, null);
    }

    /**
     * Checks if order notifications task should be queued
     *
     * @param int $shopId
     * @param int $orderId
     * @param int $statusId
     *
     * @return bool
     */
    private function shouldTaskBeQueued($shopId, $orderId, $statusId)
    {
        /** @var QueueItemRepository $queueItemRepository */
        $queueItemRepository = ServiceRegister::getService(QueueItemRepository::class);
        $item = $queueItemRepository->findLatestByTypeAndQueue('SendOrderNotificationTask', $shopId);
        $task = $item ? Serializer::unserialize($item['serializedTask']) : null;

        if (!$item || !$task) {
            return true;
        }

        if (($item['status'] === QueueItem::QUEUED || $item['status'] === QueueItem::IN_PROGRESS) &&
            ($task->getOrderId() === $orderId && $task->getStatusId() === $statusId && $task->getShopId() === $shopId)) {
            return false;
        }

        return true;
    }

    /**
     * @param array $params
     * @param $templateHtml
     * @param $templateTxt
     *
     * @return void
     */
    private function setEmailTemplates(&$params, $templateHtml, $templateTxt)
    {
        $params['template_html'] = $templateHtml;
        $params['template_txt'] = $templateTxt;
    }

    /**
     * Helper method to display the details of the service point in the
     * back office.
     *
     * @param Order $order
     *
     * @return string
     * @throws PrestaShopException
     * @throws \PrestaShop\PrestaShop\Adapter\Entity\PrestaShopException
     */
    private function displayAdminOrderServicePoint(Order $order)
    {
        if (!$order->id) {
            return '';
        }

        $point = $this->getServicePointService()->getByCartId($order->id_cart);
        if (!$point) {
            return '';
        }

        $this->smarty->assign(
            [
                'point_details' => json_decode($point['details']),
                'txt_service_point_details' => $this->getMessage('service_point_details'),
            ]
        );

        return $this->display(__FILE__, 'views/templates/hook/admin-order-content-shipping.tpl');
    }

    /**
     * @param Carrier $carrier
     * @param $carrierCode
     *
     * @return false|string
     */
    private function renderSelectionButton(Carrier $carrier, $carrierCode)
    {
        $this->smarty->assign([
            'carrier' => $carrier,
            'carrier_code' => $carrierCode
        ]);

        return $this->display(
            __FILE__,
            'views/templates/hook/carrier-selection.tpl'
        );
    }

    /**
     * Check create order params
     *
     * @param array $params
     *
     * @return bool
     */
    private function isCreateDataValid($params)
    {
        return isset($params['order'])
            && $params['order']->id
            && isset($params['orderStatus'])
            && $params['orderStatus']->id;
    }

    private function isUpdateDataValid($params)
    {
        return isset($params['object'])
            && $params['object']->id
            && $params['object']->current_state;
    }

    /**
     * Creates the administration tab for the module. It can be found at
     * Administration > SendCloud Shipping after installation.
     *
     * @return bool true if the tab was successfully created
     */
    private function installTab()
    {
        $tab = new Tab();
        $tab->module = $this->name;
        $tab->active = true;
        $tab->class_name = 'AdminSendcloudv2';
        $tab->name = [];

        foreach (Language::getLanguages(true) as $lang) {
            $tab->name[$lang['id_lang']] = 'Sendcloudv2';
        }

        $parent = Tools::version_compare(_PS_VERSION_, '1.7.0.0', '>=') ?
            Tab::getIdFromClassName('AdminParentShipping') : Tab::getIdFromClassName('AdminShipping');
        $tab->id_parent = (int)$parent;

        return $tab->add();
    }

    /**
     * Removes the administration tab created by SendcloudShipping::installTab()
     *
     * @return bool
     */
    private function uninstallTab()
    {
        $idTab = (int)Tab::getIdFromClassName('AdminSendcloudv2');
        if ($idTab) {
            $tab = new Tab($idTab);

            return $tab->delete();
        }
        // A tab may not be created at all, so there's no reason to fail
        // uninstallation because of that.
        return true;
    }

    /**
     * Removes all api key related data when integration is uninstalled
     *
     * @return bool
     */
    private function eraseWebServiceAccountData()
    {
        $connectSettings = json_decode($this->getConfigService()->getConfigValue(ColumnNamesInterface::CONNECT_SETTINGS), true);

        if ($connectSettings && array_key_exists('id', $connectSettings)) {
            $this->getApiWebService()->eraseWebServiceAccountData($connectSettings['id']);
        }

        return true;
    }

    /**
     * Create Sendcloud tables
     *
     * @return bool
     * @throws PrestaShopDatabaseException
     */
    private function createDatabaseTables()
    {
        $dbInitializer = $this->getDBInitializer();

        return $dbInitializer->createSendCloudQueuesTable()
            && $dbInitializer->createSendCloudProcessesTable()
            && $dbInitializer->createServicePointTable()
            && $dbInitializer->updateProductTable();
    }

    /**
     * Delete all module carrier data
     *
     * @return bool
     */
    private function deleteCarrierData()
    {
        return $this->getDBInitializer()->deleteCarriersByExternalModuleName();
    }

    /**
     * Drop Sendcloud tables
     *
     * @return bool
     */
    private function dropSendcloudTables()
    {
        $this->getDBInitializer()->dropSendcloudTables();

        return true;
    }

    /**
     * Register prestashop hooks
     *
     * @return bool
     */
    private function registerHooks()
    {
        $result = true;

        foreach (HooksInterface::HOOKS as $hook) {
            $result = $result && $this->registerHook($hook);
        }

        return $result;
    }

    /**
     * Unregister prestashop hooks
     *
     * @return bool
     */
    private function unregisterHooks()
    {
        $result = true;

        foreach (HooksInterface::HOOKS as $hook) {
            $result = $result && $this->unregisterHook($hook);
        }

        return $result;
    }

    /**
     * Fetch Sendcloud webhook url from database
     *
     * @param int $shopId
     *
     * @return string|null
     */
    private function getWebhookUrl($shopId)
    {
        return $this->getConfigService()->getConfigValueByShopIdAndName($shopId, ColumnNamesInterface::WEBHOOK_URL);
    }

    /**
     * Delete Sendcloud configuration data
     *
     * @return bool
     */
    private function deleteConfiguration()
    {
        $this->getConfigService()->deleteConfigEntry(ColumnNamesInterface::CONNECT_SETTINGS);
        $this->getConfigService()->deleteConfigEntry(ColumnNamesInterface::INTEGRATION_ID);
        $this->getConfigService()->deleteConfigEntry(ColumnNamesInterface::WEBHOOK_URL);
        $this->getConfigService()->deleteConfigEntry(ColumnNamesInterface::SENDCLOUD_CARRIERS);
        $this->getConfigService()->deleteConfigEntry(ColumnNamesInterface::SENDCLOUD_SCRIPT);
        $this->getConfigService()->deleteConfigEntry(ColumnNamesInterface::WEB_SERVICE);
        $this->getConfigService()->deleteWhereNameLike(ColumnNamesInterface::SENDCLOUD_CARRIER_PREFIX);

        return true;
    }

    /**
     * Return an instance of ConfigService
     *
     * @return ConfigService
     */
    private function getConfigService()
    {
        return ServiceRegister::getService(ConfigService::class);
    }

    /**
     * Return an instance of ApiWebService
     *
     * @return ApiWebService
     */
    private function getApiWebService()
    {
        if ($this->apiWebService === null) {
            $this->apiWebService = ServiceRegister::getService(ApiWebService::class);
        }

        return $this->apiWebService;
    }

    /**
     * Return an instance of CoreConfigService
     *
     * @return CoreConfigService
     */
    private function getCoreConfigService()
    {
        if ($this->coreConfigService === null) {
            $this->coreConfigService = ServiceRegister::getService(CoreConfigService::class);
        }

        return $this->coreConfigService;
    }

    /**
     * Return an instance of ServicePointService
     *
     * @return CoreConfigService
     */
    private function getServicePointService()
    {
        if ($this->servicePointService === null) {
            $this->servicePointService = ServiceRegister::getService(ServicePointService::class);
        }

        return $this->servicePointService;
    }

    /**
     * Return an instance of CarrierService
     *
     * @return CoreConfigService
     */
    private function getCarrierService()
    {
        if ($this->carrierService === null) {
            $this->carrierService = ServiceRegister::getService(CarrierService::class);
        }

        return $this->carrierService;
    }

    /**
     * Return an instance of OverrideInstaller
     *
     * @return OverrideInstaller
     */
    private function getOverrideInstaller()
    {
        if ($this->overrideInstaller === null) {
            $this->overrideInstaller = new OverrideInstaller($this);
        }

        return $this->overrideInstaller;
    }

    /**
     * Return an instance of DBInitializer
     *
     * @return DBInitializer
     */
    private function getDBInitializer()
    {
        if ($this->dbInitializer === null) {
            $this->dbInitializer = new DBInitializer();
        }

        return $this->dbInitializer;
    }
}
