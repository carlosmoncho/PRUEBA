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
use Sendcloud\PrestaShop\Classes\Services\ConnectService;

if (!defined('_PS_VERSION_')) {
    exit;
}

/**
 * Class AdminCheckStatusController
 */
class AdminCheckStatusController extends ModuleAdminController
{
    /**
     * @var ConnectService
     */
    private $connectService;

    /**
     * AdminCheckStatusController constructor
     *
     * @throws PrestaShopException
     */
    public function __construct()
    {
        parent::__construct();

        Bootstrap::init();
    }

    /**
     * Handles initial GET request
     *
     * @return void
     */
    public function init()
    {
        $isHttpsRequest = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on');

        //enabling CORS for http requests (for local testing)
        if (!$isHttpsRequest) {
            header("Access-Control-Allow-Origin: http://" . $_SERVER['SERVER_NAME']);
        }

        // Create a sample JSON response data
        $responseData = ['isConnected' => $this->getConnectService()->isIntegrationConnected()];

        // Set the JSON response headers
        header('Content-Type: application/json');

        // Encode the response data as JSON and output it
        echo json_encode($responseData);

        // Prevent PrestaShop from rendering the template
        die();
    }

    /**
     * @return ConnectService
     */
    private function getConnectService()
    {
        if ($this->connectService === null) {
            $this->connectService = ServiceRegister::getService(ConnectService::class);
        }

        return $this->connectService;
    }
}
