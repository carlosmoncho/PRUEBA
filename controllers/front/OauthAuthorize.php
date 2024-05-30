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
use Sendcloud\PrestaShop\Classes\Interfaces\ColumnNamesInterface;
use Sendcloud\PrestaShop\Classes\Services\AuthService;
use Sendcloud\PrestaShop\Classes\Services\ConfigService;
use Sendcloud\PrestaShop\Classes\Services\Validators\OauthAuthorizeValidator;

if (!defined('_PS_VERSION_')) {
    exit;
}

/**
 * Class OAuthAuthorizeController
 */
class SendCloudv2OAuthAuthorizeModuleFrontController extends ModuleFrontController
{
    /**
     * @var AuthService
     */
    private $authService;
    /**
     * @var ConfigService
     */
    private $configService;

    /**
     * OauthAuthorizeController constructor
     */
    public function __construct()
    {
        parent::__construct();

        Bootstrap::init();
    }

    /**
     * Handles initial POST request
     *
     * @return void
     *
     * @throws PrestaShopDatabaseException
     * @throws PrestaShopException
     */
    public function postProcess()
    {
        try {
            //verifies request payload
            OauthAuthorizeValidator::verifyPayload($_GET, $this->context->controller->module->name, $_POST);
            $serviceKey = $this->getAuthService()->completeOAuth();

            //delete auth parameters from database
            $this->getConfigService()->deleteConfigEntry(ColumnNamesInterface::AUTH_PARAMS);

            $response = ['token' => $serviceKey->key];
        } catch (PrestaShopModuleException $exception) {
            Logger::logError('Error occurred during authorization: ' . $exception->getMessage());
            $response = ['error' => $exception->getMessage()];
        }

        // Set the JSON header and output the response
        header('Content-Type: application/json');
        echo json_encode($response);

        exit;
    }

    /**
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
     * @return ConfigService
     */
    private function getConfigService()
    {
        if ($this->configService === null) {
            $this->configService = ServiceRegister::getService(ConfigService::class);
        }

        return $this->configService;
    }
}
