<?php
/**
 * SendCloud | Smart Shipping Service
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

use Sendcloud\PrestaShop\Classes\Bootstrap\Bootstrap;
use Sendcloud\PrestaShop\Classes\Bootstrap\ServiceRegister;
use Sendcloud\PrestaShop\Classes\Services\AuthService;
use Sendcloud\PrestaShop\Classes\Services\Validators\OauthConnectValidator;
use Sendcloud\PrestaShop\Classes\Exceptions\InvalidPayloadException;

if (!defined('_PS_VERSION_')) {
    exit;
}

/**
 * Class OAuthConnectController
 */
class SendCloudv2OAuthConnectModuleFrontController extends ModuleFrontController
{
    /**
     * @var AuthService
     */
    private $authService;

    /**
     * OauthConnectController constructor
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
     * @throws InvalidPayloadException
     */
    public function init()
    {
        //verifies request payload
        OauthConnectValidator::verifyPayload($_GET, $this->context->controller->module->name);

        //generates authorization code and saves code and code_challenge to the database
        $code = $this->getAuthService()->saveAuthorizationData(Tools::getValue('code_challenge'));

        Tools::redirect($this->getAuthService()->generateRedirectUrl(Tools::getValue('redirect_uri'), $code, Tools::getValue('state')));
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
}
