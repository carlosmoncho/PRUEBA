<?php
/**
 * Utility class for SendCloud module.
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

namespace Sendcloud\PrestaShop\Classes\Proxies;

use SendCloud\Infrastructure\Logger\Logger;
use SendCloud\Infrastructure\Utility\Exceptions\HttpAuthenticationException;
use SendCloud\Infrastructure\Utility\Exceptions\HttpCommunicationException;
use SendCloud\Infrastructure\Utility\Exceptions\HttpRequestException;
use SendCloud\Infrastructure\Utility\HttpResponse;
use Sendcloud\PrestaShop\Classes\Core\Infrastructure\Services\HttpClientService;
use Sendcloud\PrestaShop\Classes\Bootstrap\ServiceRegister;
use Sendcloud\PrestaShop\Classes\DTO\Http\HttpRequest;
use Sendcloud\PrestaShop\Classes\DTO\Webhooks\WebhookNotification;

if (!defined('_PS_VERSION_')) {
    exit;
}

/**
 * Class SendcloudProxy
 *
 * @package Sendcloud\PrestaShop\Classes\Proxies
 */
class SendcloudProxy
{
    const HTTP_STATUS_CODE_UNAUTHORIZED = 401;
    const HTTP_STATUS_CODE_FORBIDDEN = 403;

    /**
     * @var HttpClientService
     */
    private $client;

    /**
     * SendcloudProxy constructor
     */
    public function __construct()
    {
        $this->client = ServiceRegister::getService(HttpClientService::class);
    }

    /**
     * Send notification data to Sendcloud
     *
     * @param WebhookNotification $webhookNotification
     *
     * @return void
     *
     * @throws HttpAuthenticationException
     * @throws HttpCommunicationException
     * @throws HttpRequestException
     */
    public function sendNotificationsData(WebhookNotification $webhookNotification)
    {
        $httpRequest = new HttpRequest(
            $webhookNotification->getUrl(),
            'POST',
            $webhookNotification->getPayload(),
            ['token' => 'X-SC-Signature: ' . $webhookNotification->getSignature()]
        );

        $this->call($httpRequest);
    }

    /**
     * Call http client
     *
     * @param HttpRequest $httpRequest
     * @return HttpResponse
     *
     * @throws HttpAuthenticationException
     * @throws HttpCommunicationException
     * @throws HttpRequestException
     */
    protected function call(HttpRequest $httpRequest)
    {
        $bodyStringToSend = '';
        if (in_array(strtoupper($httpRequest->getMethod()), array('POST', 'PUT'))) {
            $bodyStringToSend = json_encode($httpRequest->getBody());
        }
        $headers = $this->getHeaders($httpRequest->getHeaders());

        $response = $this->client->request($httpRequest->getMethod(), $httpRequest->getUrl(), $headers, $bodyStringToSend);
        $this->validateResponse($response);

        return $response;
    }

    /**
     * Return request headers
     *
     * @param array $headers
     *
     * @return array
     */
    protected function getHeaders($headers)
    {
        $baseHeaders = [
            'accept' => 'Accept: application/json',
            'content' => 'Content-Type: application/json'
        ];

        return !empty($headers) ? array_merge($baseHeaders, $headers) : $baseHeaders;
    }

    /**
     * Validate response from Sendcloud api
     *
     * @param HttpResponse $response
     *
     * @return void
     *
     * @throws HttpAuthenticationException
     * @throws HttpRequestException
     */
    protected function validateResponse(HttpResponse $response)
    {
        if (!$response->isSuccessful()) {
            $httpCode = $response->getStatus();
            $message = $body = $response->getBody();
            $error = json_decode($body, true);
            if (is_array($error)) {
                if (isset($error['error']['message'])) {
                    $message = $error['error']['message'];
                }

                if (isset($error['error']['code'])) {
                    $httpCode = $error['error']['code'];
                }
            }

            Logger::logWarning($message);
            if ($httpCode === self::HTTP_STATUS_CODE_UNAUTHORIZED
                || $httpCode === self::HTTP_STATUS_CODE_FORBIDDEN
            ) {
                throw new HttpAuthenticationException($message, $httpCode);
            }

            throw new HttpRequestException($message, $httpCode);
        }
    }
}
