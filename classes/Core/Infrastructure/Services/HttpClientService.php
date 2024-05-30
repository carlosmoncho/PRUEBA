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

use SendCloud\Infrastructure\Utility\Exceptions\HttpCommunicationException;
use SendCloud\Infrastructure\Interfaces\Required\HttpClient;
use SendCloud\Infrastructure\Utility\Exceptions\HttpRequestException;
use SendCloud\Infrastructure\Utility\HttpResponse;
use Sendcloud\PrestaShop\Classes\Bootstrap\ServiceRegister;
use Sendcloud\PrestaShop\Classes\Core\Business\Services\ConfigService;

if (!defined('_PS_VERSION_')) {
    exit;
}

/**
 * Class HttpClientService
 *
 * @package Sendcloud\PrestaShop\Classes\Core\Infrastructure\Services
 */
class HttpClientService extends HttpClient
{
    /**
     * @var ConfigService
     */
    private $configService;
    /**
     * @var resource
     */
    protected $curlSession;

    /**
     * Create and send request
     *
     * @param string $method RESTful method (GET, POST, PUT, DELETE)
     * @param string $url address of endpoint
     * @param array $headers HTTP header
     * @param string $body In JSON format
     *
     * @return HttpResponse
     *
     * @throws HttpCommunicationException Only in situation when there is no connection, no response, throw this
     * @throws HttpRequestException
     *     exception
     */
    public function sendHttpRequest($method, $url, $headers = array(), $body = '')
    {
        $this->setCurlSessionAndCommonRequestParts($method, $url, $headers, $body);
        $this->setCurlSessionOptionsForSynchronousRequest();

        return $this->executeAndReturnResponseForSynchronousRequest($url);
    }

    /**
     * Creates and send request asynchronously
     *
     * @param string $method RESTful method (GET, POST, PUT, DELETE)
     * @param string $url address of endpoint
     * @param array $headers HTTP header
     * @param string $body In JSON format
     *
     * @throws HttpRequestException
     */
    public function sendHttpRequestAsync($method, $url, $headers = array(), $body = '')
    {
        $this->setCurlSessionAndCommonRequestParts($method, $url, $headers, $body);
        $this->setCurlSessionOptionsForAsynchronousRequest();

        curl_exec($this->curlSession);
    }

    /**
     * Executes curl and returns response as HttpResponse object
     *
     * @param string $url
     *
     * @return HttpResponse
     * @throws HttpCommunicationException
     */
    protected function executeAndReturnResponseForSynchronousRequest(string $url): HttpResponse
    {
        $apiResponse = curl_exec($this->curlSession);
        if ($apiResponse === false) {
            throw new HttpCommunicationException(
                'Request ' . $url . ' failed. ' . curl_error($this->curlSession), curl_errno($this->curlSession)
            );
        }

        $statusCode = curl_getinfo($this->curlSession, CURLINFO_HTTP_CODE);
        curl_close($this->curlSession);


        $apiResponse = $this->strip100Header($apiResponse);

        return new HttpResponse(
            $statusCode,
            $this->getHeadersFromCurlResponse($apiResponse),
            $this->getBodyFromCurlResponse($apiResponse)
        );
    }

    /**
     * Removes HTTP/1.1 100 if exist in api response
     *
     * @param string $response
     *
     * @return string
     */
    protected function strip100Header(string $response): string
    {
        $delimiter = "\r\n\r\n";
        $needle = 'HTTP/1.1 100';
        if (strpos($response, $needle) === 0) {
            return substr($response, strpos($response, $delimiter) + 4);
        }

        return $response;
    }

    /**
     * Returns header from api response
     *
     * @param string $response
     *
     * @return array
     */
    protected function getHeadersFromCurlResponse(string $response): array
    {
        $headers = [];
        $headersBodyDelimiter = "\r\n\r\n";
        $headerText = substr($response, 0, strpos($response, $headersBodyDelimiter));
        $headersDelimiter = "\r\n";

        foreach (explode($headersDelimiter, $headerText) as $i => $line) {
            if ($i === 0) {
                $headers[] = $line;
            } else {
                list($key, $value) = explode(': ', $line);
                $headers[$key] = $value;
            }
        }

        return $headers;
    }

    /**
     * Returns body from api response
     *
     * @param string $response
     *
     * @return string
     */
    protected function getBodyFromCurlResponse(string $response): string
    {
        $headersBodyDelimiter = "\r\n\r\n";
        $bodyStartingPositionOffset = 4; // number of special signs in delimiter;

        return substr(
            $response,
            strpos($response, $headersBodyDelimiter) + $bodyStartingPositionOffset
        );
    }

    /**
     * Creates curl session and sets common request parts (method, headers and body)
     *
     * @param string $method
     * @param string $url
     * @param array $headers
     * @param string $body
     *
     * @throws HttpRequestException
     */
    private function setCurlSessionAndCommonRequestParts(string $method, string $url, array $headers, string $body)
    {
        $this->initializeCurlSession();
        $this->setCurlSessionOptionsBasedOnMethod($method);
        $this->setCurlSessionUrlHeadersAndBody($url, $headers, $body);
        $this->setCommonOptionsForCurlSession();
    }

    /**
     * Initializes curl session
     * @throws HttpRequestException
     */
    private function initializeCurlSession()
    {
        $this->curlSession = curl_init();
        if ($this->curlSession === false) {
            throw new HttpRequestException('Curl failed to initialize session');
        }
    }

    /**
     * Sets curl options based on method name
     *
     * @param string $method
     */
    private function setCurlSessionOptionsBasedOnMethod(string $method)
    {
        if ($method === 'DELETE') {
            curl_setopt($this->curlSession, CURLOPT_CUSTOMREQUEST, 'DELETE');
        }

        if ($method === 'POST') {
            curl_setopt($this->curlSession, CURLOPT_POST, true);
        }

        if ($method === 'PUT') {
            curl_setopt($this->curlSession, CURLOPT_CUSTOMREQUEST, 'PUT');
        }
    }

    /**
     * Sets curl headers and body
     *
     * @param string $url
     * @param array $headers
     * @param string $body
     */
    private function setCurlSessionUrlHeadersAndBody(string $url, array $headers, string $body)
    {
        curl_setopt($this->curlSession, CURLOPT_URL, $url);
        curl_setopt($this->curlSession, CURLOPT_HTTPHEADER, $headers);
        if (!empty($body)) {
            curl_setopt($this->curlSession, CURLOPT_POSTFIELDS, $body);
        }
    }

    /**
     * Sets common curl options
     */
    private function setCommonOptionsForCurlSession()
    {
        curl_setopt($this->curlSession, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($this->curlSession, CURLOPT_FOLLOWLOCATION, true);
    }

    /**
     * Sets curl options for synchronous request
     */
    private function setCurlSessionOptionsForSynchronousRequest()
    {
        curl_setopt($this->curlSession, CURLOPT_HEADER, true);
    }

    /**
     * Sets curl options for async request
     */
    private function setCurlSessionOptionsForAsynchronousRequest()
    {
        $timeout = $this->getConfigService()->getAsyncRequestTimeout();
        // Always ensure the connection is fresh
        curl_setopt($this->curlSession, CURLOPT_FRESH_CONNECT, true);
        // Timeout super fast once connected, so it goes into async
        curl_setopt($this->curlSession, CURLOPT_TIMEOUT_MS, $timeout);
    }

    /**
     * Return instance of ConfigService
     *
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
