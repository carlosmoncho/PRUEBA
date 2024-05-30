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

namespace Sendcloud\PrestaShop\Classes\DTO\Http;

use Sendcloud\PrestaShop\Classes\DTO\AbstractDTO;

if (!defined('_PS_VERSION_')) {
    exit;
}

/**
 * Class HttpRequest
 *
 * @package Sendcloud\PrestaShop\Classes\DTO\Http
 */
class HttpRequest extends AbstractDTO
{
    /**
     * @var string
     */
    private $method;
    /**
     * @var string
     */
    private $url;
    /**
     * @var array
     */
    private $body;
    /**
     * @var array
     */
    private $headers;
    /**
     * @var array
     */
    private $parameters;

    /**
     * @param string $url
     * @param string $method
     * @param array $body
     * @param array $headers
     * @param array $parameters
     */
    public function __construct($url, $method = '',  array $body = [], array $headers = [], array $parameters = [])
    {
        $this->url = $url;
        $this->method = $method;
        $this->body = $body;
        $this->headers = $headers;
        $this->parameters = $parameters;
    }

    public function getMethod(): string
    {
        return $this->method;
    }

    public function setMethod(string $method)
    {
        $this->method = $method;
    }

    public function getUrl(): string
    {
        return $this->url;
    }

    public function setUrl(string $url)
    {
        $this->url = $url;
    }

    public function getBody(): array
    {
        return $this->body;
    }

    public function setBody(array $body)
    {
        $this->body = $body;
    }

    public function getHeaders(): array
    {
        return $this->headers;
    }

    public function setHeaders(array $headers)
    {
        $this->headers = $headers;
    }

    public function getParameters(): array
    {
        return $this->parameters;
    }

    public function setParameters(array $parameters)
    {
        $this->parameters = $parameters;
    }

    /**
     * @return array
     */
    public function toArray()
    {
        return [
            'method' => $this->method,
            'url' => $this->url,
            'body' => $this->body,
            'headers' => $this->headers,
            'parameters' => $this->parameters
        ];
    }

    /**
     * @param array $data
     *
     * @return HttpRequest
     */
    public static function fromArray(array $data)
    {
        return new self(
            self::getValue($data, 'method'),
            self::getValue($data, 'url'),
            self::getValue($data, 'body'),
            self::getValue($data, 'headers'),
            self::getValue($data, 'parameters')
        );
    }
}
