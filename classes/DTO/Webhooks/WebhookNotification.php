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

namespace Sendcloud\PrestaShop\Classes\DTO\Webhooks;

use Sendcloud\PrestaShop\Classes\DTO\AbstractDTO;

if (!defined('_PS_VERSION_')) {
    exit;
}

/**
 * Class WebhookNotification
 *
 * @package Sendcloud\PrestaShop\Classes\DTO\Webhooks
 */
class WebhookNotification extends AbstractDTO
{
    /**
     * @var string
     */
    private $url;
    /**
     * @var string
     */
    private $signature;
    /**
     * @var array
     */
    private $payload;

    /**
     * @param string $url
     * @param string $signature
     * @param array $payload
     */
    public function __construct($url, $signature, $payload)
    {
        $this->url = $url;
        $this->signature = $signature;
        $this->payload = $payload;
    }

    public function getUrl(): string
    {
        return $this->url;
    }

    public function setUrl(string $url)
    {
        $this->url = $url;
    }

    public function getSignature(): string
    {
        return $this->signature;
    }

    public function setSignature(string $signature)
    {
        $this->signature = $signature;
    }

    public function getPayload(): array
    {
        return $this->payload;
    }

    public function setPayload(array $payload)
    {
        $this->payload = $payload;
    }

    /**
     * Saves object as array representation
     *
     * @return array
     */
    public function toArray()
    {
        return [
            'url' => $this->getUrl(),
            'signature' => $this->getSignature(),
            'payload' => $this->payload
        ];
    }

    /**
     * Transforms array to WebhookNotification object
     *
     * @param $data
     *
     * @return WebhookNotification
     */
    public static function fromArray($data)
    {
        return new self(
            self::getValue($data, 'url'),
            self::getValue($data, 'signature'),
            self::getValue($data, 'payload')
        );
    }
}
