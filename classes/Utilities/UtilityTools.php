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

namespace Sendcloud\PrestaShop\Classes\Utilities;

use PrestaShop\PrestaShop\Adapter\Entity\PrestaShopException;
use PrestaShop\PrestaShop\Adapter\Entity\Tools;

if (!defined('_PS_VERSION_')) {
    exit;
}

/**
 * Class SendcloudTools
 *
 * @package Sendcloud\PrestaShop\Classes\Utilities
 */
class UtilityTools
{
    /**
     * Get a more general representation of the current PrestaShop version
     *
     * @return string
     *
     * @throws PrestaShopException when a non-supported version is detected
     */
    public static function getPrestashopVersion()
    {
        if (Tools::version_compare(_PS_VERSION_, '8.0.0.0', '>=')) {
            return 'ps80';
        }
        if (Tools::version_compare(_PS_VERSION_, '1.7.0.0', '>=')) {
            return 'ps17';
        }

        throw new PrestaShopException('Unsupported PrestaShop version.');
    }

    /**
     * Get the URL to the Webservice documentation related to the current PrestaShop
     * version.
     *
     * @return string
     */
    public static function getDocumentationLinks()
    {
        $psDocs = [
            'ps17' => 'http://doc.prestashop.com/display/PS17',
            'ps80' => 'https://devdocs.prestashop-project.org/8/',
        ];

        return $psDocs[self::getPrestashopVersion()];
    }

    /**
     * Retrieve the SendCloud Panel URL. Testing and pointing to other environments
     * could be done by setting an env variable `SENDCLOUD_PANEL_URL` with
     * any URL that matches `sendclod.sc` (e.g: `sendcloud.sc.local`)
     *
     * @param string $path path to append to the base URL
     * @param array|null $params Query params to include in the URL
     *
     * @return string the URL to SendCloud Panel
     */
    public static function getPanelURL($path = '', $params = null)
    {
        if (!is_array($params)) {
            $params = [];
        }

        $panelUrl = getenv('SENDCLOUD_PANEL_URL');
        if (!$panelUrl) {
            $panelUrl = 'https://panel.sendcloud.sc';
        }

        $queryString = '';
        if (count($params)) {
            $queryString = '?' . http_build_query($params);
        }

        return $panelUrl . $path . $queryString;
    }

    /**
     * Return base shop url (prestashop baseShopURL will always generate url using 'https'.)
     * This method is created to support functionality when testing locally on shops that use 'http'
     *
     * @param $request
     *
     * @return string
     */
    public static function getBaseShopUrl($request)
    {
        $isHttpsRequest = (isset($request['HTTPS']) && $request['HTTPS'] === 'on');

        if (!$isHttpsRequest) {
            return 'http://' . $request['SERVER_NAME'];
        }

        return rtrim('https://' . $request['SERVER_NAME'], '/');
    }

    /**
     * @param string $code
     * @return bool|int|string
     */
    public static function httpResponseCode($code = null)
    {
        $statuses = [
            '100' => 'Continue',
            '101' => 'Switching Protocols',
            '200' => 'OK',
            '201' => 'Created',
            '202' => 'Accepted',
            '203' => 'Non-Authoritative Information',
            '204' => 'No Content',
            '205' => 'Reset Content',
            '206' => 'Partial Content',
            '300' => 'Multiple Choices',
            '301' => 'Moved Permanently',
            '302' => 'Moved Temporarily',
            '303' => 'See Other',
            '304' => 'Not Modified',
            '305' => 'Use Proxy',
            '400' => 'Bad Request',
            '401' => 'Unauthorized',
            '402' => 'Payment Required',
            '403' => 'Forbidden',
            '404' => 'Not Found',
            '405' => 'Method Not Allowed',
            '406' => 'Not Acceptable',
            '407' => 'Proxy Authentication Required',
            '408' => 'Request Time-out',
            '409' => 'Conflict',
            '410' => 'Gone',
            '411' => 'Length Required',
            '412' => 'Precondition Failed',
            '413' => 'Request Entity Too Large',
            '414' => 'Request-URI Too Large',
            '415' => 'Unsupported Media Type',
            '500' => 'Internal Server Error',
            '501' => 'Not Implemented',
            '502' => 'Bad Gateway',
            '503' => 'Service Unavailable',
            '504' => 'Gateway Time-out',
            '505' => 'HTTP Version not supported',
        ];

        $code = $code === null ? '200' : $code;
        $text = $statuses[$code] ?? $statuses['200'];

        if (function_exists('http_response_code')) {
            return http_response_code((int) $code);
        } else {
            $protocol = ($_SERVER['SERVER_PROTOCOL'] ?? 'HTTP/1.0');
            header($protocol . ' ' . $code . ' ' . $text);

            return $code;
        }
    }
}
