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

namespace Sendcloud\PrestaShop\Classes\Interfaces;

if (!defined('_PS_VERSION_')) {
    exit;
}

/**
 * Class ColumnNamesInterface
 *
 * @package Sendcloud\PrestaShop\Classes\Interfaces
 */
interface ColumnNamesInterface
{
    const INTEGRATION_ID = 'SENDCLOUD_V2_INTEGRATION_ID';
    const CONNECT_SETTINGS = 'SENDCLOUD_V2_CONNECT_SETTINGS';
    const AUTH_PARAMS = 'SENDCLOUD_V2_AUTH_PARAMS';
    const WEBHOOK_URL = 'SENDCLOUD_V2_WEBHOOK_URL';
    const SENDCLOUD_CARRIERS = 'SENDCLOUD_V2_SPP_SELECTED_CARRIERS';
    const SENDCLOUD_CARRIER_PREFIX = 'SENDCLOUD_V2_SPP_CARRIER_';
    const SENDCLOUD_SCRIPT = 'SENDCLOUD_V2_SERVICE_POINT_SCRIPT';
    const DEFAULT_CARRIER = 'PS_CARRIER_DEFAULT';
    const TASK_RUNNER_STATUS = 'SENDCLOUD_TASK_RUNNER_STATUS';
    const WEB_SERVICE = 'PS_WEBSERVICE';

    //international shipping
    const HS_CODE_FIELD = 'sc_hs_code';
    const COUNTRY_OF_ORIGIN_FIELD = 'sc_country_of_origin';

    //carriers
    const CARRIER_ID = 'id_carrier';
}
