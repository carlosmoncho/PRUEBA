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

namespace Sendcloud\PrestaShop\Classes\Utilities;

use Tools;

if (!defined('_PS_VERSION_')) {
    exit;
}

/**
 * Class OverrideInstaller
 *
 * @package Sendcloud\PrestaShop\Classes\Utilities
 */
class OverrideInstaller
{
    /**
     * SendCloudv2 module instance.
     *
     * @var \SendCloudv2
     */
    private $module;

    /**
     * OverrideInstaller constructor.
     *
     * @param \SendCloudv2 $module
     */
    public function __construct(\SendCloudv2 $module)
    {
        $this->module = $module;
    }

    /**
     * Detects whether other overrides of the order code exist.
     *
     * @return bool TRUE if overrides can be safely applied; otherwise, FALSE.
     */
    public function shouldInstallOverrides()
    {
        return $this->canSendcloudAddOverride(_PS_ROOT_DIR_ . '/override/classes/Product.php');
    }

    /**
     * Checks if module can safely add our overrides.
     *
     * @param string $overriddenFilePath
     *
     * @return bool
     */
    private function canSendcloudAddOverride($overriddenFilePath)
    {
        $content = Tools::file_get_contents($overriddenFilePath);

        return $content === false || preg_match('/function __construct/', $content) === 0;
    }
}
