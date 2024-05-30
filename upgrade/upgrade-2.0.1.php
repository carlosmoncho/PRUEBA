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

use Sendcloud\PrestaShop\Classes\Bootstrap\Bootstrap;
use Sendcloud\PrestaShop\Classes\Core\Infrastructure\Repositories\QueueItemRepository;
use Sendcloud\PrestaShop\Classes\Utilities\DBInitializer;

if (!defined('_PS_VERSION_')) {
    exit;
}

/**
 * Upgrades module to version 2.0.1
 *
 * @param $module
 *
 * @return bool
 * @throws PrestaShopException
 */
function upgrade_module_2_0_1($module)
{
    $previousShopContext = Shop::getContext();
    Shop::setContext(Shop::CONTEXT_ALL);

    Bootstrap::init();

    $dbInitializer = new DBInitializer();
    $dbInitializer->addIndexesToExistingTable(QueueItemRepository::QUEUE_TABLE);

    $module->enable();
    Shop::setContext($previousShopContext);

    \Configuration::loadConfiguration();

    return true;
}
