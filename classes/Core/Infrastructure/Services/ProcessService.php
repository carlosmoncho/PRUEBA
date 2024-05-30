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

use Sendcloud\PrestaShop\Classes\Bootstrap\ServiceRegister;
use Sendcloud\PrestaShop\Classes\Core\Infrastructure\Repositories\ProcessEntityRepository;

if (!defined('_PS_VERSION_')) {
    exit;
}

/**
 * Class ProcessService
 *
 * @package Sendcloud\PrestaShop\Classes\Core\Infrastructure\Services
 */
class ProcessService
{
    /**
     * @var ProcessEntityRepository
     */
    private $processRepository;

    /**
     * Return process by guid
     *
     * @param string $guid
     *
     * @return array|null
     */
    public function getProcessByGuid($guid)
    {
        return $this->getProcessRepository()->getProcessByGuid($guid);
    }

    public function deleteByGuid($guid)
    {
        return $this->getProcessRepository()->deleteByGuid($guid);
    }

    /**
     * Return ProcessEntity repository
     *
     * @return ProcessEntityRepository
     */
    private function getProcessRepository()
    {
        if ($this->processRepository === null) {
            $this->processRepository = ServiceRegister::getService(ProcessEntityRepository::class);
        }

        return $this->processRepository;
    }
}
