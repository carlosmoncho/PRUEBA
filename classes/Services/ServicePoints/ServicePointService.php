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

namespace Sendcloud\PrestaShop\Classes\Services\ServicePoints;

use Exception;
use PrestaShop\PrestaShop\Adapter\Entity\Carrier;
use PrestaShop\PrestaShop\Adapter\Entity\Context;
use PrestaShop\PrestaShop\Adapter\Entity\ObjectModel;
use SendCloud\Infrastructure\Logger\Logger;
use Sendcloud\PrestaShop\Classes\Bootstrap\ServiceRegister;
use Sendcloud\PrestaShop\Classes\Exceptions\ServicePointException;
use Sendcloud\PrestaShop\Classes\Exceptions\UnexpectedValueException;
use Sendcloud\PrestaShop\Classes\Interfaces\ColumnNamesInterface;
use Sendcloud\PrestaShop\Classes\Interfaces\ModuleInterface;
use Sendcloud\PrestaShop\Classes\Repositories\ConfigRepository;
use Sendcloud\PrestaShop\Classes\Repositories\ServicePointRepository;
use Sendcloud\PrestaShop\Classes\Services\Carriers\CarrierService;
use Sendcloud\PrestaShop\Classes\Services\ConnectService;

if (!defined('_PS_VERSION_')) {
    exit;
}

/**
 * Class ServicePointService
 *
 * @package Sendcloud\PrestaShop\Classes\Services\ServicePoints
 */
class ServicePointService
{
    /**
     * @var ConfigRepository
     */
    private $configRepository;
    /**
     * @var CarrierService
     */
    private $carrierService;
    /**
     * @var ConnectService
     */
    private $connectService;
    /**
     * @var ServicePointRepository
     */
    private $servicePointRepository;

    /**
     * Inspect the object and if it's the service point configuration we create the
     * required carriers and update the module settings accordingly. Activating service points happens
     * in two phases:
     *
     * 1. A request is made to tell which carriers the user selected at Sendcloud
     * 2. A request is made t activate service points and inject the service point script
     *
     * After that, further requests _may_ be executed to _update selected carriers_. If a carriers
     * was removed from Sendcloud service point configuration, the corresponding carrier on PrestaShop
     * is removed as well.
     *
     * @param $shop
     * @param ObjectModel $object
     *
     * @return void
     *
     * @throws UnexpectedValueException
     * @throws \PrestaShopDatabaseException
     * @throws \PrestaShopException
     * @throws ServicePointException
     */
    public function activateServicePoints($shop, $object)
    {
        if (!$this->isServicePointConfiguration($object)) {
            return;
        }

        if ($object->name === ColumnNamesInterface::SENDCLOUD_CARRIERS) {
            try {
                if (empty($object->value)) {
                    throw new UnexpectedValueException('Invalid carrier configuration. At least one carrier must be selected');
                }
            } catch (Exception $exception) {
                $this->deleteObject($object);
                throw $exception;
            }
            $this->getConfigRepository()->removeOrphanConfiguration($shop, ColumnNamesInterface::SENDCLOUD_CARRIERS, $object->id);
            $this->getCarrierService()->updateCarrierSelection($shop);
        }

        if ($object->name === ColumnNamesInterface::SENDCLOUD_SCRIPT) {
            $this->getConfigRepository()->removeOrphanConfiguration($shop, ColumnNamesInterface::SENDCLOUD_SCRIPT, $object->id);
            $this->getCarrierService()->updateCarrierSelection($shop);
        }
    }

    /**
     * Check all the requirements to make service points available in the Frontoffice.
     *
     * - The current shop __MUST__ have a connection with Sendcloud
     * - There's a Service Point script configuration
     * - There is at least one Service Point carrier correctly configured for the current shop
     * - The Shop has a relation with the carrier (when using Multistore the admin may disable the carrier for certain shops.)
     *
     * @return bool
     * @throws \PrestaShopDatabaseException
     * @throws \PrestaShopException
     */
    public function servicePointsAvailable()
    {
        if (!$this->getConnectService()->isIntegrationConnected()) {
            return false;
        }

        $config = $this->getConfigRepository()->getConfigValueByShopIdAndName(Context::getContext()->shop->id, ColumnNamesInterface::SENDCLOUD_SCRIPT);
        if (!$config) {
            return false;
        }
        $syncedCarriers = $this->getCarrierService()->getSyncedCarriers();

        $hasAnyValidCarrier = false;
        foreach ($syncedCarriers as $carrier) {
            $hasAnyValidCarrier = $this->isServicePointsEnabledForCarrier($carrier);
            if ($hasAnyValidCarrier) {
                break;
            }
        }

        return $hasAnyValidCarrier;
    }

    /**
     * Retrieve a `SendcloudServicePoint` instance related to the `$cartId`, or
     * a new instance to relate to the given `$cartId`.
     *
     * @param $cartId
     *
     * @return array|null
     */
    public function getByCartId($cartId)
    {
        return $this->getServicePointRepository()->getByCartId($cartId);
    }

    /**
     * @param $cartId
     * @param string $action
     * @param string $details
     *
     * @return void
     */
    public function saveOrDeleteServicePoint($cartId, $action, $details)
    {
        try {
            $servicePointData = $this->getByCartId($cartId);

            switch ($action) {
                case 'delete':
                    $this->deleteServicePointByCartId($cartId);
                    break;

                default:
                case 'save':
                    if ($servicePointData) {
                        $this->updateServicePoint($cartId, $details);
                        break;
                    }
                    $this->saveServicePoint($this->dataToArray($cartId, $details));
                    break;
            }
        } catch (Exception $e) {
            Logger::logError('Could not save or delete service point' . $e->getMessage());
        }
    }

    /**
     * Saves service point data
     *
     * @param array $servicePointData
     *
     * @return int|null
     */
    private function saveServicePoint($servicePointData)
    {
        return $this->getServicePointRepository()->saveServicePoint($servicePointData);
    }

    /**
     * Updates service point data
     *
     * @param $cartId
     * @param string $details
     *
     * @return bool
     */
    private function updateServicePoint($cartId, $details)
    {
        return $this->getServicePointRepository()->updateServicePoint($cartId, $details);
    }

    /**
     * Delete service point record by cart id
     *
     * @param $cartId
     *
     * @return void
     */
    private function deleteServicePointByCartId($cartId)
    {
        $this->getServicePointRepository()->deleteByCartId($cartId);
    }

    /**
     * @param $cartId
     * @param string $details
     *
     * @return array
     */
    private function dataToArray($cartId, $details)
    {
        return [
            'id_cart' => $cartId,
            'id_address_delivery' => 0,
            'details' => $details
        ];
    }

    /**
     * Check if a given carrier matches all the criteria to allow a consumer to select service
     * points.
     *
     * @param Carrier|null $carrier
     *
     * @return bool
     * @throws \PrestaShopDatabaseException
     */
    private function isServicePointsEnabledForCarrier($carrier)
    {
        if (!$carrier || !$carrier->active || $carrier->deleted) {
            return false;
        }

        $shop = Context::getContext()->shop;
        $carrierShops = $carrier->getAssociatedShops();
        if (!in_array($shop->id, $carrierShops)) {
            return false;
        }

        $shippingZones = $carrier->getZones();
        if (empty($shippingZones)) {
            return false;
        }

        if ($this->getCarrierService()->isCarrierRestricted($carrier, $shop)) {
            return false;
        }

        return true;
    }

    /**
     * Determine if `$object` is an external configuration used to enable service points.
     *
     * @param ObjectModel $object
     *
     * @return bool
     */
    private function isServicePointConfiguration($object)
    {
        if (is_null($object) || !($object->getObjectName() === ModuleInterface::CONFIGURATION_ENTITY_CLASS)) {
            return false;
        }

        return in_array($object->name, [ColumnNamesInterface::SENDCLOUD_CARRIERS, ColumnNamesInterface::SENDCLOUD_SCRIPT]);
    }

    /**
     * Deletes current object from database.
     *
     * @param ObjectModel $object
     *
     * @return bool
     */
    private function deleteObject(ObjectModel $object)
    {
        try {
            return $object->delete();
        } catch (\PrestaShopException $e) {
            Logger::logError('Could not delete object ' . $object->name . ' from the database');
        }

        return false;
    }

    /**
     * Returns an instance of CarrierService
     *
     * @return CarrierService
     */
    private function getCarrierService()
    {
        if ($this->carrierService === null) {
            $this->carrierService = ServiceRegister::getService(CarrierService::class);
        }

        return $this->carrierService;
    }

    /**
     * Returns an instance of ConnectService
     *
     * @return ConnectService
     */
    private function getConnectService()
    {
        if ($this->connectService === null) {
            $this->connectService = ServiceRegister::getService(ConnectService::class);
        }

        return $this->connectService;
    }

    /**
     * Returns an instance of ConfigRepository
     *
     * @return ConfigRepository
     */
    private function getConfigRepository()
    {
        if ($this->configRepository === null) {
            $this->configRepository = ServiceRegister::getService(ConfigRepository::class);
        }

        return $this->configRepository;
    }

    /**
     * Returns an instance of ServicePointRepository
     *
     * @return ServicePointRepository
     */
    private function getServicePointRepository()
    {
        if ($this->servicePointRepository === null) {
            $this->servicePointRepository = ServiceRegister::getService(ServicePointRepository::class);
        }

        return $this->servicePointRepository;
    }
}