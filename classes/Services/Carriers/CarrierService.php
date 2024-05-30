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

namespace Sendcloud\PrestaShop\Classes\Services\Carriers;

use PrestaShop\PrestaShop\Adapter\Entity\Carrier;
use PrestaShop\PrestaShop\Adapter\Entity\Context;
use PrestaShop\PrestaShop\Adapter\Entity\Group;
use PrestaShop\PrestaShop\Adapter\Entity\ImageManager;
use PrestaShop\PrestaShop\Adapter\Entity\Language;
use PrestaShop\PrestaShop\Adapter\Entity\PaymentModule;
use PrestaShop\PrestaShop\Adapter\Entity\PrestaShopException;
use PrestaShop\PrestaShop\Adapter\Entity\RangePrice;
use PrestaShop\PrestaShop\Adapter\Entity\RangeWeight;
use PrestaShop\PrestaShop\Adapter\Entity\Shop;
use PrestaShop\PrestaShop\Adapter\Entity\Tools;
use Sendcloud\PrestaShop\Classes\Bootstrap\ServiceRegister;
use Sendcloud\PrestaShop\Classes\Exceptions\UnsynchronizedCarrierException;
use Sendcloud\PrestaShop\Classes\Interfaces\CarrierConfig;
use Sendcloud\PrestaShop\Classes\Interfaces\ColumnNamesInterface;
use Sendcloud\PrestaShop\Classes\Interfaces\ModuleInterface;
use Sendcloud\PrestaShop\Classes\Repositories\CarrierRepository;
use SendCloud\Infrastructure\Logger\Logger;
use Sendcloud\PrestaShop\Classes\Services\ConfigService;

if (!defined('_PS_VERSION_')) {
    exit;
}

/**
 * Class CarrierService
 *
 * @package Sendcloud\PrestaShop\Classes\Services\Carriers
 */
class CarrierService
{
    /** @var string[] Default price range for Service Point Delivery carrier. */
    private $defaultPriceRange = ['0', '10000'];

    /** @var string[] Default weight range for Service Point Delivery carrier (in kg) */
    private $defaultWeightRange = ['0', '50'];

    /**
     * @var CarrierRepository
     */
    private $carrierRepository;
    /**
     * @var ConfigService
     */
    private $configService;

    /**
     * Update carrier selection and configure carriers accordingly; existing carriers are kept as is,
     * new carriers are created and the rest is deleted.
     *
     * @param Shop $shop
     *
     * @return void
     *
     * @throws \PrestaShopDatabaseException
     * @throws \PrestaShopException
     */
    public function updateCarrierSelection($shop)
    {
        $script = $this->getConfigService()->getConfigValueByShopIdAndName($shop->id, ColumnNamesInterface::SENDCLOUD_SCRIPT);
        if (!$script) {
            // This method is only valid once service points were correctly configured.
            return;
        }

        $selectedCarriers = $this->getSelectedCarriers($shop);
        $selectedCodes = array_keys($selectedCarriers);
        $registeredCarrierCodes = $this->getConfigService()->getAllRegisteredCarrierCodes();

        // Note: it might have difference between *selected* carriers and *registered* carriers.
        // Check what have changed so that we can add/remove carriers based on that difference.
        $allCarrierCodes = array_unique(array_merge($selectedCodes, $registeredCarrierCodes));
        $sharedCodes = array_unique(array_intersect($selectedCodes, $registeredCarrierCodes));

        foreach ($allCarrierCodes as $code) {
            if (in_array($code, $sharedCodes)) {
                continue;
            }
            if (!in_array($code, $selectedCodes)) {
                // We have to remove unused carriers as the consumer cannot use the service point selection with it.
                $this->removeCarrier($shop, $code);
            } else {
                $name = $selectedCarriers[$code];
                $created = $this->createCarrier($shop, $code, $name);

                if (!$created) {
                    Logger::logError('Failed to create carrier ' . $name . ' with code ' . $code . 'for ' . $shop->id);
                }
            }
        }
    }

    /**
     * Returns all available carriers which should be shown on plugin configuration page
     *
     * @param string $adminCarriersLink
     *
     * @return array Array of carriers to be shown on plugin configuration page
     */
    public function displayCarriersOnPluginPage($adminCarriersLink)
    {
        $selectedCarriers = $this->getSelectedCarriers();
        $carriers = [];

        foreach ($selectedCarriers as $code => $name) {
            $carrier = $this->getOrSynchronizeCarrier($code);
            if ($carrier && !$carrier->deleted) {
                $editLink = $adminCarriersLink . '&id_carrier=' . $carrier->id;
            } else {
                continue;
            }

            $context = Context::getContext();
            $thumbnailName = "carrier_mini_{$carrier->id}_{$context->shop->id}.jpg";
            $imagePath = _PS_SHIP_IMG_DIR_ . $carrier->id . '.jpg';

            $thumbnail = ImageManager::thumbnail($imagePath, $thumbnailName, 45);
            // PS enforces escaping variables in templates, and the automatic validation will fail - even for trivial
            // and controlled values, like this one produced by a PrestaShop API itself. Get the URL of the
            // thumbnail and render the image ourselves in the template.
            $matches = [];
            preg_match('/^<img.+src="([^"]+)".*>$/i', $thumbnail, $matches);
            $thumbnailURL = count($matches) >= 2 ? $matches[1] : '';
            $carriers[] = [
                'code' => $code,
                // NOTE: this is the name used @ Sendcloud (i.e Chronopost, DPD, UPS), not the PrestaShop carrier name
                // (which the merchant is free to change)
                'name' => $name,
                'instance' => $carrier,
                'edit_link' => $editLink,
                'thumbnail' => $thumbnailURL,
            ];
        }

        return $carriers;
    }

    /**
     * Get a list of a `Carrier` objects based on its latest synced ID
     *
     * @param bool $idsOnly
     *
     * @return array
     * @throws \PrestaShopException
     */
    public function getSyncedCarriers($idsOnly = false)
    {
        $shop = Context::getContext()->shop;
        $codes = array_keys($this->getSelectedCarriers());
        $configNames = [];

        foreach ($codes as $code) {
            $configNames[$code] = $this->getCarrierConfigName($code);
        }
        $values = $this->getConfigService()->getMultiple($configNames, $shop->id);
        $carrierIDs = is_array($values) ? $values : [];

        $configToCodes = array_flip($configNames);

        $carriers = [];
        foreach ($carrierIDs as $key => $id) {
            if (is_null($id)) {
                // Configure::getMultiple() may return `null` values for unrecognised keys
                continue;
            }
            // Map carriers to internal Sendcloud codes
            $code = $configToCodes[$key];
            $carriers[$code] = $idsOnly === true ? $id : new Carrier($id);
        }

        return $carriers;
    }

    /**
     * Keep track of the current carrier ID. PrestaShop does soft updates and just the most recent
     * version of the carrier is visible to end consumers/merchants.
     *
     * @param int $currentId
     * @param Carrier $newCarrier
     *
     * @return void
     * @throws PrestaShopException
     */
    public function updateCarrier($currentId, $newCarrier)
    {
        if ($newCarrier->external_module_name === ModuleInterface::MODULE_NAME) {
            $shop = Context::getContext()->shop;
            $selectedCarriers = array_keys($this->getSelectedCarriers($shop));
            $matchingCode = null;

            // There is no way to attach metadata to the `Carrier` itself, so we have to iterate
            // over all known selected carriers to find a matching carrier code.
            foreach ($selectedCarriers as $code) {
                $syncedID = $this->getSyncedCarrierID($code);
                $syncedReference = $this->getSyncedCarrierID($code, true);

                if ((int) $syncedID === (int) $currentId ||
                    (int) $syncedReference === (int) $newCarrier->id_reference
                ) {
                    $matchingCode = $code;
                    break;
                }
            }
            if (is_null($matchingCode)) {
                throw new PrestaShopException('Unable to update service point carrier reference.');
            }

            $this->saveCarrier($matchingCode, $newCarrier->id);
        }
    }

    /**
     * Check for carrier restriction in relation to Payment Methods.
     *
     * @param Carrier $carrier
     * @param $shop
     *
     * @return bool
     */
    public function isCarrierRestricted(Carrier $carrier, $shop)
    {
        return $this->getCarrierRepository()->isCarrierRestricted($carrier, $shop);
    }

    /**
     * Retrieve a service point related warning message based in its status.
     *
     * @param array $carriers
     * @param $module
     * @param bool $isConnected
     *
     * @return string
     */
    public function getCarrierWarningMessage(array $carriers, $module, $isConnected)
    {
        $shop = Context::getContext()->shop;
        if ($shop->id === null) {
            return '';
        }

        if (!$isConnected) {
            return $module->getMessage('warning_no_connection');
        }

        $config = $this->getConfigService()->getConfigValueByShopIdAndName($shop->id, ColumnNamesInterface::SENDCLOUD_SCRIPT);
        if (!$config) {
            return $module->getMessage('warning_no_configuration');
        }

        if (empty($carriers)) {
            return $module->getMessage('warning_carrier_not_found');
        }

        foreach ($carriers as $item) {
            $carrier = $item['instance'];

            if (!$carrier->active && !$carrier->deleted) {
                return $module->getMessage('warning_carrier_inactive');
            }

            if ($carrier->deleted) {
                return $module->getMessage('warning_carrier_deleted');
            }

            $availableZones = $carrier->getZones();
            if (empty($availableZones)) {
                return $module->getMessage('warning_carrier_zones');
            }

            $carrierShops = $carrier->getAssociatedShops();
            if (!in_array($shop->id, $carrierShops)) {
                return $module->getMessage('warning_carrier_disabled_for_shop');
            }

            if ($this->getCarrierRepository()->isCarrierRestricted($carrier, $shop)) {
                return $module->getMessage('warning_carrier_restricted');
            }
        }

        return '';
    }

    /**
     * Get or sync the carrier module configuration.
     *
     * @param string $code
     *
     * @return Carrier|null
     */
    private function getOrSynchronizeCarrier($code)
    {
        try {
            $carrier = $this->getCarrier($code);
        } catch (UnsynchronizedCarrierException $e) {
            $this->synchronizeCarrier($e->foundCarrierId);
            $carrier = $this->saveCarrier($code, $e->foundCarrierId);
        }

        return $carrier;
    }

    /**
     * Retrieve the service point delivery carrier related to this shop and referenced by the activation configuration.
     *
     * @param string $code
     *
     * @return Carrier|null
     * @throws UnsynchronizedCarrierException
     */
    private function getCarrier($code)
    {
        $carrierID = $this->getSyncedCarrierID($code);
        $referenceID = $this->getSyncedCarrierID($code, true);
        $foundCarrierId = $this->getCarrierRepository()->getCarrierIdByReference($referenceID);

        if ($foundCarrierId && $foundCarrierId != $carrierID) {
            throw new UnsynchronizedCarrierException($foundCarrierId, $carrierID);
        }

        if (!$carrierID || !$foundCarrierId) {
            return null;
        }

        return new Carrier((int)$carrierID);
    }

    /**
     * Return the configuration of all selected carriers in the context of the current shop.
     *
     * @param Shop|null $shop
     *
     * @return array
     */
    private function getSelectedCarriers($shop = null)
    {
        $shop = $shop === null ? Context::getContext()->shop : $shop;
        $configuration = $this->getConfigService()->getConfigValueByShopIdAndName($shop->id, ColumnNamesInterface::SENDCLOUD_CARRIERS);
        $carriers = json_decode($configuration, true);

        return is_array($carriers) ? $carriers : [];
    }

    /**
     * Configuration name that holds the latest saved carrier ID so that everytime a carrier is
     * updated, the module knows which carrier to pick.
     *
     * @param string $code specific carrier code
     * @param bool $reference
     *
     * @return string
     */
    private function getCarrierConfigName($code, $reference = false)
    {
        $code = Tools::strtoupper($code);
        $name = ColumnNamesInterface::SENDCLOUD_CARRIER_PREFIX . $code;

        return $reference ? $name . '_REFERENCE' : $name;
    }

    /**
     * @param string $carrierId
     *
     * @return void
     */
    private function synchronizeCarrier($carrierId)
    {
        $carrier = new Carrier($carrierId);

        $this->addCarrierGroups($carrier);
        $this->addCarrierLogo($carrier->id);
        $this->addCarrierRanges($carrier);
        $this->addCarrierRestrictions($carrier);
    }

    /**
     * @param string $code
     * @param int $carrierId
     *
     * @return Carrier
     */
    private function saveCarrier($code, $carrierId)
    {
        $this->getConfigService()->updateGlobalValue(self::getCarrierConfigName($code), $carrierId);
        $carrier = new Carrier($carrierId);

        $this->getConfigService()->updateGlobalValue(
            self::getCarrierConfigName($code, true),
            !empty($carrier->id_reference) ? $carrier->id_reference : $carrierId
        );

        return $carrier;
    }

    /**
     * Remove the service point delivery carrier. Additional cleanup on the service point configuration is also executed.
     *
     * @param Shop $shop
     * @param string $code
     * @param bool $force
     *
     * @return bool
     * @throws \PrestaShopDatabaseException
     */
    private function removeCarrier($shop, $code, $force = false)
    {
        $carrier = $this->getOrSynchronizeCarrier($code);

        if (!$carrier || !$carrier->id) {
            // The end user may not activate service points at all, leading to no carrier
            // information to be removed. In any case, cleanup any traces of carrier configuration
            $this->getConfigService()->deleteByName(self::getCarrierConfigName($code));
            $this->getConfigService()->deleteByName(self::getCarrierConfigName($code, true));
            $this->removeCarrierConfiguration();

            return true;
        }

        if (!$this->updateDefaultCarrier($carrier)) {
            // Avoid setting it as deleted if no other carrier could be set as
            // default. By doing that we avoid the user having no active carriers
            // in the shop.
            return false;
        }

        if (!$this->isCarrierSelectedByOtherShops($shop, $code) || $force === true) {
            // Service point script configuration is saved once per shop (in a multishop environment)
            // We'll remove the carrier only if it's not being used by any other shop configuration _OR_ if explicitly
            // forced to do so
            $carrier->delete();
            $this->getConfigService()->deleteByName(self::getCarrierConfigName($code));
            $this->getConfigService()->deleteByName(self::getCarrierConfigName($code, true));
        }

        $this->removeCarrierConfiguration();

        return true;
    }

    /**
     * @param Shop $shop
     * @param string $code
     * @param string $name
     *
     * @return bool
     * @throws \PrestaShopDatabaseException
     * @throws \PrestaShopException
     */
    private function createCarrier($shop, $code, $name)
    {
        $config = CarrierConfig::CARRIER_CONFIG;
        // Retrieve the latest known carrier ID, otherwise create a new entry
        $carrier = $this->getOrSynchronizeCarrier($code);

        if (!$carrier || $carrier->deleted || !$carrier->active) {
            $carrier = new Carrier();
        } elseif ($carrier->active) {
            // Update carrier to shop definition. No extra action is required.
            return $this->getCarrierRepository()->updateCarrierRelation($carrier, $shop);
        }

        foreach ($config as $prop => $value) {
            $carrier->$prop = $value;
        }
        $this->buildCarrierObject($carrier, $name, $config);

        if (!$carrier->add()) {
            return false;
        }

        $this->synchronizeCarrier($carrier->id);
        $this->saveCarrier($code, $carrier->id);

        return true;
    }

    /**
     * @param Carrier $carrier
     * @param string $name
     * @param array $config
     *
     * @return void
     */
    private function buildCarrierObject(&$carrier, $name, $config)
    {
        // Initial carrier names would be something like: `Service Point Delivery: Colissimo`
        $carrier->name = "{$carrier->name}: $name";
        $carrier->external_module_name = ModuleInterface::MODULE_NAME;

        // FIXME: tracking URLs in the current format will soon be phased out
        $carrier->url = '';

        $maxWeight = $this->defaultWeightRange[1];
        $carrier->max_weight = $maxWeight;

        $languages = Language::getLanguages(true);
        foreach ($languages as $language) {
            $isoCode = $language['iso_code'];
            $delay = $config['delay']['en'];
            if (isset($config['delay'][$isoCode])) {
                $delay = $config['delay'][$isoCode];
            }
            $carrier->delay[$language['id_lang']] = $delay;
        }
    }

    /**
     * If all Sendcloud carriers were removed, then remove service points configuration as well
     * otherwise both back and front office may render inconsistent UI states.
     *
     * @return void
     */
    private function removeCarrierConfiguration()
    {
        $moduleCarriersCount = $this->getCarrierRepository()->getModuleCarriersCount();
        $currentShopId = (int)Shop::getContextShopID(false);

        if ($moduleCarriersCount === 0) {
            $this->getConfigService()->deleteByShopIdAndName($currentShopId, ColumnNamesInterface::SENDCLOUD_CARRIERS);
            $this->getConfigService()->deleteByShopIdAndName($currentShopId, ColumnNamesInterface::SENDCLOUD_SCRIPT);
        }
    }

    /**
     * Change the default web shop carrier to something else other than service point delivery, when applicable.
     *
     * @param Carrier $carrier
     *
     * @return bool
     */
    private function updateDefaultCarrier(Carrier $carrier)
    {
        if ($this->getConfigService()->getConfigValue(ColumnNamesInterface::DEFAULT_CARRIER) === (int)$carrier->id) {
            $context = Context::getContext();
            $carriers = Carrier::getCarriers($context->language->id);
            foreach ($carriers as $other) {
                if ($other['active'] &&
                    !$other['deleted'] &&
                    $other['id_carrier'] != $carrier->id
                ) {
                    $this->getConfigService()->saveConfigValue(ColumnNamesInterface::DEFAULT_CARRIER, $other['id_carrier']);

                    return true;
                }
            }

            return false;
        }

        return true;
    }

    /**
     * Check if a given carrier code is selected on another Shop (Sendcloud integration).
     *
     * @param Shop $shop
     * @param $code
     *
     * @return bool
     * @throws \PrestaShopDatabaseException
     */
    private function isCarrierSelectedByOtherShops($shop, $code)
    {
        $carrierInUse = false;
        $otherCarrierConfigurations = $this->getConfigService()->getOtherCarriers($shop);

        foreach ($otherCarrierConfigurations as $carrierConfiguration) {
            $selection = json_decode($carrierConfiguration, true);
            $selectedCodes = is_array($selection) ? $selection : [];
            $carrierInUse = in_array($code, array_keys($selectedCodes));

            if ($carrierInUse === true) {
                // If it's used by other shops, then there's no need to keep checking
                break;
            }
        }

        return $carrierInUse;
    }

    /**
     * Retrieve the latest ID saved for a specific (Sendcloud) carrier code (i.e. dpd, ups).
     * PrestaShop is designed in such a way that it doesn't allow us to save metadata to the
     * carrier itself and the general guideline (officially documented) is to keep a reference of
     * the latest active carrier around. We also need it's "reference carrier" to be saved to make
     * sure carrier synchronisation is done properly.
     *
     * @param string $code Sendcloud internal carrier code (i.e.: ups, dpd, colissimo...)
     * @param bool $reference if TRUE, then it returns the ID of the very first version of a carrier
     *
     * @return string The latest saved Carrier ID, based on $code
     */
    private function getSyncedCarrierID($code, $reference = false)
    {
        return $this->getConfigService()->getGlobalValue(self::getCarrierConfigName($code, $reference));
    }

    /**
     * Add relation between Group and carrier.
     *
     * @param Carrier $carrier
     *
     * @return void
     */
    private function addCarrierGroups(Carrier $carrier)
    {
        $groups = $carrier->getGroups();
        if (!$groups || (!is_array($groups) || !count($groups))) {
            // Fallback to all available groups.
            $groups = Group::getGroups(true);
        }

        $this->getCarrierRepository()->addCarrierGroups($carrier->id, $groups);
    }

    /**
     * Copy our logo to standard PS carrier logo directory.
     *
     * @param string $carrierId
     *
     * @return void
     */
    private function addCarrierLogo($carrierId)
    {
        $logoSrc = _PS_MODULE_DIR_ . ModuleInterface::MODULE_NAME . '/views/img/carrier_logo.jpg';
        $logoDst = _PS_SHIP_IMG_DIR_ . '/' . $carrierId . '.jpg';

        if (!file_exists($logoDst)) {
            copy($logoSrc, $logoDst);
        }
    }

    /**
     * Create default weight and price ranges and associate them with the `$carrier`.
     *
     * @param Carrier $carrier
     */
    private function addCarrierRanges(Carrier $carrier)
    {
        list($minPrice, $maxPrice) = $this->defaultPriceRange;
        list($minWeight, $maxWeight) = $this->defaultWeightRange;

        if (!RangePrice::rangeExist($carrier->id, $minPrice, $maxPrice) &&
            !RangePrice::isOverlapping($carrier->id, $minPrice, $maxPrice)
        ) {
            $rangePrice = new RangePrice();
            $rangePrice->id_carrier = $carrier->id;
            $rangePrice->delimiter1 = $minPrice;
            $rangePrice->delimiter2 = $maxPrice;
            $rangePrice->add();
        }

        if (!RangeWeight::rangeExist($carrier->id, $minWeight, $maxWeight) &&
            !RangeWeight::isOverlapping($carrier->id, $minWeight, $maxWeight)) {
            $rangeWeight = new RangeWeight();
            $rangeWeight->id_carrier = $carrier->id;
            $rangeWeight->delimiter1 = $minWeight;
            $rangeWeight->delimiter2 = $maxWeight;
            $rangeWeight->add();
        }
    }

    /**
     * As of PS 1.7 it's possible to change which payment modules are available per carrier.
     *
     * http://forge.prestashop.com/browse/BOOM-3070
     * When adding a carrier in the webservice context, the payment
     * relations are not added, so we enable them for all installed payment
     * modules.
     *
     * @param Carrier $carrier
     *
     * @return void
     */
    private function addCarrierRestrictions(Carrier $carrier)
    {
        $shop = Context::getContext()->shop;
        if (!$shop) {
            return;
        }

        if ($this->getCarrierRepository()->isCarrierRestricted($carrier, $shop)) {
            $modules = PaymentModule::getInstalledPaymentModules();
            $values = array_map(function ($module) use ($shop, $carrier) {
                // a `Carrier` object may not contain the reference immediately after
                // calling `Carrier::add()`:
                // http://forge.prestashop.com/browse/BOOM-3071
                $reference = is_null($carrier->id_reference) ? $carrier->id : $carrier->id_reference;

                return sprintf(
                    '(%d, %d, %d)',
                    (int)$module['id_module'],
                    (int)$shop->id,
                    (int)$reference
                );
            }, $modules);

            $this->getCarrierRepository()->addCarrierRestrictions($values);
        }
    }

    /**
     * Returns instance of CarrierRepository
     *
     * @return CarrierRepository
     */
    private function getCarrierRepository()
    {
        if ($this->carrierRepository === null) {
            $this->carrierRepository = ServiceRegister::getService(CarrierRepository::class);
        }

        return $this->carrierRepository;
    }

    /**
     * Returns instance of ConfigService
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
