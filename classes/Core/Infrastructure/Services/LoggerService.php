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

use SendCloud\Infrastructure\Interfaces\Required\Configuration;
use SendCloud\Infrastructure\Interfaces\Required\ShopLoggerAdapter;
use SendCloud\Infrastructure\Logger\LogData;
use SendCloud\Infrastructure\Logger\Logger;
use SendCloud\Infrastructure\ServiceRegister;
use Sendcloud\PrestaShop\Classes\Core\Business\Services\ConfigService;

if (!defined('_PS_VERSION_')) {
    exit;
}

/**
 * Class LoggerService
 *
 * @package Sendcloud\PrestaShop\Classes\Core\Infrastructure\Services
 */
class LoggerService implements ShopLoggerAdapter
{
    /**
     * PrestaShop log severity level codes.
     */
    const PRESTASHOP_INFO = 1;
    const PRESTASHOP_WARNING = 2;
    const PRESTASHOP_ERROR = 3;

    /**
     * Singleton instance of this class.
     *
     * @var static
     */
    protected static $instance;

    /**
     * Log level names for corresponding log level codes.
     *
     * @var array
     */
    private static $logLevelName = array(
        Logger::ERROR => 'ERROR',
        Logger::WARNING => 'WARNING',
        Logger::INFO => 'INFO',
        Logger::DEBUG => 'DEBUG',
    );

    /**
     * Mappings of Sendcloud log severity levels to Prestashop log severity levels.
     *
     * @var array
     */
    private static $logMapping = array(
        Logger::ERROR => self::PRESTASHOP_ERROR,
        Logger::WARNING => self::PRESTASHOP_WARNING,
        Logger::INFO => self::PRESTASHOP_INFO,
        Logger::DEBUG => self::PRESTASHOP_INFO,
    );

    /**
     * @inheritdoc
     */
    public function logMessage(LogData $data)
    {
        try {
            /** @var ConfigService $configService */
            $configService = ServiceRegister::getService(Configuration::CLASS_NAME);
            $minLogLevel = $configService->getMinLogLevel();
            $logLevel = $data->getLogLevel();

            if (($logLevel >= (int)$minLogLevel)) {
                return;
            }
        } catch (\Exception $e) {
            // if we cannot access configuration, log any error directly.
            $logLevel = Logger::ERROR;
        }

        $message = $this->formatLogMessage($data->getMessage(), $logLevel);
        $context = $data->getContext();
        $message = $this->updateLogMessageWithContextData($context, $message);

        \PrestaShopLogger::addLog($message, self::$logMapping[$logLevel]);
    }

    /**
     * Format log message
     *
     * @param string $message
     * @param int $logLevel
     *
     * @return string
     */
    private function formatLogMessage($message, $logLevel)
    {
        return 'SENDCLOUD LOG:' . ' | '
            . 'Date: ' . date('d/m/Y') . ' | '
            . 'Time: ' . date('H:i:s') . ' | '
            . 'Log level: ' . self::$logLevelName[$logLevel] . ' | '
            . 'Message: ' . $message;
    }

    /**
     * Update log message with context data
     *
     * @param array $context
     * @param string $message
     *
     * @return string
     */
    private function updateLogMessageWithContextData($context, $message)
    {
        if (!empty($context)) {
            $contextData = array();
            foreach ($context as $item) {
                $contextData[$item->getName()] = print_r($item->getValue(), true);
            }

            $message .= ' | ' . 'Context data: [' . json_encode($contextData) . ']';
        }

        return $message;
    }
}
