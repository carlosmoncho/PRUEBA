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

namespace Sendcloud\PrestaShop\Classes\DTO;

if (!defined('_PS_VERSION_')) {
    exit;
}

/**
 * Class AuthorizationObject
 *
 * @package Sendcloud\PrestaShop\Classes\DTO
 */
class AuthorizationObject extends AbstractDTO
{
    /**
     * @var string
     */
    private $authCode;
    /**
     * @var string
     */
    private $codeChallenge;

    /**
     * @param string $authCode
     * @param string $codeChallenge
     */
    public function __construct($authCode, $codeChallenge)
    {
        $this->authCode = $authCode;
        $this->codeChallenge = $codeChallenge;
    }

    /**
     * @return string
     */
    public function getAuthCode()
    {
        return $this->authCode;
    }

    /**
     * @return string
     */
    public function getCodeChallenge()
    {
        return $this->codeChallenge;
    }

    /**
     * Saves object as array representation
     *
     * @return array
     */
    public function toArray()
    {
        return [
            'auth_code' => $this->authCode,
            'code_challenge' => $this->codeChallenge
        ];
    }

    /**
     * Transforms array to AuthorizationObject object
     *
     * @param $data
     *
     * @return AuthorizationObject
     */
    public static function fromArray($data)
    {
        return new self(
            self::getValue($data, 'auth_code'),
            self::getValue($data, 'code_challenge')
        );
    }
}
