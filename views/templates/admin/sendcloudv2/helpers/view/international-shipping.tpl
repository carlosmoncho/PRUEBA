{* 2023 SendCloud Global B.V.
 *
 * NOTICE OF LICENSE
 *
 * This source file is subject to the Academic Free License (AFL 3.0)
 * that is bundled with this package in the file LICENSE.txt.
 * It is also available through the world-wide-web at this URL:
 * http://opensource.org/licenses/afl-3.0.php
 * If you did not receive a copy of the license and are unable to
 * obtain it through the world-wide-web, please send an email
 * to contact@sendcloud.eu so we can send you a copy immediately.
 *
 *  @author    SendCloud Global B.V. <contact@sendcloud.eu>
 *  @copyright 2023 SendCloud Global B.V.
 *  @license   http://opensource.org/licenses/afl-3.0.php  Academic Free License (AFL 3.0)
*}
<div class="row">
    <div class="col-lg-12 col-xl-4">
        <fieldset style="border:none;">
            <div class="form_block">
                <div>
                    <h2>{l s='HS Codes' mod='sendcloudv2'}</h2>
                    <input type="number" name="sc_hs_code" id="sc_hs_code" class="form-control" value="{$hs_code}"/>
                </div>
            </div>
        </fieldset>
    </div>
</div>
<div class="row">
    <div class="col-lg-12 col-xl-4">
        <fieldset style="border:none;">
            <div class="form_block">
                <div>
                    <h2>{l s='Country of Origin' mod='sendcloudv2'}</h2>
                    <input name="sc_country_of_origin" id="sc_country_of_origin" class="form-control" value="{$country_of_origin}"/>
                </div>
            </div>
        </fieldset>
    </div>
</div>
