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
{capture name='sendcloud_shipping_wslink'}
    <a href="{$prestashop_webservice_docs|escape:'htmlall':'UTF-8'}" rel="external" target="_blank">
        {l s='Webservice' mod='sendcloudv2'}
        <span class="icon icon-mail-forward"></span>
    </a>
{/capture}

{capture name='sendcloud_shipping_wsinfo'}
    {l s='By connecting with SendCloud the %s feature of Prestashop will be activated and the required API Key created.' sprintf='{WEBSERVICE}' mod='sendcloudv2'}
{/capture}

{capture name='sendcloud_shipping_successful_connection'}
    {l s='You are now connected with Sendcloud' mod='sendcloudv2'}
{/capture}

{capture name='sendcloud_module_not_active'}
    {l s='Plugin is not active for this store' mod='sendcloudv2'}
{/capture}

{assign var='webservice_info' value=$smarty.capture.sendcloud_shipping_wsinfo}
{assign var='successful_connection' value=$smarty.capture.sendcloud_shipping_successful_connection}
{assign var='module_not_active' value=$smarty.capture.sendcloud_module_not_active}

{if !$can_connect}
    <div class="info alert alert-info successful-message">
        <p>{$successful_connection|escape:'htmlall':'UTF-8'}</p>
    </div>
{else}
    <div class="info alert alert-info successful-message none">
        <p>{$successful_connection|escape:'htmlall':'UTF-8'}</p>
    </div>
{/if}

{if !$is_module_active}
    <div class="alert alert-danger">
        <p>{$module_not_active|escape:'htmlall':'UTF-8'}</p>
    </div>
{else}
    <div id="sendcloud_shipping_container"
         class="row sendcloud_shipping {$prestashop_version|escape:'htmlall':'UTF-8'}">
        <div class="col-lg-12">
            <div class="row sendcloud_shipping_connect">
                {if $multishop_warning}
                    <div class="panel">
                        <div class="panel-heading">
                            <i class="ps-icon ps-icon-warning icon icon-warning"></i>
                            {l s='Select a Shop' mod='sendcloudv2'}
                        </div>
                        <div class="panel-body">
                            <div class="row">
                                <div class="col-lg12">
                                    <div class="info alert alert-info">
                                        {l s='SendCloud settings are shop-specific, therefore you must select a shop before you’re able to continue.' mod='sendcloudv2'}
                                    </div>
                                    <div class="sendcloud-shop-demo text-center">
                                        <img src="{$multishop_warning|escape:'htmlall':'UTF-8'}" alt=""/>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                {else}
                    <div class="panel">
                        <div class="panel-heading">
                            <i class="ps-icon ps-icon-broken-link icon icon-chain-broken"></i>
                            {l s='Connect with SendCloud' mod='sendcloudv2'}
                        </div>

                        <div class="panel-body">
                            <div class="row">
                                <div class="col-lg-9 intro-text">
                                    <h4>{l s='Saving time and shipping costs with UPS, DHL, DPD and more' mod='sendcloudv2'}</h4>
                                    <p>
                                        {l s='SendCloud is the smart shipping solution for ecommerce. With SendCloud you can easily ship packages with multiple carriers like DHL, DPD, UPS and more. You can easily import all your orders, print shipping labels within one click and send automated store-branded Track and Trace emails to your customers. In addition, you can automatically take care of returns with your personal return portal via SendCloud.' mod='sendcloudv2'}
                                    </p>

                                    {if $can_connect}
                                        <div class="info alert alert-info webservice-info">
                                            <ul>
                                                <li>{$webservice_info|escape:'htmlall':'UTF-8'|replace:'{WEBSERVICE}':$smarty.capture.sendcloud_shipping_wslink}</li>
                                            </ul>
                                        </div>
                                    {else}
                                        <div class="info alert alert-info webservice-info none">
                                            <ul>
                                                <li>{$webservice_info|escape:'htmlall':'UTF-8'|replace:'{WEBSERVICE}':$smarty.capture.sendcloud_shipping_wslink}</li>
                                            </ul>
                                        </div>
                                    {/if}


                                    <p>
                                        <a
                                                class="link external"
                                                href="{$sendcloud_panel_url|escape:'htmlall':'UTF-8'}"
                                                rel="external noopener noreferrer" target="_blank">
                                            {l s='Go to SendCloud panel' mod='sendcloudv2'}
                                        </a>

                                        <a class="link external pull-right" rel="external noopener noreferer"
                                           target="_blank"
                                           href="https://addons.prestashop.com/contact-community.php?id_product=24482">{l s='Contact support' mod='sendcloudv2'}</a>
                                    </p>
                                </div>

                                <div class="col-lg-3 api-permissions">
                                    <h4>{l s='Required API Resources' mod='sendcloudv2'}</h4>
                                    <ul>
                                        {foreach from=$api_resources item=resource}
                                            <li><code>{$resource|escape:'htmlall':'UTF-8'}</code></li>
                                        {/foreach}
                                    </ul>
                                </div>
                            </div>
                        </div>

                        {* connect button *}
                        {if $can_connect}
                            <div class="panel-footer">
                                <form method="post" enctype="multipart/form-data" id="sendcloud_shipping_connect_form">
                                    <fieldset>
                                        <div class="form-group">
                                            <button
                                                    class="btn btn-default button pull-right sendcloudshipping-connect"
                                                    type="submit"
                                                    name="connectBtn">
                                                <i class="process-icon-save"></i>
                                                {l s='Connect with SendCloud' mod='sendcloudv2'}
                                            </button>
                                        </div>
                                    </fieldset>
                                </form>
                            </div>
                        {/if}
                        <div class="spinner-container none">
                            <div class="spinner"></div>
                            <p class="spinner-text">Connecting...</p>
                        </div>
                    </div>
                    <div class="panel">
                        <div class="panel-heading">
                            <i class="ps-icon ps-icon-world icon icon-globe"></i>
                            {l s='Service Point Delivery' mod='sendcloudv2'}
                        </div>

                        <div class="panel-body">
                            <div class="row">
                                <div class="col-md-12">
                                    <h4>{l s='Shipping Packages has never been so easy.' mod='sendcloudv2'}</h4>
                                    <div class="intro-text">
                                        <p>
                                            {l s='Service Points are places that accept packages to be retrieved later by the customer (e.g. a grocery store near home or work).' mod='sendcloudv2'}
                                            {l s='By enabling Service Points, your customers should be able to select a Service Point delivery location at checkout.' mod='sendcloudv2'}
                                        </p>
                                    </div>

                                    {if !empty($service_point_warning)}
                                        <p class="alert alert-warning">{$service_point_warning|escape:'htmlall':'UTF-8'}</p>
                                    {else}
                                        <p class="success alert alert-success">
                                            {l s='Service Points are enabled and correctly configured.' mod='sendcloudv2'}
                                        </p>
                                    {/if}

                                    {if !empty($service_point_carriers) && !$can_connect}
                                        <div class="row">
                                            <div class="col-lg-12 sendcloud-carriers">
                                                <table class="table tableDnD carrier">
                                                    <thead>
                                                    <tr class="nodrag nodrop">
                                                        <th class="fixed-width-xs center">
                                  <span class="title_box">
                                    ID
                                  </span>
                                                        </th>
                                                        <th class="sendcloud-carrier__logo-cell">{l s='Logo' mod='sendcloudv2'}</th>
                                                        <th>
                                  <span class="title_box">
                                    {l s='Name' mod='sendcloudv2'}
                                  </span>
                                                        </th>
                                                        <th class="fixed-width-sm center">
                                  <span class="title_box">
                                    {l s='Status' mod='sendcloudv2'}
                                  </span>
                                                        </th>
                                                        <th>{l s='Shipping locations' mod='sendcloudv2'}</th>
                                                        <th></th>
                                                    </tr>
                                                    </thead>
                                                    {foreach from=$service_point_carriers item='item'}
                                                        {assign var='shipping_zones' value=$item.instance->getZones()}
                                                        <tbody>
                                                        <tr class="sendcloud-carriers__row">
                                                            <td class="center">
                                                                {$item.instance->id|escape:'htmlall':'UTF-8'}
                                                            </td>
                                                            <td class="sendcloud-carrier__logo-cell">
                                                                {if !empty($item.thumbnail)}
                                                                    <img src="{$item.thumbnail|escape:'htmlall':'UTF-8'}"
                                                                         alt="" class="imgm img-thumbnail"/>
                                                                {/if}
                                                            </td>
                                                            <td>
                                                                {$item.instance->name|escape:'htmlall':'UTF-8'}
                                                                ({$item.name|escape:'htmlall':'UTF-8'})
                                                            </td>

                                                            <td class="center">
                                                                {if $item.instance->active}
                                                                    <span class="list-action-enable action-enabled">
                                    <i class="icon-check"></i>
                                  </span>
                                                                {else}
                                                                    <span class="list-action-enable action-disabled">
                                    <i class="icon-remove"></i>
                                  </span>
                                                                {/if}
                                                            </td>

                                                            <td>
                                                                {if !empty($shipping_zones)}
                                                                    <span class="list-action-enable action-enabled">
                                  <i class="icon-check"></i>
                                  </span>
                                                                {else}
                                                                    <span class="list-action-enable action-disabled">
                                  <i class="icon-remove"></i>
                                  </span>
                                                                {/if}
                                                            </td>

                                                            <td class="text-right">
                                                                <div class="btn-group-action">
                                                                    <div class="btn-group pull-right">
                                                                        <a
                                                                                href="{$item.edit_link|escape:'htmlall':'UTF-8'}"
                                                                                title="Edit"
                                                                                class="edit btn btn-default"
                                                                        >
                                                                            <i class="icon-pencil"></i> {l s='Edit' mod='sendcloudv2'}
                                                                        </a>
                                                                    </div>
                                                                </div>
                                                            </td>
                                                        </tr>
                                                        </tbody>
                                                    {/foreach}
                                                </table>
                                            </div>
                                        </div>
                                    {/if}
                                </div>
                            </div>
                        </div>
                    </div>
                {/if}
            </div>
        </div>
    </div>
    <script>
        let checkStatusControllerUrl = "{$controller_url}";
        let connectUrl = "{$connect_url}";
    </script>
    <script src="{$admin_js_file_path}spinner.js"></script>
{/if}
