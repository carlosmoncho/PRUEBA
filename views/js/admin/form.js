/*
 * 2023 SendCloud Global B.V.
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
 */
document.addEventListener("DOMContentLoaded", function () {
    function initialize() {
        let connectForm = document.getElementById('sendcloud_shipping_connect_form');
        if (!connectForm) {
            return;
        }
        let submitButton = connectForm.querySelector('button[type="submit"]');

        connectForm.addEventListener('submit', function (event) {
            // Prevent the default form submission
            event.preventDefault();

            // Open new tab with connect url
            window.open(connectUrl, "_blank");

            SendCloud.Spinner.hideConnectButton();
            SendCloud.Spinner.showSpinner();

            let intervalId = setInterval(() => {
                SendCloud.Spinner.checkConnection(checkStatusControllerUrl, intervalId);
            }, 500);

            // Avoid double submission + reload screen.
            submitButton.disabled = true;
        });
    }

    initialize();
});
