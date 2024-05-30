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
var SendCloud = SendCloud || {};

(function () {

    var spinner = {
        /**
         * Check connection status
         */
        checkConnection: function (checkStatusControllerUrl, intervalId) {
            SendCloud.Ajax.get(checkStatusControllerUrl, null, function (response) {
                try {
                    let jsonResponse = JSON.parse(response);
                    let spinnerContainer = document.getElementsByClassName('spinner-container');

                    if (spinner.spinnerElementExist(spinnerContainer)) {
                        if (jsonResponse.isConnected === true) {
                            spinnerContainer[0].classList.add('none');
                            spinner.showSuccessfulConnectionMessage();
                            spinner.hideWebServiceInfoMessage();

                            clearInterval(intervalId);

                            // Reload the current page to prevent form from being submitted again
                            window.location.reload();
                        }
                    } else {
                        clearInterval(intervalId);
                    }
                } catch (error) {
                    console.error("Error parsing JSON response:", error);

                    clearInterval(intervalId);
                }
            });

        },

        /**
         * Show spinner as soon as submit button is clicked
         */
        showSpinner: function () {
            let spinnerContainer = document.getElementsByClassName('spinner-container');

            if (spinnerContainer[0].classList.contains('none')) {
                spinnerContainer[0].classList.remove('none');
            }
        },

        /**
         * Hide connect button when spinner is shown
         */
        hideConnectButton: function () {
            let connectButton = document.getElementsByClassName('sendcloudshipping-connect');

            if (connectButton && connectButton[0]) {
                if (!connectButton[0].classList.contains('hide')) {
                    connectButton[0].classList.add('hide');
                }
            }

        },

        /**
         * Show success message after successful connection with Sendcloud
         */
        showSuccessfulConnectionMessage: function () {
            let successBanner = document.getElementsByClassName('successful-message');

            if (successBanner && successBanner[0]) {
                successBanner[0].classList.remove('none');
            }
        },

        /**
         * Hides WebService info message once the connection has been established
         */
        hideWebServiceInfoMessage: function () {
            let webServiceInfoMessage = document.getElementsByClassName('webservice-info');

            if (webServiceInfoMessage && webServiceInfoMessage[0]) {
                webServiceInfoMessage[0].classList.add('none');
            }
        },

        /**
         * Check if element with class 'spinner-container' exists on the page
         * @returns {Element}
         */
        spinnerElementExist: function (spinnerContainer) {
            return spinnerContainer && spinnerContainer[0];
        }
    };

    /**
     * Spinner component
     *
     * @type {{checkConnection: spinner.checkConnection, hideConnectButton: spinner.hideConnectButton,
     * showSuccessfulConnectionMessage: spinner.showSuccessfulConnectionMessage,
     * hideWebServiceInfoMessage: spinner.hideWebServiceInfoMessage, spinnerElementExist: spinner.spinnerElementExist,
     * showSpinner: spinner.showSpinner}}
     */
    SendCloud.Spinner = spinner;
})();
