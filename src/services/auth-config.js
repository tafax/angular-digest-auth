'use strict';

/**
 * Manages the configuration for the auth module.
 */
dgAuth.provider('$authConfig', function()
{
    /**
     * AuthConfig provides a service to get
     * basic configuration
     *
     * @param {Object} sign Object to represent sign in, sign out urls and configuration.
     * @param {Object} events Object to represent all events.
     * @param {String} header Specifies header to get authentication string from the server response.
     * @constructor
     */
    function AuthConfig(sign, events, header)
    {
        var $sign = sign;
        var $events = events;
        var $header = header;

        /**
         * Gets the sign object.
         *
         * @returns {Object}
         */
        this.getSign = function()
        {
            return $sign;
        };

        /**
         * Gets all events.
         *
         * @returns {Object}
         */
        this.getEvents = function()
        {
            return $events;
        };

        /**
         * Gets single event by the string provided.
         * ex: "authentication.header" is the event $events['authentication']['header'].
         *
         * @param event
         * @returns {String}
         */
        this.getEvent = function(event)
        {
            var split = event.split('.');

            return $events[split[0]][split[1]];
        };

        /**
         * Gets the header.
         *
         * @returns {String}
         */
        this.getHeader = function()
        {
            return $header;
        };
    }

    /**
     * The sign object.
     *
     * @type {{signin: string, signout: string, config: {}}}
     */
    var $sign = {
        signin: '',
        signout: '',
        config: {}
    };

    /**
     * All events in the module.
     *
     * @type {{authentication: {header: string}, process: {request: string, response: string}, signin: {successful: string, error: string, required: string}, signout: {successful: string, error: string}, credential: {submitted: string, stored: string, restored: string}}}
     */
    var $events = {
        authentication: {
            header: '$authAuthenticationHeader'
        },
        process: {
            request: '$authProcessRequest',
            response: '$authProcessResponse'
        },
        signin: {
            successful: '$authSigninSuccessful',
            error: '$authSigninError',
            required: '$authSigninRequired'
        },
        signout: {
            successful: '$authSignoutSuccessful',
            error: '$authSignoutError'
        },
        credential: {
            submitted: '$authCredentialSubmitted',
            stored: '$authCredentialStored',
            restored: '$authCredentialRestored'
        }
    };

    /**
     * The header string.
     *
     * @type {string}
     */
    var $header = '';

    /**
     * Sets the sign object by extending basic configuration.
     *
     * @param {Object} sign
     */
    this.setSign = function(sign)
    {
        angular.extend($sign, sign);
    };

    /**
     * Sets events by extending basic configuration.
     *
     * @param {Object} events
     */
    this.setEvents = function(events)
    {
        angular.extend($events, events);
    };

    /**
     * Sets the header.
     *
     * @param {String} header
     */
    this.setHeader = function(header)
    {
        $header = header;
    };

    /**
     * Gets AuthConfig service.
     *
     * @returns {AuthConfig}
     */
    this.$get = function()
    {
        return new AuthConfig($sign, $events, $header);
    };
});