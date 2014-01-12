'use strict';

/**
 * Manages the configuration for the auth module.
 */
dgAuth.provider('$authConfig', function AuthConfigProvider()
{
    function AuthConfig(sign, events, header)
    {
        var $sign = sign;
        var $events = events;
        var $header = header;

        this.getSign = function()
        {
            return $sign;
        };

        this.getEvents = function()
        {
            return $events;
        };

        this.getEvent = function(event)
        {
            var split = event.split('.');

            return $events[split[0]][split[1]];
        };

        this.getHeader = function()
        {
            return $header;
        };
    }

    var $sign = {
        // Sign in url. Default is not configured.
        signin: '',
        // Sign out url. Default is not configured.
        signout: '',
        // Requests config.
        config: ''
    };

    var $events = {
        authentication: {
            header: '$authAuthenticationHeader'
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

    var $header = '';

    this.setSign = function(sign)
    {
        angular.extend($sign, sign);
    };

    this.setEvents = function(events)
    {
        angular.extend($events, events);
    };

    this.setHeader = function(header)
    {
        $header = header;
    };

    this.$get = function()
    {
        return new AuthConfig($sign, $events, $header);
    };
});