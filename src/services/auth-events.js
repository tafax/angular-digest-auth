'use strict';

/**
 * Manages the events for the auth module.
 */
dgAuth.provider('authEvents', function AuthEventsProvider()
{
    /**
     * AuthEvents provides a service to get
     * basic configuration
     *
     * @param {Object} events Object to represent all events.
     * @constructor
     */
    function AuthEvents(events)
    {
        /**
         * The events of module.
         *
         * @type {Object}
         * @private
         */
        var _events = events;

        /**
         * Gets all events.
         *
         * @returns {Object}
         */
        this.getEvents = function()
        {
            return _events;
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

            return _events[split[0]][split[1]];
        };
    }

    /**
     * All events in the module.
     *
     * @type {{authentication: {header: string}, process: {request: string, response: string}, signin: {successful: string, error: string, required: string}, signout: {successful: string, error: string}, credential: {submitted: string, stored: string, restored: string}}}
     */
    var _events = {
        authentication: {
            headerNotFound: '$authAuthenticationHeaderNotFound',
            header: '$authAuthenticationHeader',
            request: '$authAuthenticationRequest'
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
     * Sets events by extending basic configuration.
     *
     * @param {Object} events
     */
    this.setEvents = function(events)
    {
        angular.extend(_events, events);
    };

    /**
     * Gets AuthEvents service.
     *
     * @returns {AuthEventsProvider.AuthEvents}
     */
    this.$get = function()
    {
        return new AuthEvents(_events);
    };
});