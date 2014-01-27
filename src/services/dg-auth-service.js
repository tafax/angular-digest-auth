'use strict';

dgAuth.provider('dgAuthService', function DgAuthServiceProvider()
{
    /**
     * Class to provide the API to manage
     * the module functionality.
     *
     * @param {Object} $q
     * @param {Object} authIdentity
     * @param {Object} authRequests
     * @param {StateMachine} stateMachine
     * @constructor
     */
    function DgAuthService($q, authIdentity, authRequests, stateMachine)
    {
        /**
         * Specifies if the service is started.
         *
         * @type {boolean}
         * @private
         */
        var _started = false;

        /**
         * Starts the service.
         */
        this.start = function()
        {
            stateMachine.initialize();

            stateMachine.send('run');
            stateMachine.send('restored');
            stateMachine.send('signin');

            _started = true;
        };

        /**
         * Sends a signin message to the state machine.
         */
        this.signin = function()
        {
            if(!_started)
                throw 'You have to start te service first';

            stateMachine.send('signin');
        };

        /**
         * Sends a signout message to the state machine.
         */
        this.signout = function()
        {
            if(!_started)
                throw 'You have to start te service first';

            stateMachine.send('signout');
        };

        /**
         * Sends a submitted message to the state machine
         * with the credentials specified.
         *
         * @param {string} username
         * @param {string} password
         */
        this.setCredentials = function(username, password)
        {
            if(!_started)
                throw 'You have to start te service first';

            stateMachine.send('submitted', {
                credentials: {
                    username: username,
                    password: password
                }
            });
        };

        /**
         * Checks the authentication.
         *
         * @returns {promise|false}
         */
        this.isAuthorized = function()
        {
            var deferred = $q.defer();

            authRequests.getPromise().then(function()
                {
                    deferred.resolve(authIdentity.has());
                },
                function()
                {
                    deferred.reject(authIdentity.has())
                });

            return deferred.promise;
        };
    }

    /**
     * Default storage for user credentials.
     *
     * @type {Storage}
     * @private
     */
    var _storage = window.sessionStorage;

    /**
     * Sets storage for user credentials.
     *
     * @param storage
     */
    this.setStorage = function(storage)
    {
        _storage = storage;
    };

    /**
     * Gets storage for user credentials.
     *
     * @returns {Storage}
     */
    this.getStorage = function()
    {
        return _storage;
    };

    /**
     * The configuration for the login and logout.
     *
     * @type {Object}
     * @private
     */
    var _config = {
        login: {
            method: 'POST',
            url: '/signin'
        },
        logout: {
            method: 'POST',
            url: '/signout'
        }
    };

    /**
     * Sets the configuration for the requests.
     *
     * @param {Object} config
     */
    this.setConfig = function(config)
    {
        angular.extend(_config, config);
    };

    /**
     * Gets the configuration for the requests.
     *
     * @returns {Object}
     */
    this.getConfig = function()
    {
        return _config;
    };

    /**
     *
     * @type {number|string}
     * @private
     */
    var _limit = 4;

    /**
     * Sets the limit for the login requests number.
     *
     * @param {number|string} limit
     */
    this.setLimit = function(limit)
    {
        _limit = limit;
    };

    /**
     * Gets the limit for the login requests number.
     *
     * @returns {number|string}
     */
    this.getLimit = function()
    {
        return _limit;
    };

    /**
     * Callbacks configuration.
     *
     * @type {{login: Array, logout: Array}}
     */
    this.callbacks = {
        login: [],
        logout: []
    };

    /**
     * The header string.
     *
     * @type {string}
     */
    var _header = '';

    /**
     * Sets the header.
     *
     * @param {String} header
     */
    this.setHeader = function(header)
    {
        _header = header;
    };

    /**
     * Gets the header.
     *
     * @returns {string}
     */
    this.getHeader = function()
    {
        return _header;
    };

    /**
     * Gets a new instance of the service.
     *
     * @type {*[]}
     */
    this.$get = ['$q', 'authIdentity', 'authRequests', 'stateMachine', function($q, authIdentity, authRequests, stateMachine)
    {
        return new DgAuthService($q, authIdentity, authRequests, stateMachine);
    }];
});