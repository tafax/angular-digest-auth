/**
 * Used to manage the authentication.
 */
dgAuth.provider('authService', [function AuthServiceProvider()
{
    /**
     * Creates the authentication service to performs
     * sign in and sign out, manages the current identity
     * and check the authentication.
     *
     * @constructor
     */
    function AuthService(config, $injector, authEvents, authStorage, $rootScope, $http, $q, $cookies, md5)
    {
        /**
         * The configuration of service.
         *
         * @type {{login: Object, logout: Object, callbacks: Object, automatic: boolean}}
         * @private
         */
        var _config = config;

        /**
         * The configuration for the login.
         *
         * @type {Object}
         * @private
         */
        var _login = config.login;

        /**
         * The configuration for the logout.
         *
         * @type {Object}
         * @private
         */
        var _logout = config.logout;

        /**
         * The configuration of callbacks
         *
         * @type {Object}
         * @private
         */
        var _callbacks = config.callbacks;

        /**
         * The configuration for automatic reconnection.
         *
         * @type {boolean}
         * @private
         */
        var _automatic = config.automatic;

        /**
         * Gets all configurations.
         *
         * @returns {{login: Object, logout: Object, callbacks: Object, automatic: boolean}}
         */
        this.getConfig = function()
        {
            return _config;
        };

        /**
         * The current identity
         *
         * @type {Object}
         */
        var _identity = null;

        /**
         * Initializes the login object.
         *
         * @returns {{username: string, password: string, httpRequest: null, deferred: null, mustTerminate: boolean}}
         */
        var initLogin = function ()
        {
            return {
                username: '',
                password: '',
                httpRequest: null,
                deferred: null,
                mustTerminate: false
            };
        };

        /**
         * Initializes the logout object.
         *
         * @returns {{deferred: null, mustTerminate: boolean}}
         */
        var initLogout = function()
        {
            return {
                deferred: null,
                mustTerminate: true
            }
        };

        /**
         * The login object.
         *
         * @type {{username: string, password: string, httpRequest: null, mustTerminate: boolean}}
         */
        var _loginRequest = initLogin();

        /**
         * The logout object.
         *
         * @type {{deferred: null, mustTerminate: boolean}}
         */
        var _logoutRequest = initLogout();

        /**
         * Sets the http request for login.
         *
         * @param {Object} request
         */
        this.setHttpRequest = function(request)
        {
            angular.extend(_loginRequest, {
                httpRequest: request
            });
        };

        /**
         * Verifies if the identity is set.
         *
         * @returns {boolean}
         */
        this.hasIdentity = function()
        {
            return (null !== _identity);
        };

        /**
         * Gets the identity.
         *
         * @returns {Object}
         */
        this.getIdentity = function()
        {
            return _identity;
        };

        /**
         * Sets the credential used for sign in.
         *
         * @param {String} username
         * @param {String} password
         */
        this.setCredentials = function(username, password)
        {
            angular.extend(_loginRequest, {
                username: username,
                password: password,
                mustTerminate: true
            });

            $rootScope.$broadcast(authEvents.getEvent('credential.submitted'), {
                username: _loginRequest.username,
                password: _loginRequest.password
            });
        };

        /**
         * Gets the login.
         *
         * @returns {{username: string, password: string}}
         */
        this.getCredentials = function()
        {
            return {
                username: _loginRequest.username,
                password: _loginRequest.password
            };
        };

        this.mustTerminate = function(response)
        {
            if(response.config.url == _login.url)
            {
                response.mustTerminate = _loginRequest.mustTerminate;
                return;
            }

            if(response.config.url == _logout.url)
                response.mustTerminate = _logoutRequest.mustTerminate;
        };

        var performSignin = function()
        {
            console.debug('Performs a login.');

            var deferred = $q.defer();

            $http(_login)
                .success(function(data)
                {
                    console.debug('Login successful.');

                    _identity = data;

                    $cookies['_auth'] = md5.createHash('true');

                    authStorage.setCredentials(_loginRequest.username, _loginRequest.password);

                    $rootScope.$broadcast(authEvents.getEvent('credential.stored'), {
                        username: _loginRequest.username,
                        password: _loginRequest.password
                    });

                    $rootScope.$broadcast(authEvents.getEvent('login.successful'), data);

                    angular.extend(_loginRequest, {
                        mustTerminate: false
                    });

                    deferred.resolve(data);
                })
                .error(function(data, status)
                {
                    console.debug('Login error.');

                    $rootScope.$broadcast(authEvents.getEvent('login.error'), data, status);

                    _loginRequest = initLogin();

                    deferred.reject(data);
                });

            return deferred;
        };

        /**
         * Performs the login.
         */
        this.signin = function()
        {
            if($cookies['_auth'] == md5.createHash('true') || _automatic)
            {
                if(authStorage.hasCredential())
                {
                    angular.extend(_loginRequest, {
                        username: authStorage.getUsername(),
                        password: authStorage.getPassword(),
                        mustTerminate: true
                    });

                    $rootScope.$broadcast(authEvents.getEvent('credential.restored'), {
                        username: _loginRequest.username,
                        password: _loginRequest.password
                    });
                }
            }

            if(!_loginRequest.httpRequest)
            {
                if(!_loginRequest.deferred)
                {
                    _loginRequest.deferred = performSignin();
                    for(var i in _callbacks.login)
                    {
                        var callback = $injector.invoke(_callbacks.login[i]);
                        _loginRequest.deferred.promise.then(callback.successful, callback.error);
                    }
                }
            }
            else
            {
                var promise = $http(_loginRequest.httpRequest.config).then(function(response)
                {
                    _loginRequest.httpRequest.deferred.resolve(response);
                },
                function(response)
                {
                    _loginRequest.httpRequest.deferred.reject(response);
                });

                promise['finally'](function()
                {
                    _loginRequest.httpRequest = null;
                });
            }

            return _loginRequest.deferred.promise;
        };

        var performSignout = function()
        {
            console.debug('Performs a logout.');

            var deferred = $q.defer();

            $http(_logout)
                .success(function(data)
                {
                    console.debug('Logout successful.');

                    $cookies['_auth'] = md5.createHash('false');

                    _identity = null;
                    _loginRequest = initLogin();

                    $rootScope.$broadcast(authEvents.getEvent('logout.successful'), data);

                    deferred.resolve(data);
                })
                .error(function(data, status)
                {
                    console.debug('Logout error.');

                    $rootScope.$broadcast(authEvents.getEvent('logout.error'), data, status);

                    deferred.reject(data);
                });

            return deferred;
        };

        /**
         * Performs the logout.
         */
        this.signout = function()
        {
            if(!_logoutRequest.deferred)
            {
                _logoutRequest.deferred = performSignout();
                for(var i in _callbacks.logout)
                {
                    var callbacks = $injector.invoke(_callbacks.logout[i]);
                    _logoutRequest.deferred.promise.then(callbacks.successful, callbacks.error);
                }
            }

            return _logoutRequest.deferred.promise;
        };

        /**
         * Checks the authentication.
         *
         * @returns {promise|*}
         */
        this.isAuthenticated = function()
        {
            var deferred = $q.defer();

            if(_logoutRequest.deferred)
            {
                _logoutRequest.deferred.promise.then(function()
                    {
                        deferred.reject(null);
                    },
                    function()
                    {
                        deferred.resolve(($cookies['_auth'] == md5.createHash('true') && null !== _identity))
                    });
            }
            else if(_loginRequest.deferred)
            {
                _loginRequest.deferred.promise.then(function()
                    {
                        deferred.resolve(($cookies['_auth'] == md5.createHash('true') && null !== _identity));
                    },
                    function(reason)
                    {
                        deferred.reject(reason);
                    });
            }

            return deferred.promise;
        };
    }

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
     * The configuration for automatic reconnection.
     *
     * @type {boolean}
     * @private
     */
    var _automatic = false;

    /**
     * Sets configuration for automatic reconnection.
     *
     * @param {boolean} automatic
     */
    this.setAutomatic = function(automatic)
    {
        _automatic = automatic;
    };

    /**
     * Gets configuration for automatic reconnection.
     *
     * @returns {boolean}
     */
    this.getAutomatic = function()
    {
        return _automatic;
    };

    /**
     * The configuration for the login and logout.
     *
     * @type {{login: {method: string, url: string}, logout: {method: string, url: string}}}
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

    this.setConfig = function(config)
    {
        angular.extend(_config, config);
    };

    /**
     * Gets a new instance of AuthService.
     *
     * @type {Array}
     */
    this.$get = [
        '$injector',
        'authEvents',
        'authStorage',
        '$rootScope',
        '$http',
        '$q',
        '$cookies',
        'md5',
    /**
     * Gets a new instance of AuthService.
     *
     * @param {Object} $injector
     * @param {AuthEvents} authEvents
     * @param {AuthStorage} authStorage
     * @param {Object} $rootScope
     * @param {Object} $http
     * @param {Object} $q
     * @param {Object} $cookies
     * @param {Object} md5
     * @returns {AuthService}
     */
    function($injector, authEvents, authStorage, $rootScope, $http, $q, $cookies, md5)
    {
        return new AuthService({
            login: _config.login,
            logout: _config.logout,
            callbacks: this.callbacks,
            automatic: _automatic
        }, $injector, authEvents, authStorage, $rootScope, $http, $q, $cookies, md5);
    }];

}]);