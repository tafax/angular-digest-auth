/**
 * AngularJS module to manage HTTP Digest Authentication
 * @version v0.2.0 - 2014-01-18
 * @link https://github.com/mgonto/angular-digest-auth
 * @author Matteo Tafani Alunno <matteo.tafanialunno@gmail.com>
 * @license MIT License, http://www.opensource.org/licenses/MIT
 */
'use strict';

/**
 * dgAuth provides functionality to manage
 * user authentication
 */
var dgAuth = angular.module('dgAuth', ['angular-md5', 'ngCookies']);

/**
 * Configures http to intercept requests and responses with error 401.
 */
dgAuth.config(['$httpProvider', function($httpProvider)
{
    $httpProvider.interceptors.push([
        '$rootScope',
        '$q',
        'authServer',
        'authEvents',
    function($rootScope, $q, authServer, authEvents)
    {
        return {
            'request': function(request)
            {
                $rootScope.$broadcast(authEvents.getEvent('process.request'), request);

                return (request || $q.when(request));
            },
            'responseError': function(rejection)
            {
                if(rejection.status === 401)
                {
                    $rootScope.$broadcast(authEvents.getEvent('process.response'), rejection);

                    if(rejection.mustTerminate)
                        return $q.reject(rejection);

                    console.debug("Server has requested an authentication.");

                    if(!authServer.parseHeader(rejection))
                    {
                        $rootScope.$broadcast(authEvents.getEvent('authentication.notFound'));
                        return $q.reject(rejection);
                    }

                    var deferred = $q.defer();
                    var request = {
                        config: rejection.config,
                        deferred: deferred
                    };

                    console.debug('Parse header for authentication.');
                    $rootScope.$broadcast(authEvents.getEvent('authentication.header'));
                    $rootScope.$broadcast(authEvents.getEvent('authentication.request'), request);
                    $rootScope.$broadcast(authEvents.getEvent('login.required'));

                    return deferred.promise;
                }

                return $q.reject(rejection);
            }
        };
    }]);
}]);

/**
 * Uses components to manage authentication.
 */
dgAuth.run([
    '$rootScope',
    'authEvents',
    'authService',
    'authClient',
function($rootScope, authEvents, authService, authClient)
{
    $rootScope.$on(authEvents.getEvent('process.request'), function(event, request)
    {
        if(authClient.isConfigured())
        {
            var login = authService.getCredentials();
            authClient.processRequest(login.username, login.password, request);
        }
    });

    $rootScope.$on(authEvents.getEvent('process.response'), function(event, response)
    {
        authService.mustTerminate(response);
    });

    $rootScope.$on(authEvents.getEvent('authentication.request'), function(event, request)
    {
        authService.setHttpRequest(request);
    });
}]);
/**
 * Manages authentication info in the client scope.
 */
dgAuth.factory('authClient', [
    '$rootScope',
    'authServer',
    'md5',
function($rootScope, authServer, md5)
{
    /**
     * Creates the service to use information generating
     * header for each request.
     *
     * @constructor
     */
    function AuthClient()
    {
        /**
         * Chars to select when creating nonce.
         *
         * @type {string}
         * @private
         */
        var _chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

        /**
         * Current counter.
         *
         * @type {number}
         * @private
         */
        var _nc = 0;

        /**
         * Generates the cnonce with the given length.
         *
         * @param length Length of the cnonce.
         * @returns {string}
         */
        var generateNonce = function(length)
        {
            var nonce = [];
            var charsLength = _chars.length;

            for (var i = 0; i < length; ++i)
            {
                nonce.push(_chars[Math.random() * charsLength | 0]);
            }

            return nonce.join('');
        };

        /**
         * Generate the nc progressively for each request.
         *
         * @returns {string}
         */
        var getNc = function()
        {
            _nc++;

            var zeros = 8 - _nc.toString().length;

            var nc = "";
            for(var i=0; i<zeros; i++)
            {
                nc += "0";
            }

            return (nc + _nc);
        };

        /**
         * Generate the response.
         *
         * @param {String} username The username.
         * @param {String} password The password.
         * @param {String} method Method used for the request.
         * @param {String} uri Uri of the resource requested.
         * @param {String} nc The progressive nc.
         * @param {String} cnonce The cnonce.
         * @returns {string}
         */
        var generateResponse = function(username, password, method, uri, nc, cnonce)
        {
            var ha1 = md5.createHash(username + ":" + authServer.info.realm + ":" + password);
            var ha2 = md5.createHash(method + ":" + uri);
            return md5.createHash(ha1 + ":" + authServer.info.nonce + ":" + nc + ":" + cnonce + ":" + authServer.info.qop + ":" + ha2);
        };

        /**
         * Aggregates all information to generate header.
         *
         * @param {String} username The username.
         * @param {String} password The password.
         * @param {String} method Method used for the request.
         * @param {String} uri Uri of the resource requested.
         * @returns {string}
         */
        var generateHeader = function(username, password, method, uri)
        {
            var nc = getNc();
            var cnonce = generateNonce(16);

            return "Digest " +
                "username=\"" + username + "\", " +
                "realm=\"" + authServer.info.realm + "\", " +
                "nonce=\"" + authServer.info.nonce + "\", " +
                "uri=\"" + uri + "\", " +
                "algorithm=" + authServer.algorithm + ", " +
                "response=\"" + generateResponse(username, password, method, uri, nc, cnonce) + "\", " +
                "opaque=\"" + authServer.info.opaque + "\", " +
                "qop=" + authServer.info.qop + ", " +
                "nc=\"" + nc + "\", " +
                "cnonce=\"" + cnonce + "\"";
        };

        /**
         * Returns true if the client is properly configured.
         * It needs server authentication information.
         *
         * @returns {boolean}
         */
        this.isConfigured = function()
        {
            return authServer.isConfigured();
        };

        /**
         * Process a request and add the authorization header
         * if the request need an authentication.
         *
         * @param {String} username The username.
         * @param {String} password The password.
         * @param {Object} request The current request.
         */
        this.processRequest = function(username, password, request)
        {
            if(request.url.indexOf(authServer.info.domain) >= 0)
                request.headers['Authorization'] = generateHeader(username, password, request.method, request.url);
        };
    }

    return new AuthClient();
}]);

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
     * @type {{authentication: {header: string}, process: {request: string, response: string}, login: {successful: string, error: string, required: string}, logout: {successful: string, error: string}, credential: {submitted: string, stored: string, restored: string}}}
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
        login: {
            successful: '$authSigninSuccessful',
            error: '$authSigninError',
            required: '$authSigninRequired'
        },
        logout: {
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
/**
 * Parses and provides server information for the authentication.
 */
dgAuth.provider('authServer', function AuthServerProvider()
{
    /**
     * Creates the service for the server info.
     *
     * @constructor
     */
    function AuthServer(header, authStorage)
    {
        /**
         * The header string.
         *
         * @type {string}
         */
        var _header = header;

        /**
         * The regular expression to evaluate server information.
         *
         * @type {RegExp}
         * @private
         */
        var _valuePattern = /([a-zA-Z]+)=\"?([a-zA-Z0-9\/\s]+)\"?/;

        /**
         * True if the header was correctly parsed.
         *
         * @type {boolean}
         * @private
         */
        var _configured = false;

        /**
         * The configuration of server information.
         *
         * @type {{realm: string, domain: string, nonce: string, opaque: string, algorithm: string, qop: string}}
         */
        this.info = {
            realm: '',
            domain: '',
            nonce: '',
            opaque: '',
            algorithm: '',
            qop: ''
        };

        /**
         * Checks if the header was correctly parsed.
         *
         * @returns {boolean}
         */
        this.isConfigured = function()
        {
            return _configured;
        };

        /**
         * Sets the configuration manually.
         *
         * @param {Object} server The server information.
         */
        this.setConfig = function(server)
        {
            angular.extend(this.info, server);

            _configured = true;
        };

        /**
         * Parses header to set the information.
         *
         * @param {Object} response The response to login request.
         */
        this.parseHeader = function(response)
        {
            var header = response.headers(_header);

            if(null !== header)
            {
                var splitting = header.split(', ');

                for(var i=0; i<splitting.length; i++)
                {
                    var values = _valuePattern.exec(splitting[i]);
                    this.info[values[1]] = values[2];
                }

                authStorage.setServerAuth(this.info);
                _configured = true;
            }

            return _configured;
        };
    }

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

    this.$get = ['authStorage', function(authStorage)
    {
        var auth = new AuthServer(_header, authStorage);

        if(authStorage.hasServerAuth())
            auth.setConfig(authStorage.getServerAuth());

        return auth;
    }];
});

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
/**
 * Stores information to remember user credentials
 * and server information.
 */
dgAuth.provider('authStorage', function AuthStorageProvider()
{
    /**
     * Creates the service for the storage.
     * You can choose the type of storage to
     * save user credential.
     * Server info are always stored in the
     * session.
     *
     * @param {Storage} storage Storage to save user credentials.
     * @constructor
     */
    function AuthStorage(storage)
    {
        /**
         * The storage for credentials.
         *
         * @type {Storage}
         * @private
         */
        var _storage = storage;

        /**
         * Checks if the storage has some credentials.
         *
         * @returns {boolean}
         */
        this.hasCredential = function()
        {
            var username = _storage.getItem('username');
            var password = _storage.getItem('password');

            return ((null !== username && null !== password));
        };

        /**
         * Sets the credentials.
         *
         * @param {String} username
         * @param {String} password
         */
        this.setCredentials = function(username, password)
        {
            _storage.setItem('username', username);
            _storage.setItem('password', password);
        };

        /**
         * Checks if storage contains the server information.
         *
         * @returns {boolean}
         */
        this.hasServerAuth = function()
        {
            return (null !== sessionStorage.getItem('server'));
        };

        /**
         * Sets the server information.
         *
         * @param {Object} server
         */
        this.setServerAuth = function(server)
        {
            sessionStorage.setItem('server', JSON.stringify(server));
        };

        /**
         * Gets the server information.
         *
         * @returns {Object}
         */
        this.getServerAuth = function()
        {
            return JSON.parse(sessionStorage.getItem('server'));
        };

        /**
         * Gets the username saved in the storage.
         *
         * @returns {String}
         */
        this.getUsername = function()
        {
            return _storage.getItem('username');
        };

        /**
         * Gets the password saved in the storage.
         *
         * @returns {String}
         */
        this.getPassword = function()
        {
            return _storage.getItem('password');
        };

        /**
         * Clears the storage.
         */
        this.clear = function()
        {
            _storage.clear();
            sessionStorage.clear();
        };
    }

    /**
     * Default storage for user credential.
     *
     * @type {Storage}
     * @private
     */
    var _storage = sessionStorage;

    /**
     * Sets storage for user credential.
     *
     * @param storage
     */
    this.setStorage = function(storage)
    {
        _storage = storage;
    };

    /**
     * Gets a new instance of AuthStorage.
     *
     * @returns {AuthStorageProvider.AuthStorage}
     */
    this.$get = function()
    {
        return new AuthStorage(_storage);
    };
});
