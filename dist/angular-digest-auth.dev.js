/**
 * AngularJS module to manage HTTP Digest Authentication
 * @version v0.4.3 - 2014-02-02
 * @link https://github.com/tafax/angular-digest-auth
 * @author Matteo Tafani Alunno <matteo.tafanialunno@gmail.com>
 * @license MIT License, http://www.opensource.org/licenses/MIT
 */


'use strict';


// Source: src/angular-digest-auth.js

/**
 * dgAuth provides functionality to manage
 * user authentication
 */
var dgAuth = angular.module('dgAuth', ['angular-md5', 'FSM']);

// Source: src/config/config-module.js

/**
 * Configures http to intercept requests and responses with error 401.
 */
dgAuth.config(['$httpProvider', function($httpProvider)
{
    $httpProvider.interceptors.push([
        '$q',
        'authService',
        'authClient',
        'authServer',
        'stateMachine',
        function($q, authService, authClient, authServer, stateMachine)
        {
            return {
                'request': function(request)
                {
                    var login = authService.getCredentials();
                    var header = authClient.processRequest(login.username, login.password, request.method, request.url);

                    if(header)
                        request.headers['Authorization'] = header;

                    return (request || $q.when(request));
                },
                'responseError': function(rejection)
                {
                    if(rejection.status === 401)
                    {
                        if(!authServer.parseHeader(rejection))
                        {
                            return $q.reject(rejection);
                        }

                        var deferred = $q.defer();

                        authService.setRequest(rejection.config, deferred);
                        stateMachine.send('401', {response: rejection});

                        return deferred.promise;
                    }

                    return $q.reject(rejection);
                }
            };
        }]);
}]);

// Source: src/config/config-state-machine.js

dgAuth.config(['stateMachineProvider', function(stateMachineProvider)
{
    stateMachineProvider.config({
        init: {
            transitions: {
                run: 'restoringCredentials'
            }
        },
        restoringCredentials: {
            transitions: {
                restored: 'settingCredentials'
            },
            //Restores the credentials and propagate
            action: ['authStorage', 'params', function(authStorage, params)
            {
                if(authStorage.hasCredentials())
                {
                    params.credentials = {
                        username: authStorage.getUsername(),
                        password: authStorage.getPassword()
                    };
                }

                return params;
            }]
        },
        settingCredentials: {
            transitions: {
                signin: 'loginRequest'
            },
            //Sets the credentials as candidate
            action: ['authService', 'params', function(authService, params)
            {
                if(params.hasOwnProperty('credentials'))
                {
                    var credentials = params.credentials;
                    authService.setCredentials(credentials.username, credentials.password);
                }
            }]
        },
        loginRequest: {
            transitions: {
                //Checks if the credentials are present(loginError) or not(waitingCredentials)
                401: [
                {
                    to: 'waitingCredentials',
                    predicate: ['authService', 'authRequests', function(authService, authRequests)
                    {
                        return (!authService.hasCredentials() && authRequests.getValid());
                    }]
                },
                {
                    to: 'loginError',
                    predicate: ['authService', 'authRequests', function(authService, authRequests)
                    {
                        return (authService.hasCredentials() && authRequests.getValid());
                    }]
                },
                {
                    to: 'failureLogin',
                    predicate: ['authRequests', function(authRequests)
                    {
                        return !authRequests.getValid();
                    }]
                }],
                201: 'loggedIn'
            },
            //Does the request to the server and save the promise
            action: ['authRequests', function(authRequests)
            {
                authRequests.signin();
            }]
        },
        loginError: {
            transitions: {
                submitted: 'settingCredentials'
            },
            //Delete the credentials that are invalid and notify the error
            action: ['authService', 'params', function(authService, params)
            {
                authService.clearCredentials();
                var callbacks = authService.getCallbacks('login.error');
                for(var i in callbacks)
                {
                    var callback = callbacks[i];
                    callback(params.response);
                }
            }]
        },
        waitingCredentials: {
            transitions: {
                submitted: 'settingCredentials'
            },
            //Checks the previous state and notify the credential need
            action: [
                'authService',
                'authIdentity',
                'authStorage',
                'name',
                'params',
            function(authService, authIdentity, authStorage, name, params)
            {
                if(name == 'logoutRequest')
                {
                    authIdentity.clear();
                    authService.clearRequest();
                    authService.clearCredentials();
                    authStorage.clearCredentials();

                    var callbacksLogout = authService.getCallbacks('logout.successful');
                    for(var i in callbacksLogout)
                    {
                        var funcSuccessful = callbacksLogout[i];
                        funcSuccessful(params.response);
                    }
                }

                authIdentity.suspend();
                authService.clearCredentials();
                authStorage.clearCredentials();
                var callbacksLogin = authService.getCallbacks('login.required');
                for(var j in callbacksLogin)
                {
                    var funcRequest = callbacksLogin[j];
                    funcRequest(params.response);
                }
            }]
        },
        loggedIn: {
            transitions: {
                signout: 'logoutRequest',
                401: 'waitingCredentials'
            },
            //Checks the previous state and creates the identity and notify the login successful
            action: [
                'authService',
                'authIdentity',
                'authStorage',
                'name',
                'params',
            function(authService, authIdentity, authStorage, name, params)
            {
                if(name == 'logoutRequest')
                {
                    var callbacksLogout = authService.getCallbacks('logout.error');
                    for(var i in callbacksLogout)
                    {
                        var funcError = callbacksLogout[i];
                        funcError(params.response);
                    }
                }

                if(name == 'loginRequest')
                {
                    if(authIdentity.isSuspended())
                        authIdentity.restore();

                    if(!authIdentity.has())
                        authIdentity.set(null, params.response.data);

                    authService.clearRequest();

                    var credentials = authService.getCredentials();
                    authStorage.setCredentials(credentials.username, credentials.password);

                    var callbacksLogin = authService.getCallbacks('login.successful');
                    for(var j in callbacksLogin)
                    {
                        var funcSuccessful = callbacksLogin[j];
                        funcSuccessful(params.response);
                    }
                }
            }]
        },
        logoutRequest: {
            transitions: {
                401: 'loggedIn',
                201: 'waitingCredentials'
            },
            //Does the request to the server and save the promise
            action: ['authRequests', function(authRequests)
            {
                authRequests.signout();
            }]
        },
        failureLogin: {
            action: [
                'authService',
                'authIdentity',
                'params',
            function(authService, authIdentity, params)
            {
                authIdentity.clear();
                authService.clearCredentials();

                var callbacksLogin = authService.getCallbacks('login.limit');
                for(var j in callbacksLogin)
                {
                    var funcLimit = callbacksLogin[j];
                    funcLimit(params.response);
                }
            }]
        }
    });
}]);

// Source: src/services/dg-auth-service.js

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

// Source: src/services/auth-client.js

/**
 * Manages authentication info in the client scope.
 */
dgAuth.factory('authClient', [
    'authServer',
    'md5',
function(authServer, md5)
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
         * @param {string} username The username.
         * @param {string} password The password.
         * @param {string} method Method used for the request.
         * @param {string} uri Uri of the resource requested.
         * @param {string} nc The progressive nc.
         * @param {string} cnonce The cnonce.
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
         * @param {string} username The username.
         * @param {string} password The password.
         * @param {string} method Method used for the request.
         * @param {string} uri Uri of the resource requested.
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
                "algorithm=\"" + authServer.info.algorithm + "\", " +
                "response=\"" + generateResponse(username, password, method, uri, nc, cnonce) + "\", " +
                "opaque=\"" + authServer.info.opaque + "\", " +
                "qop=\"" + authServer.info.qop + "\", " +
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
         * @param {string} username The username.
         * @param {string} password The password.
         * @param {string} method The method of the request.
         * @param {string} url The url of the request.
         * @returns {string|null}
         */
        this.processRequest = function(username, password, method, url)
        {
            var header = null;

            if(this.isConfigured())
            {
                if(url.indexOf(authServer.info.domain) >= 0)
                    header = generateHeader(username, password, method, url);
            }

            return header;
        };
    }

    return new AuthClient();
}]);


// Source: src/services/auth-identity.js

dgAuth.factory('authIdentity', function()
{
    function AuthIdentity()
    {
        /**
         * The current identity of user.
         *
         * @type {Object|null}
         * @private
         */
        var _identity = null;

        /**
         * Specifies if the identity is suspended.
         *
         * @type {boolean}
         * @private
         */
        var _suspended = false;

        /**
         * Sets the entire identity fields or
         * if key is specified, one of these.
         *
         * @param {string} [key]
         * @param {Object|string|Array} value
         */
        this.set = function(key, value)
        {
            if(_suspended)
                return;

            if(key)
            {
                if(null == _identity)
                    _identity = {};

                _identity[key] = value;
            }
            else
            {
                if(value instanceof Object)
                    _identity = value;
                else
                    throw 'You have to provide an object if you want to set the identity without a key.';
            }
        };

        /**
         * Gets the entire identity of
         * if key is specified, one single field.
         *
         * @param {string} [key]
         * @returns {Object|Array|string|null}
         */
        this.get = function(key)
        {
            if(_suspended)
                return null;

            if(!key)
                return _identity;

            if(!_identity || !_identity.hasOwnProperty(key))
                return null;

            return _identity[key];
        };

        /**
         * Returns true if the identity
         * is properly set.
         *
         * @returns {boolean}
         */
        this.has = function()
        {
            if(_suspended)
                return false;

            return (null !== _identity);
        };

        /**
         * Clears the identity.
         */
        this.clear = function()
        {
            _identity = null;
        };

        /**
         * Suspends the identity.
         */
        this.suspend = function()
        {
            _suspended = true;
        };

        /**
         * Restores identity that is
         * previously suspended.
         */
        this.restore = function()
        {
            _suspended = false;
        };

        /**
         * Checks if the identity is suspended.
         *
         * @returns {boolean}
         */
        this.isSuspended = function()
        {
            return _suspended;
        };
    }

    return new AuthIdentity();
});

// Source: src/services/auth-server.js

/**
 * Parses and provides server information for the authentication.
 */
dgAuth.provider('authServer', ['dgAuthServiceProvider', function AuthServerProvider(dgAuthServiceProvider)
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

            _configured = false;

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

    this.$get = ['authStorage', function(authStorage)
    {
        var auth = new AuthServer(dgAuthServiceProvider.getHeader(), authStorage);

        if(authStorage.hasServerAuth())
            auth.setConfig(authStorage.getServerAuth());

        return auth;
    }];
}]);


// Source: src/services/auth-service.js

/**
 * Used to manage the authentication.
 */
dgAuth.provider('authService', ['dgAuthServiceProvider', function AuthServiceProvider(dgAuthServiceProvider)
{
    /**
     * Creates the authentication service to performs
     * sign in and sign out, manages the current identity
     * and check the authentication.
     *
     * @constructor
     */
    function AuthService(callbacks, $injector)
    {
        /**
         *
         * @type {string}
         * @private
         */
        var _username = '';

        /**
         *
         * @type {string}
         * @private
         */
        var _password = '';

        /**
         *
         * @param {string} username
         * @param {string} password
         */
        this.setCredentials = function(username, password)
        {
            _username = username.trim();
            _password = password.trim();
        };

        /**
         *
         * @returns {{username: string, password: string}}
         */
        this.getCredentials = function()
        {
            return {
                username: _username,
                password: _password
            };
        };

        this.hasCredentials = function()
        {
            return (('' !== _username.trim()) && ('' !== _password.trim()));
        };

        /**
         *
         */
        this.clearCredentials = function()
        {
            _username = '';
            _password = '';
        };

        /**
         *
         * @type {Object}
         * @private
         */
        var _request = null;

        /**
         *
         * @param {Object} config
         * @param {Object} deferred
         */
        this.setRequest = function(config, deferred)
        {
            _request = {
                config: config,
                deferred: deferred
            };
        };

        /**
         *
         * @returns {Object}
         */
        this.getRequest = function()
        {
            return _request;
        };

        /**
         *
         * @returns {boolean}
         */
        this.hasRequest = function()
        {
            return (null !== _request);
        };

        /**
         *
         */
        this.clearRequest = function()
        {
            _request = null;
        };

        /**
         *
         * @param {string} callback
         * @returns {Array}
         */
        this.getCallbacks = function(callback)
        {
            var split = callback.split('.');
            if(split.length > 2 || split.length == 0)
                throw 'The type for the callbacks is invalid.';

            var family = split[0];
            var type = (split.length == 2) ? split[1] : null;

            var result = [];

            if(callbacks.hasOwnProperty(family))
            {
                var typedCallbacks = callbacks[family];
                for(var i in typedCallbacks)
                {
                    var func = $injector.invoke(typedCallbacks[i]);

                    if(type)
                    {
                        if(func.hasOwnProperty(type))
                            result.push(func[type]);
                    }
                    else
                        result.push(func);
                }
            }

            return result;
        };
    }

    /**
     * Gets a new instance of AuthService.
     *
     * @type {Array}
     */
    this.$get = [
        '$injector',
    /**
     * Gets a new instance of AuthService.
     *
     * @param {Object} $injector
     * @returns {AuthService}
     */
    function($injector)
    {
        return new AuthService(dgAuthServiceProvider.callbacks, $injector);
    }];

}]);

// Source: src/services/auth-requests.js

dgAuth.provider('authRequests', ['dgAuthServiceProvider', function AuthRequestsProvider(dgAuthServiceProvider)
{
    function AuthRequest(limit, config, $http, authService, stateMachine)
    {
        /**
         *
         *
         * @type {promise|null}
         * @private
         */
        var _promise = null;

        /**
         *
         *
         * @returns {promise|null}
         */
        this.getPromise = function()
        {
            return _promise;
        };

        /**
         *
         * @type {number}
         * @private
         */
        var _times = 0;

        /**
         *
         * @returns {boolean}
         */
        this.getValid = function()
        {
            if('inf' == limit)
                return true;

            return (_times <= limit);
        };

        var request = function()
        {
            var promise = null;

            if(authService.hasRequest())
            {
                var request = authService.getRequest();
                promise = $http(request.config).then(function(response)
                    {
                        request.deferred.resolve(response);

                        if(_times > 0)
                            _times = 0;

                        if(stateMachine.isAvailable('201'))
                            stateMachine.send('201', {response: response});

                        return response;
                    },
                    function(response)
                    {
                        request.deferred.reject(response);

                        if(_times > 0)
                            _times = 0;

                        if(stateMachine.isAvailable('failure'))
                            stateMachine.send('failure', {response: response});

                        return response;
                    });
            }

            return promise;
        };

        /**
         *
         * @returns {promise}
         */
        this.signin = function()
        {
            _times++;

            _promise = request();
            if(_promise)
                return _promise;

            _promise = $http(config.login).then(function(response)
                {
                    _times = 0;
                    stateMachine.send('201', {response: response});

                    return response;
                },
                function(response)
                {
                    _times = 0;
                    stateMachine.send('failure', {response: response});

                    return response;
                });

            return _promise;
        };

        /**
         *
         * @returns {promise}
         */
        this.signout = function()
        {
            _promise = request();
            if(_promise)
                return _promise;

            _promise = $http(config.logout).then(function(response)
                {
                    stateMachine.send('201', {response: response});

                    return response;
                },
                function(response)
                {
                    return response;
                });
            return _promise;
        };
    }

    this.$get = ['$http', 'authService', 'stateMachine', function($http, authService, stateMachine)
    {
        return new AuthRequest(dgAuthServiceProvider.getLimit(), dgAuthServiceProvider.getConfig(), $http, authService, stateMachine);
    }];
}]);

// Source: src/services/auth-storage.js

/**
 * Stores information to remember user credentials
 * and server information.
 */
dgAuth.provider('authStorage', ['dgAuthServiceProvider', function AuthStorageProvider(dgAuthServiceProvider)
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
         * The session storage.
         *
         * @type {Storage}
         * @private
         */
        var _sessionStorage = window.sessionStorage;

        /**
         * Checks if the storage has some credentials.
         *
         * @returns {boolean}
         */
        this.hasCredentials = function()
        {
            var username = _storage.getItem('username');
            var password = _storage.getItem('password');

            return ((null !== username && null !== password) && (undefined !== username && undefined !== password));
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
         * Removes the credentials in the storage.
         */
        this.clearCredentials = function()
        {
            _storage.removeItem('username');
            _storage.removeItem('password');
        };

        /**
         * Checks if storage contains the server information.
         *
         * @returns {boolean}
         */
        this.hasServerAuth = function()
        {
            var value = _sessionStorage.getItem('server');
            return (null !== value && undefined !== value);
        };

        /**
         * Sets the server information.
         *
         * @param {Object} server
         */
        this.setServerAuth = function(server)
        {
            _sessionStorage.setItem('server', angular.toJson(server));
        };

        /**
         * Gets the server information.
         *
         * @returns {Object}
         */
        this.getServerAuth = function()
        {
            return angular.fromJson(_sessionStorage.getItem('server'));
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
            _sessionStorage.clear();
        };
    }

    /**
     * Gets a new instance of AuthStorage.
     *
     * @returns {AuthStorageProvider.AuthStorage}
     */
    this.$get = function()
    {
        return new AuthStorage(dgAuthServiceProvider.getStorage());
    };
}]);
