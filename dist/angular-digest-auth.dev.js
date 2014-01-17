/**
 * AngularJS module to manage HTTP Digest Authentication
 * @version v0.1.2 - 2014-01-16
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
        '$authConfig',
    function($rootScope, $q, $authConfig)
    {
        return {
            'request': function(request)
            {
                $rootScope.$broadcast($authConfig.getEvent('process.request'), request);

                return (request || $q.when(request));
            },
            'responseError': function(rejection)
            {
                if(rejection.status === 401)
                {
                    $rootScope.$broadcast($authConfig.getEvent('process.response'), rejection);

                    if(rejection.mustTerminate)
                        return $q.reject(rejection);

                    console.debug("Server has requested an authentication.");

                    var header = rejection.headers($authConfig.getHeader());

                    if(null == header)
                    {
                        $rootScope.$broadcast($authConfig.getEvent('authentication.notFound'));
                        return $q.reject(rejection);
                    }

                    var deferred = $q.defer();
                    var request = {
                        config: rejection.config,
                        deferred: deferred
                    };

                    console.debug('Parse header for authentication: ' + header);
                    $rootScope.$broadcast($authConfig.getEvent('authentication.header'), header, request);
                    $rootScope.$broadcast($authConfig.getEvent('signin.required'));

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
    '$authConfig',
    '$authService',
    '$clientAuth',
    '$serverAuth',
function($rootScope, $authConfig, $authService, $clientAuth, $serverAuth)
{
    $rootScope.$on($authConfig.getEvent('process.request'), function(event, request)
    {
        if($clientAuth.isConfigured())
        {
            var login = $authService.getCredentials();

            $clientAuth.processRequest(login.username, login.password, request);
        }
    });

    $rootScope.$on($authConfig.getEvent('process.response'), function(event, response)
    {
        $authService.mustTerminate(response);
    });

    $rootScope.$on($authConfig.getEvent('authentication.header'), function(event, header, request)
    {
        $authService.setHttpRequest(request);
        $serverAuth.parseHeader(header);
    });
}]);
/**
 * Manages authentication info in the client scope.
 */
dgAuth.factory('$clientAuth', [
    '$rootScope',
    '$serverAuth',
    'md5',
function($rootScope, $serverAuth, md5)
{
    /**
     * Creates the service to use information generating
     * header for each request.
     *
     * @constructor
     */
    function ClientAuth()
    {
        var $chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
        var $nc = 0;

        /**
         * Generates the cnonce with the given length.
         *
         * @param length Length of the cnonce.
         * @returns {string}
         */
        var generateNonce = function(length)
        {
            var nonce = [];
            var charsLength = $chars.length;

            for (var i = 0; i < length; ++i)
            {
                nonce.push($chars[Math.random() * charsLength | 0]);
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
            $nc++;

            var zeros = 8 - $nc.toString().length;

            var nc = "";
            for(var i=0; i<zeros; i++)
            {
                nc += "0";
            }

            return (nc + $nc);
        };

        /**
         * Generate the response.
         *
         * @param username
         * @param password
         * @param method Method used for the request.
         * @param uri Uri of the resource requested.
         * @param nc The progressive nc.
         * @param cnonce The cnonce.
         * @returns {string}
         */
        var generateResponse = function(username, password, method, uri, nc, cnonce)
        {
            var ha1 = md5.createHash(username + ":" + $serverAuth.realm + ":" + password);
            var ha2 = md5.createHash(method + ":" + uri);
            return md5.createHash(ha1 + ":" + $serverAuth.nonce + ":" + nc + ":" + cnonce + ":" + $serverAuth.qop + ":" + ha2);
        };

        /**
         * Aggregates all information to generate header.
         *
         * @param username
         * @param password
         * @param method Method used for the request.
         * @param uri Uri of the resource requested.
         * @returns {string}
         */
        var generateHeader = function(username, password, method, uri)
        {
            var nc = getNc();
            var cnonce = generateNonce(16);

            return "Digest " +
                "username=\"" + username + "\", " +
                "realm=\"" + $serverAuth.realm + "\", " +
                "nonce=\"" + $serverAuth.nonce + "\", " +
                "uri=\"" + uri + "\", " +
                "algorithm=" + $serverAuth.algorithm + ", " +
                "response=\"" + generateResponse(username, password, method, uri, nc, cnonce) + "\", " +
                "opaque=\"" + $serverAuth.opaque + "\", " +
                "qop=" + $serverAuth.qop + ", " +
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
            return $serverAuth.isConfigured();
        };

        /**
         * Process a request and add the authorization header
         * if the request need an authentication.
         *
         * @param username
         * @param password
         * @param request
         */
        this.processRequest = function(username, password, request)
        {
            if(request.url.indexOf($serverAuth.domain) >= 0)
                request.headers['Authorization'] = generateHeader(username, password, request.method, request.url);
        };
    }

    return new ClientAuth();
}]);

'use strict';

/**
 * Manages the configuration for the auth module.
 */
dgAuth.provider('$authConfig', function AuthConfigProvider()
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
     * Gets AuthEvents service.
     *
     * @returns {AuthConfigProvider.AuthEvents}
     */
    this.$get = function()
    {
        return new AuthConfig($sign, $events, $header);
    };
});
/**
 * Parses and provides server information for the authentication.
 */
dgAuth.factory('$serverAuth', ['$authStorage', function($authStorage)
{
    /**
     * Creates the service for the server info.
     *
     * @constructor
     */
    function ServerAuth()
    {
        var $valuePattern = /([a-zA-Z]+)=\"?([a-zA-Z0-9\/\s]+)\"?/;
        var $header = false;

        this.realm = "";
        this.domain = "";
        this.nonce = "";
        this.opaque = "";
        this.algorithm = "";
        this.qop = "";

        this.isConfigured = function()
        {
            return $header;
        };

        this.config = function(server)
        {
            this.realm = server.realm;
            this.domain = server.domain;
            this.nonce = server.nonce;
            this.opaque = server.opaque;
            this.algorithm = server.algorithm;
            this.qop = server.qop;
            $header = true;
        };

        this.parseHeader = function(headerLine)
        {
            var splitting = headerLine.split(', ');

            for(var i=0; i<splitting.length; i++)
            {
                var values = $valuePattern.exec(splitting[i]);
                this[values[1]] = values[2];
            }

            $header = true;
            $authStorage.setServerAuth(this);
        };
    }

    /**
     * Creates server info taking
     * the information from storage
     * if they are previously saved.
     *
     * @returns {ServerAuth}
     */
    var getServerAuth = function()
    {
        var auth = new ServerAuth();

        if($authStorage.hasServerAuth())
            auth.config($authStorage.getServerAuth());

        return auth;
    };

    return getServerAuth();
}]);

/**
 * Used to manage the authentication.
 */
dgAuth.provider('$authService', [function AuthServiceProvider()
{
    /**
     * Creates the authentication service to performs
     * sign in and sign out, manages the current identity
     * and check the authentication.
     *
     * @constructor
     */
    function AuthService(config, $authConfig, $authStorage, $rootScope, $http, $q, $cookies, md5)
    {
        var $signin = config.signin;
        var $signout = config.signout;
        var $callbacks = config.callbacks;
        var $automatic = config.automatic;

        /**
         * The current identity
         *
         * @type {Object}
         */
        var $identity = null;

        /**
         * Initializes the login object.
         *
         * @returns {{username: string, password: string, httpRequest: null, mustTerminate: boolean}}
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
        var $login = initLogin();

        var $logout = initLogout();

        this.setHttpRequest = function(request)
        {
            angular.extend($login, {
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
            return (null !== $identity);
        };

        /**
         * Gets the identity.
         *
         * @returns {Object}
         */
        this.getIdentity = function()
        {
            return $identity;
        };

        /**
         * Sets the credential used for sign in.
         *
         * @param {String} username
         * @param {String} password
         */
        this.setCredentials = function(username, password)
        {
            angular.extend($login, {
                username: username,
                password: password,
                mustTerminate: true
            });

            $rootScope.$broadcast($authConfig.getEvent('credential.submitted'), {
                username: $login.username,
                password: $login.password
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
                username: $login.username,
                password: $login.password
            };
        };

        this.mustTerminate = function(response)
        {
            if(response.config.url == $signin.url)
            {
                response.mustTerminate = $login.mustTerminate;
                return;
            }

            if(response.config.url == $signout.url)
                response.mustTerminate = $logout.mustTerminate;
        };

        var performSignin = function()
        {
            console.debug('Performs a login.');

            var deferred = $q.defer();

            $http($signin)
                .success(function(data)
                {
                    console.debug('Login successful.');

                    $identity = angular.extend({
                        username: $login.username
                    }, data);

                    $cookies['_auth'] = md5.createHash('true');

                    $authStorage.setCredentials($login.username, $login.password);

                    $rootScope.$broadcast($authConfig.getEvent('credential.stored'), {
                        username: $login.username,
                        password: $login.password
                    });

                    $rootScope.$broadcast($authConfig.getEvent('signin.successful'), data);

                    angular.extend($login, {
                        mustTerminate: false
                    });

                    deferred.resolve(data);
                })
                .error(function(data, status)
                {
                    console.debug('Login error.');

                    $rootScope.$broadcast($authConfig.getEvent('signin.error'), data, status);

                    $login = initLogin();

                    deferred.reject(data);
                });

            return deferred;
        };

        /**
         * Performs the login.
         */
        this.signin = function()
        {
            if($cookies['_auth'] == md5.createHash('true') || $automatic)
            {
                if($authStorage.hasCredential())
                {
                    angular.extend($login, {
                        username: $authStorage.getUsername(),
                        password: $authStorage.getPassword(),
                        mustTerminate: true
                    });
                }
            }

            if(!$login.httpRequest)
            {
                if(!$login.deferred)
                {
                    $login.deferred = performSignin();
                    $login.deferred.promise.then($callbacks.login.successful, $callbacks.login.error);
                }
            }
            else
            {
                var promise = $http($login.httpRequest.config).then(function(response)
                {
                    $login.httpRequest.deferred.resolve(response);
                },
                function(response)
                {
                    $login.httpRequest.deferred.reject(response);
                });

                promise['finally'](function()
                {
                    $login.httpRequest = null;
                });
            }

            return $login.deferred.promise;
        };

        var performSignout = function()
        {
            console.debug('Performs a logout.');

            var deferred = $q.defer();

            $http($signout)
                .success(function(data)
                {
                    console.debug('Logout successful.');

                    $cookies['_auth'] = md5.createHash('false');

                    $identity = null;
                    $login = initLogin();

                    $rootScope.$broadcast($authConfig.getEvent('signout.successful'), data);

                    deferred.resolve(data);
                })
                .error(function(data, status)
                {
                    console.debug('Logout error.');

                    $rootScope.$broadcast($authConfig.getEvent('signout.error'), data, status);

                    deferred.reject(data);
                });

            return deferred;
        };

        /**
         * Performs the logout.
         */
        this.signout = function()
        {
            if(!$logout.deferred)
            {
                $logout.deferred = performSignout();
                $logout.deferred.promise.then($callbacks.logout.successful, $callbacks.logout.error);
            }

            return $logout.deferred.promise;
        };

        /**
         * Checks the authentication.
         *
         * @returns {promise|*}
         */
        this.isAuthenticated = function()
        {
            var deferred = $q.defer();

            if($logout.deferred)
            {
                $logout.deferred.promise.then(function()
                    {
                        deferred.reject(null);
                    },
                    function()
                    {
                        deferred.resolve(($cookies['_auth'] == md5.createHash('true') && null !== $identity))
                    });
            }
            else if($login.deferred)
            {
                $login.deferred.promise.then(function()
                    {
                        deferred.resolve(($cookies['_auth'] == md5.createHash('true') && null !== $identity));
                    },
                    function(reason)
                    {
                        deferred.reject(reason);
                    });
            }

            return deferred.promise;
        };
    }

    var $automatic = true;

    this.setAutomatic = function(automatic)
    {
        $automatic = automatic;
    };

    this.getAutomatic = function()
    {
        return $automatic;
    };

    var $signin = {
        method: 'POST',
        url: '/signin'
    };

    this.setSignin = function(signin)
    {
        angular.extend($signin, signin);
    };

    this.getSignin = function()
    {
        return $signin;
    };

    var $signout = {
        method: 'POST',
        url: '/signout'
    };

    this.setSignout = function(signout)
    {
       angular.extend($signout, signout);
    };

    this.getSignout = function()
    {
        return $signout;
    };

    var $callbacks = {
        login: {
            successful: function(){},
            error: function(){}
        },
        logout: {
            successful: function(){},
            error: function(){}
        }
    };

    this.setCallbacks = function(callbacks)
    {
        angular.extend($callbacks, callbacks);
    };

    this.getCallbacks = function()
    {
        return $callbacks;
    };

    this.$get = [
        '$authConfig',
        '$authStorage',
        '$rootScope',
        '$http',
        '$q',
        '$cookies',
        'md5',
    function($authConfig, $authStorage, $rootScope, $http, $q, $cookies, md5)
    {
        return new AuthService({
            signin: $signin,
            signout: $signout,
            callbacks: $callbacks,
            automatic: $automatic
        }, $authConfig, $authStorage, $rootScope, $http, $q, $cookies, md5);
    }];

}]);
/**
 * Stores information to remember user credential
 * and server configuration.
 */
dgAuth.provider('$authStorage', function AuthStorageProvider()
{
    /**
     * Creates the service for the storage.
     * You can choose the type of storage to
     * save user credential.
     * Server info are always stored in the
     * session.
     *
     * @param storage Storage to save user credential.
     * @constructor
     */
    function AuthStorage(storage)
    {
        var $storage = storage;

        this.hasCredential = function()
        {
            var username = $storage.getItem('username');
            var password = $storage.getItem('password');

            return ((null !== username && null !== password));
        };

        this.setCredentials = function(username, password)
        {
            $storage.setItem('username', username);
            $storage.setItem('password', password);
        };

        this.hasServerAuth = function()
        {
            return (null !== sessionStorage.getItem('server'));
        };

        this.setServerAuth = function(server)
        {
            sessionStorage.setItem('server', JSON.stringify(server));
        };

        this.getServerAuth = function()
        {
            return JSON.parse(sessionStorage.getItem('server'));
        };

        this.getUsername = function()
        {
            return $storage.getItem('username');
        };

        this.getPassword = function()
        {
            return $storage.getItem('password');
        };

        this.clear = function()
        {
            $storage.clear();
            sessionStorage.clear();
        };
    }

    // Default storage for user credential.
    var $storage = sessionStorage;

    /**
     * Sets storage for user credential.
     *
     * @param storage
     */
    this.setStorage = function(storage)
    {
        $storage = storage;
    };

    this.$get = function()
    {
        return new AuthStorage($storage);
    };
});
