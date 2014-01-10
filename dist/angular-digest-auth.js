/**
 * AngularJS module to manage HTTP Digest Authentication
 * @version v0.1.0 - 2014-01-10
 * @link https://github.com/mgonto/angular-digest-auth
 * @author Matteo Tafani Alunno <matteo.tafanialunno@gmail.com>
 * @license MIT License, http://www.opensource.org/licenses/MIT
 */
/**
 * The MIT License (MIT)
 *
 * Copyright (c) 2014 Matteo Tafani Alunno <matteo.tafanialunno@gmail.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

'use strict';

/**
 * dhAuth provides functionality to manage
 * user authentication
 */
var dhAuth = angular.module('dhAuth', ['angular-md5', 'ngCookies']);

/**
 * Stores information to remember user credential
 * and server configuration.
 */
dhAuth.provider('$authStorage', function AuthStorageProvider()
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

        this.setCredential = function(username, password)
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

/**
 * Parses and provides server information for the authentication.
 */
dhAuth.factory('$serverAuth', ['$authStorage', function($authStorage)
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

        this.hasHeader = function()
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
 * Manages authentication info in the client scope.
 */
dhAuth.factory('$clientAuth', [
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
             * It needs credential stored in the storage and
             * server authentication information.
             *
             * @returns {boolean}
             */
            this.isConfigured = function()
            {
                return $serverAuth.hasHeader();
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

/**
 * Manages the configuration for the auth module.
 */
dhAuth.provider('$authConfig', function AuthConfigProvider()
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
        authenticationHeader: '$authAuthenticationHeader',
        loginSuccessful: '$authLoginSuccessful',
        loginError: '$authLoginError',
        logoutSuccessful: '$authLogoutSuccessful',
        logoutError: '$authLogoutError',
        loginRequired: '$authLoginRequired',
        loginSubmitted: '$authLoginSubmitted',
        loginStored: '$authLoginStored'
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

/**
 * Used to performs sign in and sign out requests.
 */
dhAuth.factory('$authService', [
    '$authConfig',
    '$authStorage',
    '$clientAuth',
    '$rootScope',
    '$cookies',
    'md5',
    '$log',
    function($authConfig, $authStorage, $clientAuth, $rootScope, $cookies, md5, $log)
    {
        /**
         * Creates the authentication service to performs
         * sign in and sign out.
         *
         * @constructor
         */
        function AuthService()
        {
            var $loginRequest = {
                username: '',
                password: '',
                logged: false,
                requested: false
            };

            var authenticationCheck = function()
            {
                return ($cookies['_auth'] == md5.createHash('true'));
            };

            var loginSuccessful = function(data)
            {
                $log.debug('Login successful.');

                $cookies['_auth'] = md5.createHash('true');

                if($loginRequest.requested)
                {
                    $authStorage.setCredential($loginRequest.username, $loginRequest.password);
                }

                $rootScope.$broadcast($authConfig.getEvents().loginSuccessful, data);
            };

            var loginError = function(data, status)
            {
                $log.debug('Login error.');

                $loginRequest = null;
                $rootScope.$broadcast($authConfig.getEvents().loginError, data, status);
            };

            var logoutSuccessful = function(data)
            {
                $cookies['_auth'] = md5.createHash('false');
                $rootScope.$broadcast($authConfig.getEvents().logoutSuccessful, data);
            };

            var logoutError = function(data, status)
            {

            };

            this.setLoginRequest = function(username, password)
            {
                $loginRequest = {
                    username: username,
                    password: password,
                    logged: false,
                    requested: true
                };
            };

            this.getLoginRequest = function()
            {
                return $loginRequest;
            };

            this.isLoginRequest = function()
            {
                return $loginRequest.requested;
            };

            this.isAbleToSignin = function()
            {
                return ($clientAuth.isConfigured() && $authStorage.hasCredential());
            };

            this.isAuthenticated = function()
            {
                return authenticationCheck();
            };

            this.processRequest = function(request)
            {
                if($clientAuth.isConfigured())
                {
                    if(($loginRequest || $authStorage.hasCredential()))
                    {
                        var username;
                        var password;

                        if($authStorage.hasCredential())
                        {
                            username = $authStorage.getUsername();
                            password = $authStorage.getPassword();
                        }
                        else
                        {
                            username = $loginRequest.username;
                            password = $loginRequest.password;
                        }
                    }

                    $clientAuth.processRequest(username, password, request);
                }
            };

            this.signin = function()
            {
                $rootScope.$broadcast('$authRequestSignin', {
                    successful: loginSuccessful,
                    error: loginError
                })
            };

            this.signout = function()
            {
                $rootScope.$broadcast('$authRequestSignout', {
                    successful: logoutSuccessful,
                    error: logoutError
                });
            };
        }

        return new AuthService();

    }]);

/**
 * Configures http to intercept requests and responses with error 401.
 */
dhAuth.config(['$httpProvider', function($httpProvider)
{
    $httpProvider.interceptors.push([
        '$rootScope',
        '$q',
        '$authConfig',
        '$authService',
        '$log',
        function($rootScope, $q, $authConfig, $authService, $log)
        {
            return {
                'request': function(request)
                {
                    $authService.processRequest(request);

                    return (request || $q.when(request));
                },
                'responseError': function(rejection)
                {
                    if(rejection.status === 401)
                    {
                        $log.debug("Server has requested an authentication.");

                        var deferred = $q.defer();
                        var request = {
                            config: rejection.config,
                            deferred: deferred
                        };

                        var events = $authConfig.getEvents();

                        $rootScope.requests401.push(request);
                        $rootScope.$broadcast(events.authenticationHeader, rejection.headers($authConfig.getHeader()));

                        if($authService.isLoginRequest())
                            $rootScope.$broadcast(events.loginError);

                        if($authService.isAbleToSignin())
                            $rootScope.$broadcast(events.loginStored);
                        else
                            $rootScope.$broadcast(events.loginRequired);

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
dhAuth.run([
    '$rootScope',
    '$authConfig',
    '$authService',
    '$authStorage',
    '$serverAuth',
    '$http',
    '$log',
    function($rootScope, $authConfig, $authService, $authStorage, $serverAuth, $http, $log)
    {
        $rootScope.requests401 = [];

        var events = $authConfig.getEvents();

        var signin = function(event, data)
        {
            $log.debug('Performs a sign in.');

            $http.post($authConfig.getSign().signin, $authConfig.getSign().config)
                .success(data.successful)
                .error(data.error);
        };

        var signout = function(event, data)
        {
            $log.debug('Performs a sign out.');

            $http.post($authConfig.getSign().signout, $authConfig.getSign().config)
                .success(data.logoutSuccessful)
                .error(data.logoutError);
        };

        var resendRequests = function()
        {
            $log.debug('Request another sign in.');

            for(var i=0; i<$rootScope.requests401.length; i++)
            {
                var request = $rootScope.requests401[i];

                $http(request.config).then(function(response)
                {
                    request.deferred.resolve(response);
                });
            }
        };

        $rootScope.$on('$authRequestSignin', signin);
        $rootScope.$on('$authRequestSignout', signout);

        $rootScope.$on(events.authenticationHeader, function(event, header)
        {
            $log.debug('Parse header for authentication. ' + event.name + " with " + header);
            $serverAuth.parseHeader(header);
        });

        $rootScope.$on(events.loginSubmitted, function(event, data)
        {
            $authService.setLoginRequest(data.username, data.password);
            resendRequests();
        });

        $rootScope.$on(events.loginStored, resendRequests);

        
        
        $log.log();
    }]);