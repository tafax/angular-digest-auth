/**
 * AngularJS module to manage HTTP Digest Authentication
 * @version v0.1.0 - 2014-01-10
 * @link https://github.com/mgonto/angular-digest-auth
 * @author Matteo Tafani Alunno <matteo.tafanialunno@gmail.com>
 * @license MIT License, http://www.opensource.org/licenses/MIT
 */
'use strict';

/**
 * dhAuth provides functionality to manage
 * user authentication
 */
var dhAuth = angular.module('dgAuth', ['angular-md5', 'ngCookies']);

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
        '$serverAuth',
    function($rootScope, $q, $authConfig, $authService, $serverAuth)
    {
        return {
            'request': function(request)
            {
                $authService.processRequest(request);

                return (request || $q.when(request));
            },
            'responseError': function(rejection)
            {
                if($authService.isLoginRequested())
                {
                    $rootScope.$broadcast($authConfig.getEvent('login.error'), rejection);
                    return $q.reject(rejection);
                }

                if(rejection.status === 401)
                {
                    console.debug("Server has requested an authentication.");

                    var deferred = $q.defer();
                    var request = {
                        config: rejection.config,
                        deferred: deferred
                    };

                    $rootScope.requests401.push(request);

                    var header = rejection.headers($authConfig.getHeader());

                    $serverAuth.parseHeader(header);

                    console.debug('Parse header for authentication: ' + header);
                    $rootScope.$broadcast($authConfig.getEvent('authentication.header'), header);

                    if(!$authService.restoreCredential())
                    {
                        $rootScope.$broadcast($authConfig.getEvent('login.required'));
                    }

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
    '$http',
    function($rootScope, $authConfig, $authService, $http)
    {
        $rootScope.requests401 = [];

        var resendRequests = function()
        {
            console.debug('Request another sign in.');

            for(var i=0; i<$rootScope.requests401.length; i++)
            {
                var request = $rootScope.requests401[i];

                $http(request.config).then(function(response)
                {
                    request.deferred.resolve(response);
                });
            }
        };

        $rootScope.$on('$authRequestSignin', function(event, data)
        {
            console.debug('Performs a sign in.');

            $http.post($authConfig.getSign().signin, $authConfig.getSign().config)
                .success(data.successful)
                .error(data.error);

            event.preventDefault();
        });

        $rootScope.$on('$authRequestSignout', function(event, data)
        {
            console.debug('Performs a sign out.');

            $http.post($authConfig.getSign().signout, $authConfig.getSign().config)
                .success(data.successful)
                .error(data.error);

            event.preventDefault();
        });

        $rootScope.$on($authConfig.getEvent('credential.submitted'), resendRequests);
        $rootScope.$on($authConfig.getEvent('credential.restored'), resendRequests);
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
         * It needs server authentication information.
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

'use strict';

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
 * Used to performs sign in and sign out requests.
 */
dhAuth.factory('$authService', [
    '$authConfig',
    '$authStorage',
    '$clientAuth',
    '$rootScope',
    '$cookies',
    'md5',
function($authConfig, $authStorage, $clientAuth, $rootScope, $cookies, md5)
{
    /**
     * Creates the authentication service to performs
     * sign in and sign out.
     *
     * @constructor
     */
    function AuthService()
    {
        var $identity;

        var $loginRequest = {
            username: '',
            password: '',
            requested: false
        };

        var authenticationCheck = function()
        {
            return ($cookies['_auth'] == md5.createHash('true') && null !== $identity);
        };

        var signinSuccessful = function(data)
        {
            console.debug('Login successful.');

            $identity = data;
            $cookies['_auth'] = md5.createHash('true');

            if($loginRequest.requested)
            {
                $authStorage.setCredential($loginRequest.username, $loginRequest.password);
                $rootScope.$broadcast($authConfig.getEvents().credential.stored, {
                    username: $loginRequest.username,
                    password: $loginRequest.password
                });
            }

            $rootScope.$broadcast($authConfig.getEvents().signin.successful, data);
        };

        var signinError = function(data, status)
        {
            console.debug('Login error.');

            $loginRequest = null;
            $rootScope.$broadcast($authConfig.getEvents().signin.error, data, status);
        };

        var signoutSuccessful = function(data)
        {
            console.debug('Logout successful.');

            $cookies['_auth'] = md5.createHash('false');
            $identity = null;
            $rootScope.$broadcast($authConfig.getEvents().signout.successful, data);
        };

        var signoutError = function(data, status)
        {
            console.debug('Logout error.');

            $rootScope.$broadcast($authConfig.getEvents().signout.error, data, status);
        };

        this.hasIdentity = function()
        {
            return (null !== $identity);
        };

        this.getIdentity = function()
        {
            return $identity;
        };

        this.setLoginRequest = function(username, password)
        {
            $loginRequest = {
                username: username,
                password: password,
                requested: true
            };

            $rootScope.$broadcast($authConfig.getEvents().loginSubmitted, $loginRequest);
        };

        this.getLoginRequest = function()
        {
            return $loginRequest;
        };

        this.isLoginRequested = function()
        {
            return $loginRequest.requested;
        };

        this.isAuthenticated = function()
        {
            return authenticationCheck();
        };

        this.restoreCredential = function()
        {
            if(!$authStorage.hasCredential() || !$clientAuth.isConfigured())
                return false;

            $loginRequest.username = $authStorage.getUsername();
            $loginRequest.password = $authStorage.getPassword();

            $rootScope.$broadcast($authConfig.getEvent('credential.restored'));

            return true;
        };

        this.processRequest = function(request)
        {
            if($clientAuth.isConfigured())
                $clientAuth.processRequest($loginRequest.username, $loginRequest.password, request);
        };

        this.signin = function()
        {
            $rootScope.$broadcast('$authRequestSignin', {
                successful: signinSuccessful,
                error: signinError
            })
        };

        this.signout = function()
        {
            $rootScope.$broadcast('$authRequestSignout', {
                successful: signoutSuccessful,
                error: signoutError
            });
        };
    }

    return new AuthService();

}]);
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
