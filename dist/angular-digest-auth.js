/**
 * AngularJS module to manage HTTP Digest Authentication
 * @version v0.1.0 - 2014-01-13
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

                    if(rejection.login)
                        return $q.reject(rejection);

                    

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
    '$serverAuth',
    '$http',
function($rootScope, $authConfig, $authService, $serverAuth, $http)
{
    $rootScope.requests401 = [];

    var resendRequests = function()
    {
        

        for(var i=0; i<$rootScope.requests401.length; i++)
        {
            var request = $rootScope.requests401[i];

            $http(request.config).then(function(response)
            {
                request.deferred.resolve(response);
            },
            function(response)
            {
                request.deferred.reject(response);
            });
        }
    };

    $rootScope.$on($authConfig.getEvent('process.request'), function(event, request)
    {
        $authService.processRequest(request);
    });

    $rootScope.$on($authConfig.getEvent('process.response'), function(event, response)
    {
        if($authService.isRequested())
            response.login = true;
    });

    $rootScope.$on($authConfig.getEvent('authentication.header'), function(event, header, request)
    {
        $rootScope.requests401.push(request);
        $serverAuth.parseHeader(header);
    });

    $rootScope.$on($authConfig.getEvent('signin.required'), function(event)
    {
        if($authService.restoreCredential())
        {
            event.preventDefault();
            resendRequests();
        }
    });

    $rootScope.$on($authConfig.getEvent('credential.submitted'), function(event, credential)
    {
        
        resendRequests();
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
 * Used to manage the authentication.
 */
dgAuth.factory('$authService', [
    '$authConfig',
    '$authStorage',
    '$clientAuth',
    '$rootScope',
    '$http',
    '$cookies',
    'md5',
function($authConfig, $authStorage, $clientAuth, $rootScope, $http, $cookies, md5)
{
    /**
     * Creates the authentication service to performs
     * sign in and sign out, manages the current identity
     * and check the authentication.
     *
     * @constructor
     */
    function AuthService()
    {
        /**
         * The current identity
         *
         * @type {Object}
         */
        var $identity;

        /**
         * The request used to sing in user.
         *
         * @type {{username: string, password: string, requested: boolean}}
         */
        var $request = {
            username: '',
            password: '',
            requested: false
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
        this.setRequest = function(username, password)
        {
          $request = {
                username: username,
                password: password,
                requested: true
            };

            $rootScope.$broadcast($authConfig.getEvent('credential.submitted'), {
                username: $request.username,
                password: $request.password,
                requested: $request.requested
            });
        };

        /**
         * Gets the request for the sign in.
         *
         * @returns {{username: string, password: string, requested: boolean}}
         */
        this.getRequest = function()
        {
            return $request;
        };

        /**
         * Checks if the request is set properly.
         *
         * @returns {boolean}
         */
        this.isRequested = function()
        {
            return $request.requested;
        };

        /**
         * Checks the authentication.
         *
         * @returns {boolean}
         */
        this.isAuthenticated = function()
        {
            return ($cookies['_auth'] == md5.createHash('true') && null !== $identity);
        };

        /**
         * Gets the credential stored in the auth storage.
         *
         * @returns {boolean}
         */
        this.restoreCredential = function()
        {
            if(!$authStorage.hasCredential() || !$clientAuth.isConfigured())
                return false;

            $request.username = $authStorage.getUsername();
            $request.password = $authStorage.getPassword();

            return true;
        };

        /**
         * Processes the request to the server.
         *
         * @param {Object} request
         */
        this.processRequest = function(request)
        {
            if($clientAuth.isConfigured())
                $clientAuth.processRequest($request.username, $request.password, request);
        };

        /**
         * Performs the login.
         */
        this.signin = function()
        {
            

            $http.post($authConfig.getSign().signin, $authConfig.getSign().config)
                .success(function(data)
                {
                    

                    $identity = angular.extend({
                        username: $request.username
                    }, data);

                    $cookies['_auth'] = md5.createHash('true');

                    if($request.requested)
                    {
                        $authStorage.setCredential($request.username, $request.password);
                        $rootScope.$broadcast($authConfig.getEvent('credential.stored'), {
                            username: $request.username,
                            password: $request.password
                        });

                        $request.requested = false;
                    }

                    $rootScope.$broadcast($authConfig.getEvent('signin.successful'), data);
                })
                .error(function(data, status)
                {
                    

                    $request = null;
                    $rootScope.$broadcast($authConfig.getEvent('signin.error'), data, status);
                });
        };

        /**
         * Performs the logout.
         */
        this.signout = function()
        {
            

            $http.post($authConfig.getSign().signout, $authConfig.getSign().config)
                .success(function(data)
                {
                    

                    $cookies['_auth'] = md5.createHash('false');
                    $identity = null;
                    $rootScope.$broadcast($authConfig.getEvent('signout.successful'), data);
                })
                .error(function(data, status)
                {
                    

                    $rootScope.$broadcast($authConfig.getEvent('signout.error'), data, status);
                });
        };
    }

    return new AuthService();

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
