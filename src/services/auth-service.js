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
    function AuthService(config, $authConfig, $authStorage, $clientAuth, $rootScope, $http, $q, $cookies, md5)
    {
        var $deferred = null;

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
            angular.extend($request, {
                username: username,
                password: password,
                requested: true
            });

            $rootScope.$broadcast($authConfig.getEvent('credential.submitted'), {
                username: $request.username,
                password: $request.password
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
            // TODO: aggiungere il check con le promise
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

        var performSignin = function()
        {
            var deferred = $q.defer();

            $http($signin)
                .success(function(data)
                {
                    console.debug('Login successful.');

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

                    deferred.resolve(data);
                })
                .error(function(data, status)
                {
                    console.debug('Login error.');

                    $request = null;
                    $rootScope.$broadcast($authConfig.getEvent('signin.error'), data, status);

                    deferred.reject(data);
                });

            return deferred;
        };

        /**
         * Performs the login.
         */
        this.signin = function()
        {
            console.debug('Performs a login.');

            if($cookies['_auth'] == md5.createHash('true') && $automatic)
            {
                // TODO: caricare le credenziali dallo storage
            }

            $deferred = performSignin();
            $deferred.promise.then($callbacks.login.successful, $callbacks.login.error);
        };

        /**
         * Performs the logout.
         */
        this.signout = function()
        {
            console.debug('Performs a logout.');

            $http.post($authConfig.getSign().signout, $authConfig.getSign().config)
                .success(function(data)
                {
                    console.debug('Logout successful.');

                    $cookies['_auth'] = md5.createHash('false');
                    $identity = null;
                    $rootScope.$broadcast($authConfig.getEvent('signout.successful'), data);
                })
                .error(function(data, status)
                {
                    console.debug('Logout error.');

                    $rootScope.$broadcast($authConfig.getEvent('signout.error'), data, status);
                });
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
        '$clientAuth',
        '$rootScope',
        '$http',
        '$q',
        '$cookies',
        'md5',
    function($authConfig, $authStorage, $clientAuth, $rootScope, $http, $q, $cookies, md5)
    {
        return new AuthService({
            signin: $signin,
            signout: $signout,
            callbacks: $callbacks,
            automatic: $automatic
        }, $authConfig, $authStorage, $clientAuth, $rootScope, $http, $q, $cookies, md5);
    }];

}]);