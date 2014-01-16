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

        this.setRequest = function(request)
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