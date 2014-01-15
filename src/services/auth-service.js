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
            console.debug('Performs a login.');

            $http.post($authConfig.getSign().signin, $authConfig.getSign().config)
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
                })
                .error(function(data, status)
                {
                    console.debug('Login error.');

                    $request = null;
                    $rootScope.$broadcast($authConfig.getEvent('signin.error'), data, status);
                });
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

    return new AuthService();

}]);