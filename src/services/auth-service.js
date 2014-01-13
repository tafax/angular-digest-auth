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
        var $loginRequest = {
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
        this.setLoginRequest = function(username, password)
        {
            $loginRequest = {
                username: username,
                password: password,
                requested: true
            };

            $rootScope.$broadcast($authConfig.getEvent('credential.submitted'), {
                username: $loginRequest.username,
                password: $loginRequest.password,
                requested: $loginRequest.requested
            });
        };

        /**
         * Gets the request for the sign in.
         *
         * @returns {{username: string, password: string, requested: boolean}}
         */
        this.getLoginRequest = function()
        {
            return $loginRequest;
        };

        /**
         * Checks if the request is set properly.
         *
         * @returns {boolean}
         */
        this.isLoginRequested = function()
        {
            return $loginRequest.requested;
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

            $loginRequest.username = $authStorage.getUsername();
            $loginRequest.password = $authStorage.getPassword();

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
                $clientAuth.processRequest($loginRequest.username, $loginRequest.password, request);
        };

        /**
         * Performs the sign in.
         */
        this.signin = function()
        {
            console.debug('Performs a sign in.');

            $http.post($authConfig.getSign().signin, $authConfig.getSign().config)
                .success(function(data)
                {
                    console.debug('Sign in successful.');

                    $identity = angular.extend({
                        username: $loginRequest.username
                    }, data);

                    $cookies['_auth'] = md5.createHash('true');

                    if($loginRequest.requested)
                    {
                        $authStorage.setCredential($loginRequest.username, $loginRequest.password);
                        $rootScope.$broadcast($authConfig.getEvent('credential.stored'), {
                            username: $loginRequest.username,
                            password: $loginRequest.password
                        });

                        $loginRequest.requested = false;
                    }

                    $rootScope.$broadcast($authConfig.getEvent('signin.successful'), data);
                })
                .error(function(data, status)
                {
                    console.debug('Sign in error.');

                    $loginRequest = null;
                    $rootScope.$broadcast($authConfig.getEvent('signin.error'), data, status);
                });
        };

        /**
         * Performs the sign out.
         */
        this.signout = function()
        {
            console.debug('Performs a sign out.');

            $http.post($authConfig.getSign().signout, $authConfig.getSign().config)
                .success(function(data)
                {
                    console.debug('Sign out successful.');

                    $cookies['_auth'] = md5.createHash('false');
                    $identity = null;
                    $rootScope.$broadcast($authConfig.getEvent('signout.successful'), data);
                })
                .error(function(data, status)
                {
                    console.debug('Sign out error.');

                    $rootScope.$broadcast($authConfig.getEvent('signout.error'), data, status);
                });
        };
    }

    return new AuthService();

}]);