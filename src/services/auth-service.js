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