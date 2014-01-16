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
        $authService.setRequest(request);
        $serverAuth.parseHeader(header);
    });
}]);