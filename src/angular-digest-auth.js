'use strict';

/**
 * dgAuth provides functionality to manage
 * user authentication
 */
var dgAuth = angular.module('dgAuth', ['angular-md5', 'ngCookies', 'FSM']);

/**
 * Configures http to intercept requests and responses with error 401.
 */
dgAuth.config(['$httpProvider', function($httpProvider)
{
    $httpProvider.interceptors.push([
        '$rootScope',
        '$q',
        'authService',
        'authClient',
        'authServer',
        'stateMachine',
    function($rootScope, $q, authService, authClient, authServer, stateMachine)
    {
        return {
            'request': function(request)
            {
                var login = authService.getCredentials();
                var header = authClient.processRequest(login.username, login.password, request.method, request.url);

                if(header)
                    request.headers['Authorization'] = header;

                return (request || $q.when(request));
            },
            'responseError': function(rejection)
            {
                if(rejection.status === 401)
                {
                    console.debug("Server has requested an authentication.");

                    if(!authServer.parseHeader(rejection))
                    {
                        return $q.reject(rejection);
                    }

                    var deferred = $q.defer();

                    authService.setRequest(rejection.config, deferred);
                    stateMachine.send('401', {response: rejection});

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
    'authEvents',
    'authService',
    'authClient',
function($rootScope, authEvents, authService, authClient)
{

}]);