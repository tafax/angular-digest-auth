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

                    $rootScope.requests401.push(request);

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
dgAuth.run([
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