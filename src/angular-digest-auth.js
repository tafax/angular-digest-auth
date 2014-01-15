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
    '$serverAuth',
    '$http',
function($rootScope, $authConfig, $authService, $serverAuth, $http)
{
    $rootScope.requests401 = [];

    var resendRequests = function()
    {
        console.debug('Request another login.');

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

        $rootScope.requests401 = [];
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
        console.debug('Submitted credential.');

        if($rootScope.requests401.length == 0)
            $authService.signin();
        else
            resendRequests();
    });
}]);