'use strict';

/**
 * Configures http to intercept requests and responses with error 401.
 */
dgAuth.config(['$httpProvider', function($httpProvider)
{
    $httpProvider.interceptors.push([
        '$q',
        'authService',
        'authClient',
        'authServer',
        'stateMachine',
        function($q, authService, authClient, authServer, stateMachine)
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