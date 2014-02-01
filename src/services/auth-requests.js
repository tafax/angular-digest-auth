dgAuth.provider('authRequests', ['dgAuthServiceProvider', function AuthRequestsProvider(dgAuthServiceProvider)
{
    function AuthRequest(limit, config, $http, authService, stateMachine)
    {
        /**
         *
         *
         * @type {promise|null}
         * @private
         */
        var _promise = null;

        /**
         *
         *
         * @returns {promise|null}
         */
        this.getPromise = function()
        {
            return _promise;
        };

        /**
         *
         * @type {number}
         * @private
         */
        var _times = 0;

        /**
         *
         * @returns {boolean}
         */
        this.getValid = function()
        {
            if('inf' == limit)
                return true;

            return (_times <= limit);
        };

        var request = function()
        {
            var promise = null;

            if(authService.hasRequest())
            {
                var request = authService.getRequest();
                promise = $http(request.config).then(function(response)
                    {
                        request.deferred.resolve(response);

                        if(_times > 0)
                            _times = 0;

                        if(stateMachine.isAvailable('201'))
                            stateMachine.send('201', {response: response});

                        return response;
                    },
                    function(response)
                    {
                        request.deferred.reject(response);

                        if(_times > 0)
                            _times = 0;

                        if(stateMachine.isAvailable('failure'))
                            stateMachine.send('failure', {response: response});

                        return response;
                    });
            }

            return promise;
        };

        /**
         *
         * @returns {promise}
         */
        this.signin = function()
        {
            _times++;

            _promise = request();
            if(_promise)
                return _promise;

            _promise = $http(config.login).then(function(response)
                {
                    _times = 0;
                    stateMachine.send('201', {response: response});

                    return response;
                },
                function(response)
                {
                    _times = 0;
                    stateMachine.send('failure', {response: response});

                    return response;
                });

            return _promise;
        };

        /**
         *
         * @returns {promise}
         */
        this.signout = function()
        {
            _promise = request();
            if(_promise)
                return _promise;

            _promise = $http(config.logout).then(function(response)
                {
                    stateMachine.send('201', {response: response});

                    return response;
                },
                function(response)
                {
                    return response;
                });
            return _promise;
        };
    }

    this.$get = ['$http', 'authService', 'stateMachine', function($http, authService, stateMachine)
    {
        return new AuthRequest(dgAuthServiceProvider.getLimit(), dgAuthServiceProvider.getConfig(), $http, authService, stateMachine);
    }];
}]);