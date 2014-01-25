dgAuth.provider('authRequests', function AuthRequestsProvider()
{
    function AuthRequest(config, $http, authService, stateMachine)
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

        var request = function()
        {
            var promise = null;

            if(authService.hasRequest())
            {
                var request = authService.getRequest();
                promise = $http(request.config).then(function(response)
                    {
                        request.deferred.resolve(response);

                        return response;
                    },
                    function(response)
                    {
                        request.deferred.reject(response);

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
            _promise = request();
            if(_promise)
                return _promise;

            _promise = $http(config.login).then(function(response)
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

    /**
     * The configuration for the login and logout.
     *
     * @type {Object}
     * @private
     */
    var _config = {
        login: {
            method: 'POST',
            url: '/signin'
        },
        logout: {
            method: 'POST',
            url: '/signout'
        }
    };

    /**
     * Sets the configuration for the requests.
     *
     * @param {Object} config
     */
    this.setConfig = function(config)
    {
        angular.extend(_config, config);
    };

    this.$get = ['$http', 'authService', 'stateMachine', function($http, authService, stateMachine)
    {
        return new AuthRequest(_config, $http, authService, stateMachine);
    }];
});