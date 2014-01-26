dgAuth.provider('authRequests', function AuthRequestsProvider()
{
    function AuthRequest(max, config, $http, authService, stateMachine)
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
            if('inf' == max)
                return true;

            return (_times <= max);
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

    /**
     *
     * @type {number|string}
     * @private
     */
    var _maxRequests = 4;

    /**
     *
     * @param {number|string} max
     */
    this.setMaxRequests = function(max)
    {
        _maxRequests = max;
    };

    this.$get = ['$http', 'authService', 'stateMachine', function($http, authService, stateMachine)
    {
        return new AuthRequest(_maxRequests, _config, $http, authService, stateMachine);
    }];
});