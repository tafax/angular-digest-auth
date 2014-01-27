/**
 * Used to manage the authentication.
 */
dgAuth.provider('authService', ['dgAuthServiceProvider', function AuthServiceProvider(dgAuthServiceProvider)
{
    /**
     * Creates the authentication service to performs
     * sign in and sign out, manages the current identity
     * and check the authentication.
     *
     * @constructor
     */
    function AuthService(callbacks, $injector)
    {
        /**
         *
         * @type {string}
         * @private
         */
        var _username = '';

        /**
         *
         * @type {string}
         * @private
         */
        var _password = '';

        /**
         *
         * @param {string} username
         * @param {string} password
         */
        this.setCredentials = function(username, password)
        {
            _username = username.trim();
            _password = password.trim();
        };

        /**
         *
         * @returns {{username: string, password: string}}
         */
        this.getCredentials = function()
        {
            return {
                username: _username,
                password: _password
            };
        };

        this.hasCredentials = function()
        {
            return (('' !== _username.trim()) && ('' !== _password.trim()));
        };

        /**
         *
         */
        this.clearCredentials = function()
        {
            _username = '';
            _password = '';
        };

        /**
         *
         * @type {Object}
         * @private
         */
        var _request = null;

        /**
         *
         * @param {Object} config
         * @param {Object} deferred
         */
        this.setRequest = function(config, deferred)
        {
            _request = {
                config: config,
                deferred: deferred
            };
        };

        /**
         *
         * @returns {Object}
         */
        this.getRequest = function()
        {
            return _request;
        };

        /**
         *
         * @returns {boolean}
         */
        this.hasRequest = function()
        {
            return (null !== _request);
        };

        /**
         *
         */
        this.clearRequest = function()
        {
            _request = null;
        };

        /**
         *
         * @param {string} callback
         * @returns {Array}
         */
        this.getCallbacks = function(callback)
        {
            var split = callback.split('.');
            if(split.length > 2 || split.length == 0)
                throw 'The type for the callbacks is invalid.';

            var family = split[0];
            var type = (split.length == 2) ? split[1] : null;

            var result = [];

            if(callbacks.hasOwnProperty(family))
            {
                var typedCallbacks = callbacks[family];
                for(var i in typedCallbacks)
                {
                    var func = $injector.invoke(typedCallbacks[i]);

                    if(type)
                    {
                        if(func.hasOwnProperty(type))
                            result.push(func[type]);
                    }
                    else
                        result.push(func);
                }
            }

            return result;
        };
    }

    /**
     * Gets a new instance of AuthService.
     *
     * @type {Array}
     */
    this.$get = [
        '$injector',
    /**
     * Gets a new instance of AuthService.
     *
     * @param {Object} $injector
     * @returns {AuthService}
     */
    function($injector)
    {
        return new AuthService(dgAuthServiceProvider.callbacks, $injector);
    }];

}]);