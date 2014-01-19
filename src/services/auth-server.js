/**
 * Parses and provides server information for the authentication.
 */
dgAuth.provider('authServer', function AuthServerProvider()
{
    /**
     * Creates the service for the server info.
     *
     * @constructor
     */
    function AuthServer(header, authStorage, authEvents, $rootScope)
    {
        /**
         * The header string.
         *
         * @type {string}
         */
        var _header = header;

        /**
         * The regular expression to evaluate server information.
         *
         * @type {RegExp}
         * @private
         */
        var _valuePattern = /([a-zA-Z]+)=\"?([a-zA-Z0-9\/\s]+)\"?/;

        /**
         * True if the header was correctly parsed.
         *
         * @type {boolean}
         * @private
         */
        var _configured = false;

        /**
         * The configuration of server information.
         *
         * @type {{realm: string, domain: string, nonce: string, opaque: string, algorithm: string, qop: string}}
         */
        this.info = {
            realm: '',
            domain: '',
            nonce: '',
            opaque: '',
            algorithm: '',
            qop: ''
        };

        /**
         * Checks if the header was correctly parsed.
         *
         * @returns {boolean}
         */
        this.isConfigured = function()
        {
            return _configured;
        };

        /**
         * Sets the configuration manually.
         *
         * @param {Object} server The server information.
         */
        this.setConfig = function(server)
        {
            angular.extend(this.info, server);

            _configured = true;
        };

        /**
         * Parses header to set the information.
         *
         * @param {Object} response The response to login request.
         */
        this.parseHeader = function(response)
        {
            if(!_configured)
            {
                var header = response.headers(_header);

                if(null !== header)
                {
                    var splitting = header.split(', ');

                    for(var i=0; i<splitting.length; i++)
                    {
                        var values = _valuePattern.exec(splitting[i]);
                        this.info[values[1]] = values[2];
                    }

                    authStorage.setServerAuth(this.info);
                    _configured = true;

                    console.debug('Parse header for authentication.');
                    $rootScope.$broadcast(authEvents.getEvent('authentication.header'));
                }
            }

            return _configured;
        };
    }

    /**
     * The header string.
     *
     * @type {string}
     */
    var _header = '';

    /**
     * Sets the header.
     *
     * @param {String} header
     */
    this.setHeader = function(header)
    {
        _header = header;
    };

    this.$get = ['authStorage', 'authEvents', '$rootScope', function(authStorage, authEvents, $rootScope)
    {
        var auth = new AuthServer(_header, authStorage, authEvents, $rootScope);

        if(authStorage.hasServerAuth())
            auth.setConfig(authStorage.getServerAuth());

        return auth;
    }];
});
