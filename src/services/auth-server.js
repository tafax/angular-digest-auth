/**
 * Parses and provides server information for the authentication.
 */
dgAuth.provider('authServer', ['dgAuthServiceProvider', function AuthServerProvider(dgAuthServiceProvider)
{
    this.$get = ['authStorage', 'parseChallenge', '$log',
                 function(authStorage, parseChallenge, $log)
    {
        /**
         * Creates the service for the server info.
         *
         * @constructor
         */
        function AuthServer(header, authStorage)
        {
            // Regular expression builders.  An attempt to improve legibility.


            /**
             * The header string.
             *
             * @type {string}
             */
            var _header = header;

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
                
                _configured = false;

                var value = response.headers(_header);
                try
                {
                    parseChallenge(value, this.info);
                }
                catch(e)
                {
                    $log.error(e);
                    return _configured;
                }

                authStorage.setServerAuth(this.info);
                _configured = true;
                return _configured;
            };
        }

        var auth = new AuthServer(dgAuthServiceProvider.getHeader(), authStorage);

        if(authStorage.hasServerAuth())
            auth.setConfig(authStorage.getServerAuth());

        return auth;
    }];
}]);
