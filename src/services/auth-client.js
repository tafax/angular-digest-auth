/**
 * Manages authentication info in the client scope.
 */
dgAuth.factory('authClient', [
    'authServer',
    'md5',
function(authServer, md5)
{
    /**
     * Creates the service to use information generating
     * header for each request.
     *
     * @constructor
     */
    function AuthClient()
    {
        /**
         * Chars to select when creating nonce.
         *
         * @type {string}
         * @private
         */
        var _chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

        /**
         * Current counter.
         *
         * @type {number}
         * @private
         */
        var _nc = 0;

        /**
         * Generates the cnonce with the given length.
         *
         * @param length Length of the cnonce.
         * @returns {string}
         */
        var generateNonce = function(length)
        {
            var nonce = [];
            var charsLength = _chars.length;

            for (var i = 0; i < length; ++i)
            {
                nonce.push(_chars[Math.random() * charsLength | 0]);
            }

            return nonce.join('');
        };

        /**
         * Generate the nc progressively for each request.
         *
         * @returns {string}
         */
        var getNc = function()
        {
            _nc++;

            var zeros = 8 - _nc.toString().length;

            var nc = "";
            for(var i=0; i<zeros; i++)
            {
                nc += "0";
            }

            return (nc + _nc);
        };

        /**
         * Generate the response.
         *
         * @param {string} username The username.
         * @param {string} password The password.
         * @param {string} method Method used for the request.
         * @param {string} uri Uri of the resource requested.
         * @param {string} nc The progressive nc.
         * @param {string} cnonce The cnonce.
         * @returns {string}
         */
        var generateResponse = function(username, password, method, uri, nc, cnonce)
        {
            var ha1 = md5.createHash(username + ":" + authServer.info.realm + ":" + password);
            var ha2 = md5.createHash(method + ":" + uri);
            return md5.createHash(ha1 + ":" + authServer.info.nonce + ":" + nc + ":" + cnonce + ":" + authServer.info.qop + ":" + ha2);
        };

        /**
         * Aggregates all information to generate header.
         *
         * @param {string} username The username.
         * @param {string} password The password.
         * @param {string} method Method used for the request.
         * @param {string} uri Uri of the resource requested.
         * @returns {string}
         */
        var generateHeader = function(username, password, method, uri)
        {
            var nc = getNc();
            var cnonce = generateNonce(16);

            return "Digest " +
                "username=\"" + username + "\", " +
                "realm=\"" + authServer.info.realm + "\", " +
                "nonce=\"" + authServer.info.nonce + "\", " +
                "uri=\"" + uri + "\", " +
                "algorithm=\"" + authServer.info.algorithm + "\", " +
                "response=\"" + generateResponse(username, password, method, uri, nc, cnonce) + "\", " +
                "opaque=\"" + authServer.info.opaque + "\", " +
                "qop=\"" + authServer.info.qop + "\", " +
                "nc=\"" + nc + "\", " +
                "cnonce=\"" + cnonce + "\"";
        };

        /**
         * Returns true if the client is properly configured.
         * It needs server authentication information.
         *
         * @returns {boolean}
         */
        this.isConfigured = function()
        {
            return authServer.isConfigured();
        };

        /**
         * Process a request and add the authorization header
         * if the request need an authentication.
         *
         * @param {string} username The username.
         * @param {string} password The password.
         * @param {string} method The method of the request.
         * @param {string} url The url of the request.
         * @returns {string|null}
         */
        this.processRequest = function(username, password, method, url)
        {
            var header = null;

            if(this.isConfigured())
            {
                if(url.indexOf(authServer.info.domain) >= 0)
                    header = generateHeader(username, password, method, url);
            }

            return header;
        };
    }

    return new AuthClient();
}]);
