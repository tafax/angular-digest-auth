/**
 * Manages authentication info in the client scope.
 */
dgAuth.factory('authClient', [
    '$rootScope',
    'authServer',
    'md5',
function($rootScope, authServer, md5)
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
         * @param {String} username The username.
         * @param {String} password The password.
         * @param {String} method Method used for the request.
         * @param {String} uri Uri of the resource requested.
         * @param {String} nc The progressive nc.
         * @param {String} cnonce The cnonce.
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
         * @param {String} username The username.
         * @param {String} password The password.
         * @param {String} method Method used for the request.
         * @param {String} uri Uri of the resource requested.
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
                "algorithm=" + authServer.algorithm + ", " +
                "response=\"" + generateResponse(username, password, method, uri, nc, cnonce) + "\", " +
                "opaque=\"" + authServer.info.opaque + "\", " +
                "qop=" + authServer.info.qop + ", " +
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
         * @param {String} username The username.
         * @param {String} password The password.
         * @param {Object} request The current request.
         */
        this.processRequest = function(username, password, request)
        {
            if(request.url.indexOf(authServer.info.domain) >= 0)
                request.headers['Authorization'] = generateHeader(username, password, request.method, request.url);
        };
    }

    return new AuthClient();
}]);
