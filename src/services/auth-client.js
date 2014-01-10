/**
 * Manages authentication info in the client scope.
 */
dhAuth.factory('$clientAuth', [
    '$rootScope',
    '$serverAuth',
    'md5',
function($rootScope, $serverAuth, md5)
{
    /**
     * Creates the service to use information generating
     * header for each request.
     *
     * @constructor
     */
    function ClientAuth()
    {
        var $chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
        var $nc = 0;

        /**
         * Generates the cnonce with the given length.
         *
         * @param length Length of the cnonce.
         * @returns {string}
         */
        var generateNonce = function(length)
        {
            var nonce = [];
            var charsLength = $chars.length;

            for (var i = 0; i < length; ++i)
            {
                nonce.push($chars[Math.random() * charsLength | 0]);
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
            $nc++;

            var zeros = 8 - $nc.toString().length;

            var nc = "";
            for(var i=0; i<zeros; i++)
            {
                nc += "0";
            }

            return (nc + $nc);
        };

        /**
         * Generate the response.
         *
         * @param username
         * @param password
         * @param method Method used for the request.
         * @param uri Uri of the resource requested.
         * @param nc The progressive nc.
         * @param cnonce The cnonce.
         * @returns {string}
         */
        var generateResponse = function(username, password, method, uri, nc, cnonce)
        {
            var ha1 = md5.createHash(username + ":" + $serverAuth.realm + ":" + password);
            var ha2 = md5.createHash(method + ":" + uri);
            return md5.createHash(ha1 + ":" + $serverAuth.nonce + ":" + nc + ":" + cnonce + ":" + $serverAuth.qop + ":" + ha2);
        };

        /**
         * Aggregates all information to generate header.
         *
         * @param username
         * @param password
         * @param method Method used for the request.
         * @param uri Uri of the resource requested.
         * @returns {string}
         */
        var generateHeader = function(username, password, method, uri)
        {
            var nc = getNc();
            var cnonce = generateNonce(16);

            return "Digest " +
                "username=\"" + username + "\", " +
                "realm=\"" + $serverAuth.realm + "\", " +
                "nonce=\"" + $serverAuth.nonce + "\", " +
                "uri=\"" + uri + "\", " +
                "algorithm=" + $serverAuth.algorithm + ", " +
                "response=\"" + generateResponse(username, password, method, uri, nc, cnonce) + "\", " +
                "opaque=\"" + $serverAuth.opaque + "\", " +
                "qop=" + $serverAuth.qop + ", " +
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
            return $serverAuth.hasHeader();
        };

        /**
         * Process a request and add the authorization header
         * if the request need an authentication.
         *
         * @param username
         * @param password
         * @param request
         */
        this.processRequest = function(username, password, request)
        {
            if(request.url.indexOf($serverAuth.domain) >= 0)
                request.headers['Authorization'] = generateHeader(username, password, request.method, request.url);
        };
    }

    return new ClientAuth();
}]);
