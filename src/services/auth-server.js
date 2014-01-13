/**
 * Parses and provides server information for the authentication.
 */
dgAuth.factory('$serverAuth', ['$authStorage', function($authStorage)
{
    /**
     * Creates the service for the server info.
     *
     * @constructor
     */
    function ServerAuth()
    {
        var $valuePattern = /([a-zA-Z]+)=\"?([a-zA-Z0-9\/\s]+)\"?/;
        var $header = false;

        this.realm = "";
        this.domain = "";
        this.nonce = "";
        this.opaque = "";
        this.algorithm = "";
        this.qop = "";

        this.hasHeader = function()
        {
            return $header;
        };

        this.config = function(server)
        {
            this.realm = server.realm;
            this.domain = server.domain;
            this.nonce = server.nonce;
            this.opaque = server.opaque;
            this.algorithm = server.algorithm;
            this.qop = server.qop;
            $header = true;
        };

        this.parseHeader = function(headerLine)
        {
            var splitting = headerLine.split(', ');

            for(var i=0; i<splitting.length; i++)
            {
                var values = $valuePattern.exec(splitting[i]);
                this[values[1]] = values[2];
            }

            $header = true;
            $authStorage.setServerAuth(this);
        };
    }

    /**
     * Creates server info taking
     * the information from storage
     * if they are previously saved.
     *
     * @returns {ServerAuth}
     */
    var getServerAuth = function()
    {
        var auth = new ServerAuth();

        if($authStorage.hasServerAuth())
            auth.config($authStorage.getServerAuth());

        return auth;
    };

    return getServerAuth();
}]);
