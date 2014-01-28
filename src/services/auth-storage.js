/**
 * Stores information to remember user credentials
 * and server information.
 */
dgAuth.provider('authStorage', ['dgAuthServiceProvider', function AuthStorageProvider(dgAuthServiceProvider)
{
    /**
     * Creates the service for the storage.
     * You can choose the type of storage to
     * save user credential.
     * Server info are always stored in the
     * session.
     *
     * @param {Storage} storage Storage to save user credentials.
     * @constructor
     */
    function AuthStorage(storage)
    {
        /**
         * The storage for credentials.
         *
         * @type {Storage}
         * @private
         */
        var _storage = storage;

        /**
         * The session storage.
         *
         * @type {Storage}
         * @private
         */
        var _sessionStorage = window.sessionStorage;

        /**
         * Checks if the storage has some credentials.
         *
         * @returns {boolean}
         */
        this.hasCredentials = function()
        {
            var username = _storage.getItem('username');
            var password = _storage.getItem('password');

            return ((null !== username && null !== password) && (undefined !== username && undefined !== password));
        };

        /**
         * Sets the credentials.
         *
         * @param {String} username
         * @param {String} password
         */
        this.setCredentials = function(username, password)
        {
            _storage.setItem('username', username);
            _storage.setItem('password', password);
        };

        /**
         * Removes the credentials in the storage.
         */
        this.clearCredentials = function()
        {
            _storage.removeItem('username');
            _storage.removeItem('password');
        };

        /**
         * Checks if storage contains the server information.
         *
         * @returns {boolean}
         */
        this.hasServerAuth = function()
        {
            var value = _sessionStorage.getItem('server');
            return (null !== value && undefined !== value);
        };

        /**
         * Sets the server information.
         *
         * @param {Object} server
         */
        this.setServerAuth = function(server)
        {
            _sessionStorage.setItem('server', angular.toJson(server));
        };

        /**
         * Gets the server information.
         *
         * @returns {Object}
         */
        this.getServerAuth = function()
        {
            return angular.fromJson(_sessionStorage.getItem('server'));
        };

        /**
         * Gets the username saved in the storage.
         *
         * @returns {String}
         */
        this.getUsername = function()
        {
            return _storage.getItem('username');
        };

        /**
         * Gets the password saved in the storage.
         *
         * @returns {String}
         */
        this.getPassword = function()
        {
            return _storage.getItem('password');
        };

        /**
         * Clears the storage.
         */
        this.clear = function()
        {
            _storage.clear();
            _sessionStorage.clear();
        };
    }

    /**
     * Gets a new instance of AuthStorage.
     *
     * @returns {AuthStorageProvider.AuthStorage}
     */
    this.$get = function()
    {
        return new AuthStorage(dgAuthServiceProvider.getStorage());
    };
}]);
