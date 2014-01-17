/**
 * Stores information to remember user credentials
 * and server information.
 */
dgAuth.provider('authStorage', function AuthStorageProvider()
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
         * Checks if the storage has some credentials.
         *
         * @returns {boolean}
         */
        this.hasCredential = function()
        {
            var username = _storage.getItem('username');
            var password = _storage.getItem('password');

            return ((null !== username && null !== password));
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
         * Checks if storage contains the server information.
         *
         * @returns {boolean}
         */
        this.hasServerAuth = function()
        {
            return (null !== sessionStorage.getItem('server'));
        };

        /**
         * Sets the server information.
         *
         * @param {Object} server
         */
        this.setServerAuth = function(server)
        {
            sessionStorage.setItem('server', JSON.stringify(server));
        };

        /**
         * Gets the server information.
         *
         * @returns {Object}
         */
        this.getServerAuth = function()
        {
            return JSON.parse(sessionStorage.getItem('server'));
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
            sessionStorage.clear();
        };
    }

    /**
     * Default storage for user credential.
     *
     * @type {Storage}
     * @private
     */
    var _storage = sessionStorage;

    /**
     * Sets storage for user credential.
     *
     * @param storage
     */
    this.setStorage = function(storage)
    {
        _storage = storage;
    };

    /**
     * Gets a new instance of AuthStorage.
     *
     * @returns {AuthStorageProvider.AuthStorage}
     */
    this.$get = function()
    {
        return new AuthStorage(_storage);
    };
});
