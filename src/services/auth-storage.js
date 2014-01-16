/**
 * Stores information to remember user credential
 * and server configuration.
 */
dgAuth.provider('$authStorage', function AuthStorageProvider()
{
    /**
     * Creates the service for the storage.
     * You can choose the type of storage to
     * save user credential.
     * Server info are always stored in the
     * session.
     *
     * @param storage Storage to save user credential.
     * @constructor
     */
    function AuthStorage(storage)
    {
        var $storage = storage;

        this.hasCredential = function()
        {
            var username = $storage.getItem('username');
            var password = $storage.getItem('password');

            return ((null !== username && null !== password));
        };

        this.setCredentials = function(username, password)
        {
            $storage.setItem('username', username);
            $storage.setItem('password', password);
        };

        this.hasServerAuth = function()
        {
            return (null !== sessionStorage.getItem('server'));
        };

        this.setServerAuth = function(server)
        {
            sessionStorage.setItem('server', JSON.stringify(server));
        };

        this.getServerAuth = function()
        {
            return JSON.parse(sessionStorage.getItem('server'));
        };

        this.getUsername = function()
        {
            return $storage.getItem('username');
        };

        this.getPassword = function()
        {
            return $storage.getItem('password');
        };

        this.clear = function()
        {
            $storage.clear();
            sessionStorage.clear();
        };
    }

    // Default storage for user credential.
    var $storage = sessionStorage;

    /**
     * Sets storage for user credential.
     *
     * @param storage
     */
    this.setStorage = function(storage)
    {
        $storage = storage;
    };

    this.$get = function()
    {
        return new AuthStorage($storage);
    };
});
