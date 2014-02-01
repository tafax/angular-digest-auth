dgAuth.factory('authIdentity', function()
{
    function AuthIdentity()
    {
        /**
         * The current identity of user.
         *
         * @type {Object|null}
         * @private
         */
        var _identity = null;

        /**
         * Specifies if the identity is suspended.
         *
         * @type {boolean}
         * @private
         */
        var _suspended = false;

        /**
         * Sets the entire identity fields or
         * if key is specified, one of these.
         *
         * @param {string} [key]
         * @param {Object|string|Array} value
         */
        this.set = function(key, value)
        {
            if(_suspended)
                return;

            if(key)
            {
                if(null == _identity)
                    _identity = {};

                _identity[key] = value;
            }
            else
            {
                if(value instanceof Object)
                    _identity = value;
                else
                    throw 'You have to provide an object if you want to set the identity without a key.';
            }
        };

        /**
         * Gets the entire identity of
         * if key is specified, one single field.
         *
         * @param {string} [key]
         * @returns {Object|Array|string|null}
         */
        this.get = function(key)
        {
            if(_suspended)
                return null;

            if(!key)
                return _identity;

            if(!_identity || !_identity.hasOwnProperty(key))
                return null;

            return _identity[key];
        };

        /**
         * Returns true if the identity
         * is properly set.
         *
         * @returns {boolean}
         */
        this.has = function()
        {
            if(_suspended)
                return false;

            return (null !== _identity);
        };

        /**
         * Clears the identity.
         */
        this.clear = function()
        {
            _identity = null;
        };

        /**
         * Suspends the identity.
         */
        this.suspend = function()
        {
            _suspended = true;
        };

        /**
         * Restores identity that is
         * previously suspended.
         */
        this.restore = function()
        {
            _suspended = false;
        };

        /**
         * Checks if the identity is suspended.
         *
         * @returns {boolean}
         */
        this.isSuspended = function()
        {
            return _suspended;
        };
    }

    return new AuthIdentity();
});