'use strict';

describe('Authentication Service Specification', function()
{
    var _authService;

    var _log;

    beforeEach(angular.mock.module('dgAuth'));

    beforeEach(function()
    {
        var fake = angular.module('test.config', []);
        fake.config(['dgAuthServiceProvider', function(dgAuthServiceProvider)
        {
            dgAuthServiceProvider.callbacks.login.push(['$log', function($log)
            {
                return {
                    successful: function()
                    {
                        return $log;
                    },
                    error: function()
                    {
                        return $log;
                    },
                    request: function()
                    {
                        return $log;
                    }
                };
            }]);

            dgAuthServiceProvider.callbacks.login.push(['$log', function($log)
            {
                return {
                    successful: function()
                    {
                        return $log;
                    },
                    error: function()
                    {
                        return $log;
                    },
                    request: function()
                    {
                        return $log;
                    }
                };
            }]);

            dgAuthServiceProvider.callbacks.logout.push(['$log', function($log)
            {
                return {
                    successful: function()
                    {
                        return $log;
                    },
                    error: function()
                    {
                        return $log;
                    }
                };
            }]);

            dgAuthServiceProvider.callbacks.logout.push(['$log', function($log)
            {
                return {
                    successful: function()
                    {
                        return $log;
                    },
                    error: function()
                    {
                        return $log;
                    }
                };
            }]);
        }]);

        module('test.config', 'dgAuth');

        inject(function($injector)
        {
            _authService = $injector.get('authService');

            _log = $injector.get('$log');
        });
    });

    describe('tests the request methods', function()
    {
        it('should return null', function()
        {
            expect(_authService.hasRequest()).toBeFalsy();
            expect(_authService.getRequest()).toBeNull();
        });

        it('should return the request', function()
        {
            var config = {
                method: 'GET',
                url: '/path'
            };

            var deferred = Object();

            _authService.setRequest(config, deferred);
            expect(_authService.hasRequest()).toBeTruthy();
            expect(_authService.getRequest()).toEqual({
                config: config,
                deferred: deferred
            });
        });

        it('should clear the request', function()
        {
            var config = {
                method: 'GET',
                url: '/path'
            };

            var deferred = Object();

            _authService.setRequest(config, deferred);
            _authService.clearRequest();

            expect(_authService.hasRequest()).toBeFalsy();
            expect(_authService.getRequest()).toBeNull();
        });
    });

    describe('tests the credentials', function()
    {
        it('should return empty values', function()
        {
            expect(_authService.hasCredentials()).toBeFalsy();
            expect(_authService.getCredentials()).toEqual({
                username: '',
                password: ''
            });
        });

        it('should return the credentials', function()
        {
            _authService.setCredentials('username', 'password');

            expect(_authService.hasCredentials()).toBeTruthy();
            expect(_authService.getCredentials()).toEqual({
                username: 'username',
                password: 'password'
            });
        });

        it('should return empty values even if they are set', function()
        {
            _authService.setCredentials(' ', ' ');

            expect(_authService.hasCredentials()).toBeFalsy();
            expect(_authService.getCredentials()).toEqual({
                username: '',
                password: ''
            });
        });

        it('should clear the credentials', function()
        {
            _authService.setCredentials('username', 'password');

            expect(_authService.hasCredentials()).toBeTruthy();
            expect(_authService.getCredentials()).toEqual({
                username: 'username',
                password: 'password'
            });

            _authService.clearCredentials();

            expect(_authService.hasCredentials()).toBeFalsy();
            expect(_authService.getCredentials()).toEqual({
                username: '',
                password: ''
            });
        });
    });

    describe('tests the login callbacks', function()
    {
        it('should return the login callbacks', function()
        {
            var callbacks = _authService.getCallbacks('login');

            expect(callbacks.length).toEqual(2);

            for(var i in callbacks)
            {
                var callback = callbacks[i];
                expect(callback.successful()).toEqual(_log);
                expect(callback.error()).toEqual(_log);
                expect(callback.request()).toEqual(_log);
            }
        });

        it('should return the login successful callbacks', function()
        {
            var successful = _authService.getCallbacks('login.successful');

            expect(successful.length).toEqual(2);

            for(var j in successful)
            {
                var func = successful[j];
                expect(func()).toEqual(_log);
            }
        });

        it('should return the login error callbacks', function()
        {
            var error = _authService.getCallbacks('login.error');

            expect(error.length).toEqual(2);

            for(var j in error)
            {
                var func = error[j];
                expect(func()).toEqual(_log);
            }
        });

        it('should return the login request callbacks', function()
        {
            var request = _authService.getCallbacks('login.request');

            expect(request.length).toEqual(2);

            for(var j in request)
            {
                var func = request[j];
                expect(func()).toEqual(_log);
            }
        });
    });

    describe('tests the logout callbacks', function()
    {
        it('should return the logout callbacks', function()
        {
            var callbacks = _authService.getCallbacks('logout');

            expect(callbacks.length).toEqual(2);

            for(var i in callbacks)
            {
                var callback = callbacks[i];
                expect(callback.successful()).toEqual(_log);
                expect(callback.error()).toEqual(_log);
            }
        });

        it('should return the logout successful callbacks', function()
        {
            var successful = _authService.getCallbacks('logout.successful');

            expect(successful.length).toEqual(2);

            for(var j in successful)
            {
                var func = successful[j];
                expect(func()).toEqual(_log);
            }
        });

        it('should return the logout error callbacks', function()
        {
            var error = _authService.getCallbacks('logout.error');

            expect(error.length).toEqual(2);

            for(var j in error)
            {
                var func = error[j];
                expect(func()).toEqual(_log);
            }
        });
    });
});