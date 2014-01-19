describe('angular-digest-auth', function()
{
    var _regex = /Digest username\=\"([a-z]*)\"/;
    var _authStorage;
    var _authEvents;
    var _authService;
    var _httpBackend;
    var _rootScope;
    var _config;

    var _identity = {
        id: 1
    };

    var _loginError = {
        message: 'Login error.'
    };

    var _logoutError = {
        message: 'Logout error.'
    };

    beforeEach(angular.mock.module('dgAuth'));

    beforeEach(function()
    {
        var fakeModule = angular.module('test.config', []);
        fakeModule.config([
            'authEventsProvider',
            'authServiceProvider',
            'authServerProvider',
        function(authEventsProvider, authServiceProvider, authServerProvider)
        {
            authServiceProvider.setConfig({
                login: {
                    method: 'POST',
                    url: '/signin'
                },
                logout: {
                    method: 'POST',
                    url: '/signout'
                }
            });

            authServiceProvider.callbacks.login.push(['authService', function(authService)
            {
                return {
                    successful: function(data)
                    {
                        expect(data).toEqual(_identity);
                        expect(authService.getIdentity()).toEqual(_identity);
                        expect(authService.hasIdentity()).toEqual(true);
                    },
                    error: function(error)
                    {
                        expect(error).toEqual(_loginError);
                        expect(authService.getIdentity()).toEqual(null);
                        expect(authService.hasIdentity()).toEqual(false);
                    },
                    required: function()
                    {
                        expect(authService.getIdentity()).toEqual(null);
                        expect(authService.hasIdentity()).toEqual(false);
                    }
                };
            }]);

            authServiceProvider.callbacks.logout.push(['authService', function(authService)
            {
                return {
                    successful: function(data)
                    {
                        expect(data).toEqual('');
                        expect(authService.getIdentity()).toEqual(null);
                        expect(authService.hasIdentity()).toEqual(false);
                    },
                    error: function(error)
                    {
                        expect(error).toEqual(_logoutError);
                        expect(authService.getIdentity()).toEqual(_identity);
                        expect(authService.hasIdentity()).toEqual(true);
                    }
                };
            }]);

            authServerProvider.setHeader('X-Auth-Digest');
        }]);

        module('dgAuth', 'test.config');

        inject(function($injector)
        {
            _rootScope = $injector.get('$rootScope');
            spyOn(_rootScope, '$broadcast').andCallThrough();

            _authEvents = $injector.get('authEvents');
            _authService = $injector.get('authService');

            _authStorage = $injector.get('authStorage');
            _authStorage.clear();

            _config = _authService.getConfig();

            _httpBackend = $injector.get('$httpBackend');
            _httpBackend.whenPOST(_config.login.url).respond(function(method, url, data, headers)
            {
                var authorization = headers.Authorization;
                if(authorization)
                {
                    var regex = new RegExp(_regex);
                    var username = regex.exec(authorization);

                    if(username[1] == 'test')
                    {
                        return [201, JSON.stringify(_identity), ''];
                    }
                }

                var responseHeaders = {
                    'X-Auth-Digest': 'Digest ' +
                        'realm="Test AngularJS module", ' +
                        'domain="/", ' +
                        'nonce="32fffd4e446fc7735c4995154674e9d4", ' +
                        'opaque="e66aa41ca5bf6992a5479102cc787bc9", ' +
                        'algorithm="MD5", ' +
                        'qop="auth"'
                };

                return [401, JSON.stringify(_loginError), responseHeaders];
            });

            _httpBackend.whenPOST(_config.logout.url).respond(function(method, url, data, headers)
            {
                var authorization = headers.Authorization;
                if(authorization)
                {
                    var regex = new RegExp(_regex);
                    var username = regex.exec(authorization);

                    if(username[1] == 'test')
                    {
                        return [201, '', ''];
                    }
                }

                return [400, JSON.stringify(_logoutError), headers];
            });
        });
    });

    afterEach(function()
    {
        _httpBackend.verifyNoOutstandingExpectation();
        _httpBackend.verifyNoOutstandingRequest();
    });

    describe('ALL', function()
    {
        it('performs the login - error', function()
        {
            _authService.signin();

            _httpBackend.expectPOST(_config.login.url);
            _httpBackend.flush();

            expect(_rootScope.$broadcast).toHaveBeenCalledWith(_authEvents.getEvent('process.request'), jasmine.any(Object));
            expect(_rootScope.$broadcast).toHaveBeenCalledWith(_authEvents.getEvent('process.response'), jasmine.any(Object));
            expect(_rootScope.$broadcast).toHaveBeenCalledWith(_authEvents.getEvent('authentication.header'));
            expect(_rootScope.$broadcast).toHaveBeenCalledWith(_authEvents.getEvent('authentication.request'));
            expect(_rootScope.$broadcast).toHaveBeenCalledWith(_authEvents.getEvent('login.required'));

            var login = {
                username: 'fake',
                password: 'fake'
            };

            _authService.setCredentials(login.username, login.password);
            _authService.signin();

            _authService.isAuthenticated().then(null, function()
            {
                expect(_authService.hasIdentity()).toEqual(false);
            });

            _httpBackend.expectPOST(_config.login.url);
            _httpBackend.flush();

            expect(_rootScope.$broadcast).toHaveBeenCalledWith(_authEvents.getEvent('credential.submitted'), login);
            expect(_rootScope.$broadcast).toHaveBeenCalledWith(_authEvents.getEvent('login.error'), jasmine.any(Object));
        });

        it('multiple login error', function()
        {
            _authService.signin();

            _httpBackend.expectPOST(_config.login.url);
            _httpBackend.flush();

            _authService.setCredentials('fake', 'fake');
            _authService.signin();

            _authService.isAuthenticated().then(null, function()
            {
                expect(_authService.hasIdentity()).toEqual(false);
            });

            _httpBackend.expectPOST(_config.login.url);
            _httpBackend.flush();

            expect(_rootScope.$broadcast).toHaveBeenCalledWith(_authEvents.getEvent('login.error'), jasmine.any(Object));

            _authService.setCredentials('fake', 'fake');
            _authService.signin();

            _authService.isAuthenticated().then(null, function()
            {
                expect(_authService.hasIdentity()).toEqual(false);
            });

            _httpBackend.expectPOST(_config.login.url);
            _httpBackend.flush();

            expect(_rootScope.$broadcast).toHaveBeenCalledWith(_authEvents.getEvent('login.error'), jasmine.any(Object));

            _authService.setCredentials('test', 'test');
            _authService.signin();

            _authService.isAuthenticated().then(function()
            {
                expect(_authService.hasIdentity()).toEqual(true);
            });

            _httpBackend.expectPOST(_config.login.url);
            _httpBackend.flush();

            _authService.isAuthenticated().then(function()
            {
                expect(_authService.hasIdentity()).toEqual(true);
            });

            expect(_rootScope.$broadcast).toHaveBeenCalledWith(_authEvents.getEvent('login.successful'), jasmine.any(Object));
        });

        it('performs the login - successful', function()
        {
            _authService.signin();

            _httpBackend.expectPOST(_config.login.url);
            _httpBackend.flush();

            expect(_rootScope.$broadcast).toHaveBeenCalledWith(_authEvents.getEvent('process.request'), jasmine.any(Object));
            expect(_rootScope.$broadcast).toHaveBeenCalledWith(_authEvents.getEvent('process.response'), jasmine.any(Object));
            expect(_rootScope.$broadcast).toHaveBeenCalledWith(_authEvents.getEvent('authentication.header'));
            expect(_rootScope.$broadcast).toHaveBeenCalledWith(_authEvents.getEvent('authentication.request'));
            expect(_rootScope.$broadcast).toHaveBeenCalledWith(_authEvents.getEvent('login.required'));

            var login = {
                username: 'test',
                password: 'test'
            };

            _authService.setCredentials(login.username, login.password);
            _authService.signin();

            _authService.isAuthenticated().then(function()
            {
                expect(_authService.hasIdentity()).toEqual(true);
            });

            _httpBackend.expectPOST(_config.login.url);
            _httpBackend.flush();

            expect(_rootScope.$broadcast).toHaveBeenCalledWith(_authEvents.getEvent('credential.submitted'), login);
            expect(_rootScope.$broadcast).toHaveBeenCalledWith(_authEvents.getEvent('credential.stored'), {
                username: login.username,
                password: login.password
            });
            expect(_rootScope.$broadcast).toHaveBeenCalledWith(_authEvents.getEvent('login.successful'), jasmine.any(Object));
        });

        it('performs the logout - error', function()
        {
            _authService.signin();

            _httpBackend.expectPOST(_config.login.url);
            _httpBackend.flush();

            var login = {
                username: 'test',
                password: 'test'
            };

            _authService.setCredentials(login.username, login.password);
            _authService.signin();

            _authService.isAuthenticated().then(function()
            {
                expect(_authService.hasIdentity()).toEqual(true);
            });

            _httpBackend.expectPOST(_config.login.url);
            _httpBackend.flush();

            _authService.setCredentials('fake', 'fake');
            _authService.signout();

            _authService.isAuthenticated().then(function()
            {
                expect(_authService.hasIdentity()).toEqual(true);
            });

            _httpBackend.expectPOST(_config.logout.url);
            _httpBackend.flush();

            expect(_rootScope.$broadcast).toHaveBeenCalledWith(_authEvents.getEvent('logout.error'), jasmine.any(Object));
        });

        it('performs the logout - successful', function()
        {
            _authService.signin();

            _httpBackend.expectPOST(_config.login.url);
            _httpBackend.flush();

            var login = {
                username: 'test',
                password: 'test'
            };

            _authService.setCredentials(login.username, login.password);
            _authService.signin();

            _httpBackend.expectPOST(_config.login.url);
            _httpBackend.flush();

            _authService.signout();

            _authService.isAuthenticated().then(null, function()
            {
                expect(_authService.hasIdentity()).toEqual(false);
            });

            _httpBackend.expectPOST(_config.logout.url);
            _httpBackend.flush();

            expect(_rootScope.$broadcast).toHaveBeenCalledWith(_authEvents.getEvent('logout.successful'), jasmine.any(Object));
        });
    });
});