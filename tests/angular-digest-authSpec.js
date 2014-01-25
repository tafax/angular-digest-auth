describe('angular-digest-auth', function()
{
    var _stateMachine;

    var _authIdentity;
    var _authRequests;
    var _authService;
    var _authStorage;
    var _authServer;
    var _md5;

    var _http;
    var _httpBackend;

    var _regex = /Digest username\=\"([a-z]*)\"/;

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
            'authRequestsProvider',
            'authServiceProvider',
            'authServerProvider',
        function(authRequestsProvider, authServiceProvider, authServerProvider)
        {
            authRequestsProvider.setConfig({
                login: {
                    method: 'POST',
                    url: '/signin'
                },
                logout: {
                    method: 'POST',
                    url: '/signout'
                }
            });

            authServiceProvider.callbacks.login.push(['authIdentity', function(authIdentity)
            {
                return {
                    successful: function(response)
                    {
                        expect(response.data).toEqual(_identity);
                        expect(authIdentity.has()).toEqual(true);
                        expect(authIdentity.get()).toEqual(_identity);
                    },
                    error: function(response)
                    {
                        expect(response.data).toEqual(_loginError);
                        expect(authIdentity.has()).toEqual(false);
                        expect(authIdentity.get()).toEqual(null);
                    },
                    required: function()
                    {
                        expect(authIdentity.has()).toEqual(false);
                        expect(authIdentity.get()).toEqual(null);
                    }
                };
            }]);

            authServiceProvider.callbacks.logout.push(['authIdentity', function(authIdentity)
            {
                return {
                    successful: function(data)
                    {
                        expect(data).toEqual('');
                        expect(authIdentity.hasIdentity()).toEqual(false);
                        expect(authIdentity.getIdentity()).toEqual(null);
                    },
                    error: function(error)
                    {
                        expect(error).toEqual(_logoutError);
                        expect(authIdentity.hasIdentity()).toEqual(true);
                        expect(authIdentity.getIdentity()).toEqual(_identity);
                    }
                };
            }]);

            authServerProvider.setHeader('X-Auth-Digest');
        }]);

        module('dgAuth', 'test.config');

        inject(function($injector)
        {
            _stateMachine = $injector.get('stateMachine');

            _authIdentity = $injector.get('authIdentity');
            _authRequests = $injector.get('authRequests');
            _authService = $injector.get('authService');
            _authStorage = $injector.get('authStorage');
            _authServer = $injector.get('authServer');
            _md5 = $injector.get('md5');

            _http = $injector.get('$http');
            _httpBackend = $injector.get('$httpBackend');

            _httpBackend.whenGET('/change').respond(function(method, url, data, headers)
            {
                var responseHeaders = {
                    'X-Auth-Digest': 'Digest ' +
                        'realm="Test AngularJS module", ' +
                        'domain="/", ' +
                        'nonce="32fffd4e446fc7735c4995154674e9d4", ' +
                        'opaque="e66aa41ca5bf6992a5479102cc787bc9", ' +
                        'algorithm="MD5", ' +
                        'qop="auth"'
                };

                return [401, angular.toJson(_loginError), responseHeaders];
            });

            _httpBackend.whenPOST('/signin').respond(function(method, url, data, headers)
            {
                var authorization = headers.Authorization;

                if(authorization)
                {
                    var regex = new RegExp(_regex);
                    var username = regex.exec(authorization);

                    if(username[1] == 'test')
                    {
                        return [201, angular.toJson(_identity), ''];
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

                return [401, angular.toJson(_loginError), responseHeaders];
            });

            _httpBackend.whenPOST('/signout').respond(function(method, url, data, headers)
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

                return [400, angular.toJson(_logoutError), headers];
            });
        });
    });

    afterEach(function()
    {
        _httpBackend.verifyNoOutstandingExpectation();
        _httpBackend.verifyNoOutstandingRequest();
    });

    describe('tests all functionality', function()
    {
        beforeEach(function()
        {
            _stateMachine.initialize();
        });

        it('should restore the credentials and sign in', function()
        {
            _authServer.info = {
                realm: 'Test Authentication Realm',
                domain: '/',
                nonce: _md5.createHash('nonce'),
                opaque: _md5.createHash('opaque'),
                algorithm: 'MD5',
                qop: 'auth'
            };

            spyOn(_authServer, 'isConfigured').andReturn(true);

            spyOn(_authStorage, 'hasCredentials').andReturn(true);
            spyOn(_authStorage, 'getUsername').andReturn('test');
            spyOn(_authStorage, 'getPassword').andReturn('test');

            _stateMachine.send('run');

            expect(_authStorage.hasCredentials).toHaveBeenCalled();
            expect(_authStorage.getUsername).toHaveBeenCalled();
            expect(_authStorage.getPassword).toHaveBeenCalled();

            spyOn(_authService, 'setCredentials').andCallThrough();

            _stateMachine.send('restored');

            expect(_authService.setCredentials).toHaveBeenCalledWith('test', 'test');

            spyOn(_authRequests, 'signin').andCallThrough();

            _stateMachine.send('signin');

            _authIdentity.isAuthorized().then(function(value)
            {
                expect(value).toBeTruthy();
            });

            expect(_authRequests.signin).toHaveBeenCalled();

            _httpBackend.expectPOST('/signin');
            _httpBackend.flush(1);
        });
    });
});