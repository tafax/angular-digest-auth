'use strict';

describe('angular-digest-auth', function()
{
    var _dgAuthService;
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
            'dgAuthServiceProvider',
        function(dgAuthServiceProvider)
        {
            dgAuthServiceProvider.setLimit(10);

            dgAuthServiceProvider.setConfig({
                login: {
                    method: 'POST',
                    url: '/signin'
                },
                logout: {
                    method: 'POST',
                    url: '/signout'
                }
            });

            dgAuthServiceProvider.callbacks.login.push(['authIdentity', function(authIdentity)
            {
                return {
                    successful: function(response)
                    {
                        if(response.url == '/signin')
                        {
                            expect(response.data).toEqual(_identity);
                        }

                        if(response.url == '/change')
                        {
                            expect(response.data).toEqual('OK');
                        }

                        expect(authIdentity.has()).toEqual(true);
                        expect(authIdentity.get()).toEqual(_identity);
                    },
                    error: function(response)
                    {
                        expect(response.data).toEqual(_loginError);
                        expect(authIdentity.has()).toEqual(false);
                        expect(authIdentity.get()).toEqual(null);
                    },
                    required: function(response)
                    {
                        expect(authIdentity.has()).toEqual(false);
                        expect(authIdentity.get()).toEqual(null);
                    },
                    limit: function(response)
                    {
                        expect(response.data).toEqual(_loginError);
                        expect(authIdentity.has()).toEqual(false);
                        expect(authIdentity.get()).toEqual(null);
                    }
                };
            }]);

            dgAuthServiceProvider.callbacks.logout.push(['authIdentity', function(authIdentity)
            {
                return {
                    successful: function(response)
                    {
                        expect(response.data).toEqual('');
                        expect(authIdentity.has()).toEqual(false);
                        expect(authIdentity.get()).toEqual(null);
                    },
                    error: function(response)
                    {
                        expect(response.data).toEqual(_logoutError);
                        expect(authIdentity.has()).toEqual(true);
                        expect(authIdentity.get()).toEqual(_identity);
                    }
                };
            }]);

            dgAuthServiceProvider.setHeader('X-Auth-Digest');
        }]);

        module('dgAuth', 'test.config');

        inject(function($injector)
        {
            _dgAuthService = $injector.get('dgAuthService');
            _stateMachine = $injector.get('stateMachine');

            _authIdentity = $injector.get('authIdentity');
            _authRequests = $injector.get('authRequests');
            _authService = $injector.get('authService');
            _authStorage = $injector.get('authStorage');
            _authServer = $injector.get('authServer');
            _md5 = $injector.get('md5');

            _http = $injector.get('$http');
            _httpBackend = $injector.get('$httpBackend');

            var changeCount = 0;

            _httpBackend.whenGET('/change').respond(function(method, url, data, headers)
            {
                if(changeCount == 0)
                {
                    changeCount++;

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
                }

                return [200, 'OK', ''];
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

    beforeEach(function()
    {
        _stateMachine.initialize();
    });

    afterEach(function()
    {
        _httpBackend.verifyNoOutstandingExpectation();
        _httpBackend.verifyNoOutstandingRequest();
    });

    describe('tests with no server info or credentials stored', function()
    {
        beforeEach(function()
        {
            spyOn(_authStorage, 'hasCredentials').andReturn(false);

            _stateMachine.send('run');

            expect(_authStorage.hasCredentials).toHaveBeenCalled();

            spyOn(_authService, 'setCredentials').andCallThrough();
            spyOn(_authService, 'clearCredentials').andCallThrough();
            spyOn(_authService, 'getCallbacks').andCallThrough();

            _stateMachine.send('restored');

            expect(_authService.setCredentials).not.toHaveBeenCalled();

            spyOn(_authRequests, 'signin').andCallThrough();
        });

        afterEach(function()
        {
            _stateMachine.send('submitted', {
                credentials: {
                    username: 'test',
                    password: 'test'
                }
            });

            expect(_authService.setCredentials).toHaveBeenCalledWith('test', 'test');

            spyOn(_authIdentity, 'set').andCallThrough();

            _stateMachine.send('signin');

            _httpBackend.expectPOST('/signin');
            _httpBackend.flush(1);

            expect(_authIdentity.set).toHaveBeenCalled();
            expect(_authService.getCallbacks).toHaveBeenCalled();

            _dgAuthService.isAuthorized().then(function(value)
            {
                expect(value).toBeTruthy();
            });
        });

        it('should ask for the info and credentials and then sign in', function()
        {
            _stateMachine.send('signin');

            expect(_authRequests.signin).toHaveBeenCalled();
            expect(_authStorage.hasCredentials).toHaveBeenCalled();

            _httpBackend.expectPOST('/signin');
            _httpBackend.flush(1);

            expect(_authService.clearCredentials).toHaveBeenCalled();
            expect(_authService.getCallbacks).toHaveBeenCalledWith('login.required');
        });

        it('should ask for the info and then have an error on login', function()
        {
            _stateMachine.send('signin');

            _dgAuthService.isAuthorized().then(function(value)
            {
                expect(value).toBeTruthy();
            });

            expect(_authRequests.signin).toHaveBeenCalled();
            expect(_authStorage.hasCredentials).toHaveBeenCalled();

            _httpBackend.expectPOST('/signin');
            _httpBackend.flush(1);

            expect(_authService.clearCredentials).toHaveBeenCalled();
            expect(_authService.getCallbacks).toHaveBeenCalledWith('login.required');

            _stateMachine.send('submitted', {
                credentials: {
                    username: 'fake',
                    password: 'fake'
                }
            });

            expect(_authService.setCredentials).toHaveBeenCalledWith('fake', 'fake');

            _stateMachine.send('signin');

            _dgAuthService.isAuthorized().then(function(value)
            {
                expect(value).toBeTruthy();
            });

            _httpBackend.expectPOST('/signin');
            _httpBackend.flush(1);

            expect(_authService.clearCredentials).toHaveBeenCalled();
            expect(_authService.getCallbacks).toHaveBeenCalledWith('login.error');
        });
    });

    describe('test the limit', function()
    {
        beforeEach(function()
        {
            spyOn(_authRequests, 'getValid').andCallThrough();
            spyOn(_authIdentity, 'clear').andCallThrough();
            spyOn(_authStorage, 'hasCredentials').andReturn(false);

            _stateMachine.send('run');

            expect(_authStorage.hasCredentials).toHaveBeenCalled();

            spyOn(_authService, 'setCredentials').andCallThrough();
            spyOn(_authService, 'clearCredentials').andCallThrough();
            spyOn(_authService, 'getCallbacks').andCallThrough();

            _stateMachine.send('restored');

            expect(_authService.setCredentials).not.toHaveBeenCalled();

            spyOn(_authRequests, 'signin').andCallThrough();

            _stateMachine.send('signin');

            _dgAuthService.isAuthorized().then(function(value)
            {
                expect(value).toBeTruthy();
            });

            expect(_authRequests.signin).toHaveBeenCalled();
            expect(_authStorage.hasCredentials).toHaveBeenCalled();

            _httpBackend.expectPOST('/signin');
            _httpBackend.flush(1);

            expect(_authService.clearCredentials).toHaveBeenCalled();
            expect(_authService.getCallbacks).toHaveBeenCalledWith('login.required');
        });

        it('should have multiple error and exceed the limit', function()
        {
            for(var i=0; i<10; i++)
            {
                _stateMachine.send('submitted', {
                    credentials: {
                        username: 'fake',
                        password: 'fake'
                    }
                });

                expect(_authService.setCredentials).toHaveBeenCalledWith('fake', 'fake');

                _stateMachine.send('signin');

                _httpBackend.expectPOST('/signin');
                _httpBackend.flush(1);

                expect(_authService.clearCredentials).toHaveBeenCalled();
                expect(_authService.getCallbacks).toHaveBeenCalledWith('login.error');
            }

            expect(_authRequests.getValid).toHaveBeenCalled();
            expect(_authIdentity.clear).toHaveBeenCalled();
            expect(_authService.clearCredentials).toHaveBeenCalled();
            expect(_authService.getCallbacks).toHaveBeenCalledWith('login.limit');
        });

        it('should have multiple error on login', function()
        {
            for(var i=0; i<8; i++)
            {
                _stateMachine.send('submitted', {
                    credentials: {
                        username: 'fake',
                        password: 'fake'
                    }
                });

                expect(_authService.setCredentials).toHaveBeenCalledWith('fake', 'fake');

                _stateMachine.send('signin');

                _httpBackend.expectPOST('/signin');
                _httpBackend.flush(1);

                expect(_authService.clearCredentials).toHaveBeenCalled();
                expect(_authService.getCallbacks).toHaveBeenCalledWith('login.error');
            }

            _stateMachine.send('submitted', {
                credentials: {
                    username: 'test',
                    password: 'test'
                }
            });

            expect(_authService.setCredentials).toHaveBeenCalledWith('test', 'test');

            spyOn(_authIdentity, 'set').andCallThrough();

            _stateMachine.send('signin');

            _httpBackend.expectPOST('/signin');
            _httpBackend.flush(1);

            expect(_authIdentity.set).toHaveBeenCalled();
            expect(_authService.getCallbacks).toHaveBeenCalled();

            _dgAuthService.isAuthorized().then(function(value)
            {
                expect(value).toBeTruthy();
            });
        });

        it('should have multiple errors and logout successful', function()
        {
            for(var i=0; i<8; i++)
            {
                _stateMachine.send('submitted', {
                    credentials: {
                        username: 'fake',
                        password: 'fake'
                    }
                });

                expect(_authService.setCredentials).toHaveBeenCalledWith('fake', 'fake');

                _stateMachine.send('signin');

                _httpBackend.expectPOST('/signin');
                _httpBackend.flush(1);

                expect(_authService.clearCredentials).toHaveBeenCalled();
                expect(_authService.getCallbacks).toHaveBeenCalledWith('login.error');
            }

            _stateMachine.send('submitted', {
                credentials: {
                    username: 'test',
                    password: 'test'
                }
            });

            expect(_authService.setCredentials).toHaveBeenCalledWith('test', 'test');

            spyOn(_authIdentity, 'set').andCallThrough();

            _stateMachine.send('signin');

            _httpBackend.expectPOST('/signin');
            _httpBackend.flush(1);

            expect(_authIdentity.set).toHaveBeenCalled();
            expect(_authService.getCallbacks).toHaveBeenCalled();

            _dgAuthService.isAuthorized().then(function(value)
            {
                expect(value).toBeTruthy();
            });

            _stateMachine.send('signout');

            _dgAuthService.isAuthorized().then(function(value)
            {
                expect(value).toBeFalsy();
            });

            _httpBackend.expectPOST('/signout');
            _httpBackend.flush(1);

            expect(_authIdentity.clear).toHaveBeenCalled();
            expect(_authService.getCallbacks).toHaveBeenCalledWith('logout.successful');

            _dgAuthService.isAuthorized().then(function(value)
            {
                expect(value).toBeFalsy();
            });
        });
    });

    describe('tests with server info stored', function()
    {
        beforeEach(function()
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

            spyOn(_authStorage, 'hasCredentials').andReturn(false);
            spyOn(_authStorage, 'getUsername');
            spyOn(_authStorage, 'getPassword');

            _stateMachine.send('run');

            expect(_authStorage.hasCredentials).toHaveBeenCalled();
            expect(_authStorage.getUsername).not.toHaveBeenCalled();
            expect(_authStorage.getPassword).not.toHaveBeenCalled();

            spyOn(_authService, 'setCredentials').andCallThrough();
            spyOn(_authService, 'clearCredentials').andCallThrough();
            spyOn(_authService, 'getCallbacks').andCallThrough();

            _stateMachine.send('restored');

            expect(_authService.setCredentials).not.toHaveBeenCalled();

            spyOn(_authRequests, 'signin').andCallThrough();
        });

        afterEach(function()
        {
            _stateMachine.send('submitted', {
                credentials: {
                    username: 'test',
                    password: 'test'
                }
            });

            expect(_authService.setCredentials).toHaveBeenCalledWith('test', 'test');

            spyOn(_authIdentity, 'set').andCallThrough();

            _stateMachine.send('signin');

            _httpBackend.expectPOST('/signin');
            _httpBackend.flush(1);

            expect(_authIdentity.set).toHaveBeenCalled();
            expect(_authService.getCallbacks).toHaveBeenCalled();

            _dgAuthService.isAuthorized().then(function(value)
            {
                expect(value).toBeTruthy();
            });
        });

        it('should restore the info and ask for the credentials', function()
        {
            _stateMachine.send('signin');

            _dgAuthService.isAuthorized().then(function(value)
            {
                expect(value).toBeTruthy();
            });

            expect(_authRequests.signin).toHaveBeenCalled();
            expect(_authStorage.hasCredentials).toHaveBeenCalled();

            _httpBackend.expectPOST('/signin');
            _httpBackend.flush(1);

            expect(_authService.clearCredentials).toHaveBeenCalled();
            expect(_authService.getCallbacks).toHaveBeenCalledWith('login.required');
        });
    });

    describe('tests with server info and credentials stored', function()
    {
        beforeEach(function()
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
            spyOn(_authService, 'clearCredentials').andCallThrough();
            spyOn(_authService, 'getCallbacks').andCallThrough();

            _stateMachine.send('restored');

            expect(_authService.setCredentials).toHaveBeenCalledWith('test', 'test');

            spyOn(_authIdentity, 'set').andCallThrough();
            spyOn(_authIdentity, 'clear').andCallThrough();
            spyOn(_authRequests, 'signin').andCallThrough();
        });

        it('should restore the credentials, info and sign in', function()
        {
            _stateMachine.send('signin');

            _dgAuthService.isAuthorized().then(function(value)
            {
                expect(value).toBeTruthy();
            });

            expect(_authRequests.signin).toHaveBeenCalled();

            _httpBackend.expectPOST('/signin');
            _httpBackend.flush(1);

            expect(_authIdentity.set).toHaveBeenCalled();
            expect(_authService.getCallbacks).toHaveBeenCalledWith('login.successful');

            _dgAuthService.isAuthorized().then(function(value)
            {
                expect(value).toBeTruthy();
            });
        });

        it('should resubmit the credentials', function()
        {
            spyOn(_authStorage, 'clearCredentials');

            _stateMachine.send('signin');

            _dgAuthService.isAuthorized().then(function(value)
            {
                expect(value).toBeTruthy();
            });

            expect(_authRequests.signin).toHaveBeenCalled();

            _httpBackend.expectPOST('/signin');
            _httpBackend.flush(1);

            expect(_authIdentity.set).toHaveBeenCalled();
            expect(_authService.getCallbacks).toHaveBeenCalledWith('login.successful');

            _dgAuthService.isAuthorized().then(function(value)
            {
                expect(value).toBeTruthy();
            });

            _http.get('/change').then(function(response)
            {
                expect(response.data).toEqual('OK');
            });

            _httpBackend.expectGET('/change');
            _httpBackend.flush(1);

            _dgAuthService.isAuthorized().then(function(value)
            {
                expect(value).toBeFalsy();
            });

            expect(_authStorage.clearCredentials).toHaveBeenCalled();
            expect(_authService.clearCredentials).toHaveBeenCalled();
            expect(_authService.getCallbacks).toHaveBeenCalledWith('login.required');

            _stateMachine.send('submitted', {
                credentials: {
                    username: 'test',
                    password: 'test'
                }
            });

            expect(_authService.setCredentials).toHaveBeenCalledWith('test', 'test');

            _stateMachine.send('signin');

            _httpBackend.expectGET('/change');
            _httpBackend.flush(1);

            expect(_authIdentity.set).toHaveBeenCalled();
            expect(_authService.getCallbacks).toHaveBeenCalledWith('login.successful');

            _dgAuthService.isAuthorized().then(function(value)
            {
                expect(value).toBeTruthy();
            });
        });

        it('should sign out', function()
        {
            _stateMachine.send('signin');

            _dgAuthService.isAuthorized().then(function(value)
            {
                expect(value).toBeTruthy();
            });

            expect(_authRequests.signin).toHaveBeenCalled();

            _httpBackend.expectPOST('/signin');
            _httpBackend.flush(1);

            expect(_authIdentity.set).toHaveBeenCalled();
            expect(_authService.getCallbacks).toHaveBeenCalledWith('login.successful');

            _dgAuthService.isAuthorized().then(function(value)
            {
                expect(value).toBeTruthy();
            });

            _stateMachine.send('signout');

            _dgAuthService.isAuthorized().then(function(value)
            {
                expect(value).toBeFalsy();
            });

            _httpBackend.expectPOST('/signout');
            _httpBackend.flush(1);

            expect(_authIdentity.clear).toHaveBeenCalled();
            expect(_authService.getCallbacks).toHaveBeenCalledWith('logout.successful');

            _dgAuthService.isAuthorized().then(function(value)
            {
                expect(value).toBeFalsy();
            });
        });

        it('should sign out and then sign in again', function()
        {
            _stateMachine.send('signin');

            _dgAuthService.isAuthorized().then(function(value)
            {
                expect(value).toBeTruthy();
            });

            expect(_authRequests.signin).toHaveBeenCalled();

            _httpBackend.expectPOST('/signin');
            _httpBackend.flush(1);

            expect(_authIdentity.set).toHaveBeenCalled();
            expect(_authService.getCallbacks).toHaveBeenCalledWith('login.successful');

            _dgAuthService.isAuthorized().then(function(value)
            {
                expect(value).toBeTruthy();
            });

            _stateMachine.send('signout');

            _dgAuthService.isAuthorized().then(function(value)
            {
                expect(value).toBeFalsy();
            });

            _httpBackend.expectPOST('/signout');
            _httpBackend.flush(1);

            expect(_authIdentity.clear).toHaveBeenCalled();
            expect(_authService.getCallbacks).toHaveBeenCalledWith('logout.successful');

            _dgAuthService.isAuthorized().then(function(value)
            {
                expect(value).toBeFalsy();
            });

            _stateMachine.send('submitted', {
                credentials: {
                    username: 'test',
                    password: 'test'
                }
            });

            expect(_authService.setCredentials).toHaveBeenCalledWith('test', 'test');

            _stateMachine.send('signin');

            _dgAuthService.isAuthorized().then(function(value)
            {
                expect(value).toBeTruthy();
            });

            expect(_authRequests.signin).toHaveBeenCalled();

            _httpBackend.expectPOST('/signin');
            _httpBackend.flush(1);

            expect(_authIdentity.set).toHaveBeenCalled();
            expect(_authService.getCallbacks).toHaveBeenCalledWith('login.successful');

            _dgAuthService.isAuthorized().then(function(value)
            {
                expect(value).toBeTruthy();
            });
        });
    });
});