'use strict';

describe('Authentication Requests Specifications', function()
{
    var _authRequests;

    var _stateMachine;
    var _authService;
    var _authServer;

    var _http;
    var _httpBackend;
    var _q;

    var _fail = false;

    beforeEach(angular.mock.module('dgAuth'));

    beforeEach(function()
    {
        inject(function($injector)
        {
            _authRequests = $injector.get('authRequests');
            _stateMachine = $injector.get('stateMachine');

            _authService = $injector.get('authService');
            _authServer = $injector.get('authServer');

            _httpBackend = $injector.get('$httpBackend');
            _http = $injector.get('$http');
            _q = $injector.get('$q');

            spyOn(_stateMachine, 'send');

            _httpBackend.whenPOST('/signin').respond(function()
            {
                if(_fail)
                    return [401, '401', ''];

                return [201, '201', ''];
            });

            _httpBackend.whenPOST('/signout').respond(function()
            {
                return [201, '201', ''];
            });

            _httpBackend.whenGET('/request').respond(function()
            {
                return [201, '201', ''];
            });
        });
    });

    afterEach(function()
    {
        _httpBackend.verifyNoOutstandingExpectation();
        _httpBackend.verifyNoOutstandingRequest();
    });

    describe('tests access methods', function()
    {
        it('should return null', function()
        {
            expect(_authRequests.getPromise()).toBeNull();
        });
    });

    describe('tests login http requests', function()
    {
        it('should return the specified response', function()
        {
            var promise = _authRequests.signin();

            expect(_authRequests.getPromise()).toEqual(promise);

            promise.then(function(response)
            {
                expect(response.data).toEqual('201');
                expect(_stateMachine.send).toHaveBeenCalledWith('201', {response: response});
            });

            _httpBackend.expectPOST('/signin');
            _httpBackend.flush(1);

            promise.then(function(response)
            {
                expect(response.data).toEqual('201');
                expect(_stateMachine.send).toHaveBeenCalledWith('201', {response: response});
            });
        });

        it('should do the request previous saved', function()
        {
            spyOn(_stateMachine, 'isAvailable').andReturn(true);

            spyOn(_authService, 'hasRequest').andReturn(true);
            spyOn(_authService, 'getRequest').andCallFake(function()
            {
                var deferred = _q.defer();

                deferred.promise.then(function(response)
                {
                    expect(response.data).toEqual('201');

                    return response;
                });

                return {
                    config: {
                        method: 'GET',
                        url: '/request'
                    },
                    deferred: deferred
                };
            });

            var promise = _authRequests.signin();

            expect(_authRequests.getPromise()).toEqual(promise);

            promise.then(function(response)
            {
                expect(response.data).toEqual('201');
            });

            _httpBackend.expectGET('/request');
            _httpBackend.flush(1);

            expect(_stateMachine.isAvailable).toHaveBeenCalled();
            expect(_stateMachine.send).toHaveBeenCalled();
        });
    });

    describe('tests logout http requests', function()
    {
        it('should return the specified response', function()
        {
            var promise = _authRequests.signout();

            expect(_authRequests.getPromise()).toEqual(promise);

            promise.then(function(response)
            {
                expect(response.data).toEqual('201');
                expect(_stateMachine.send).toHaveBeenCalledWith('201', {response: response});
            });

            _httpBackend.expectPOST('/signout');
            _httpBackend.flush(1);

            promise.then(function(response)
            {
                expect(response.data).toEqual('201');
                expect(_stateMachine.send).toHaveBeenCalledWith('201', {response: response});
            });
        });

        it('should do the request previous saved', function()
        {
            spyOn(_stateMachine, 'isAvailable').andReturn(false);

            spyOn(_authService, 'hasRequest').andReturn(true);
            spyOn(_authService, 'getRequest').andCallFake(function()
            {
                var deferred = _q.defer();

                deferred.promise.then(function(response)
                {
                    expect(response.data).toEqual('201');

                    return response;
                });

                return {
                    config: {
                        method: 'GET',
                        url: '/request'
                    },
                    deferred: deferred
                };
            });

            var promise = _authRequests.signout();

            expect(_authRequests.getPromise()).toEqual(promise);

            promise.then(function(response)
            {
                expect(response.data).toEqual('201');
            });

            _httpBackend.expectGET('/request');
            _httpBackend.flush(1);

            expect(_stateMachine.isAvailable).toHaveBeenCalled();
        });
    });

    describe('limit set to default', function()
    {
        beforeEach(function()
        {
            _fail = true;

            spyOn(_authServer, 'parseHeader').andReturn(true);
        });

        it('should respect the limit', function()
        {
            for(var i=0; i<4; i++)
            {
                _authRequests.signin();

                _httpBackend.expectPOST('/signin');
                _httpBackend.flush(1);

                expect(_stateMachine.send).toHaveBeenCalled();
                expect(_authRequests.getValid()).toBeTruthy();
            }
        });

        it('should exceed the limit', function()
        {
            for(var i=0; i<4; i++)
            {
                _authRequests.signin();

                _httpBackend.expectPOST('/signin');
                _httpBackend.flush(1);

                expect(_stateMachine.send).toHaveBeenCalled();
                expect(_authRequests.getValid()).toBeTruthy();
            }

            _authRequests.signin();

            _httpBackend.expectPOST('/signin');
            _httpBackend.flush(1);

            expect(_stateMachine.send).toHaveBeenCalled();
            expect(_authRequests.getValid()).toBeFalsy();
        });
    });
});