'use strict';

describe('Authentication Identity Specification', function()
{
    var _authIdentity;
    var _httpBackend;

    var _identity = {
        key1: 'value1',
        key2: 'value2',
        key3: {
            subKey1: 'subValue1',
            subKey2: 'subValue2'
        }
    };

    var _authRequests;

    beforeEach(angular.mock.module('dgAuth'));

    beforeEach(function()
    {
        inject(function($injector)
        {
            _authIdentity = $injector.get('authIdentity');
            _authRequests = $injector.get('authRequests');
            _httpBackend = $injector.get('$httpBackend');

            var http = $injector.get('$http');

            spyOn(_authRequests, 'getPromise').andCallFake(function()
            {
                return http.post('/fake');
            });

            _httpBackend.whenPOST('/fake').respond(function()
            {
                return [201, '', ''];
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
        it('should get null values', function()
        {
            expect(_authIdentity.has()).toBeFalsy();
            expect(_authIdentity.get()).toBeNull();
            expect(_authIdentity.get('some_key')).toBeNull();
        });

        it('should set the values and gets them', function()
        {
            _authIdentity.set(null, _identity);

            expect(_authIdentity.has()).toBeTruthy();

            expect(_authIdentity.get('key1')).toEqual(_identity.key1);
            expect(_authIdentity.get('key2')).toEqual(_identity.key2);
            expect(_authIdentity.get('key3')).toEqual(_identity.key3);

            expect(_authIdentity.get('fake')).toBeNull();

            expect(_authIdentity.get()).toEqual(_identity);
        });

        it('should set one value and gets it', function()
        {
            _authIdentity.set('key', 'value');

            expect(_authIdentity.has()).toBeTruthy();
            expect(_authIdentity.get('key')).toEqual('value');

            _authIdentity.set(null, _identity);

            expect(_authIdentity.get()).toEqual(_identity);
            expect(_authIdentity.get('key')).toBeNull();
        });

        it('should clear the identity', function()
        {
            _authIdentity.set(null, _identity);

            expect(_authIdentity.has()).toBeTruthy();

            _authIdentity.clear();

            expect(_authIdentity.has()).toBeFalsy();
            expect(_authIdentity.get()).toBeNull();
        });
    });
});