'use strict';

describe('Authentication Storage Specifications', function()
{
    var _mockup = function()
    {
        var _table = {};

        return {
            getItem: function(key)
            {
                return _table[key];
            },
            setItem: function(key, value)
            {
                _table[key] = value.toString();
            },
            removeItem: function(key, value)
            {
                delete _table[key];
            },
            clear: function()
            {
                _table = {};
            }
        };
    }();

    var _authStorage;

    var _serverInfo = {
        info: 'info',
        value: 'value'
    };

    beforeEach(angular.mock.module('dgAuth'));

    beforeEach(function()
    {
        Object.defineProperty(window, 'sessionStorage', { value: _mockup });

        spyOn(window.sessionStorage, 'setItem').andCallThrough();
        spyOn(window.sessionStorage, 'getItem').andCallThrough();
        spyOn(window.sessionStorage, 'removeItem').andCallThrough();

        inject(function($injector)
        {
            _authStorage = $injector.get('authStorage');
        });
    });

    describe('tests all access methods', function()
    {
        it('should return undefined server info', function()
        {
            expect(_authStorage.hasServerAuth()).toBeFalsy();
            expect(_authStorage.getServerAuth()).toBeUndefined();

            expect(window.sessionStorage.getItem).toHaveBeenCalledWith('server');
        });

        it('should set the server info', function()
        {
            _authStorage.setServerAuth(_serverInfo);

            expect(window.sessionStorage.setItem).toHaveBeenCalledWith('server', angular.toJson(_serverInfo));

            expect(_authStorage.hasServerAuth()).toBeTruthy();
            expect(_authStorage.getServerAuth()).toEqual(_serverInfo);
        });

        it('should return undefined credentials', function()
        {
            expect(_authStorage.hasCredentials()).toBeFalsy();
            expect(_authStorage.getUsername()).toBeUndefined();
            expect(_authStorage.getPassword()).toBeUndefined();

            expect(window.sessionStorage.getItem).toHaveBeenCalledWith('username');
            expect(window.sessionStorage.getItem).toHaveBeenCalledWith('password');
        });

        it('should return the specified credentials', function()
        {
            _authStorage.setCredentials('test', 'test');

            expect(window.sessionStorage.setItem).toHaveBeenCalledWith('username', 'test');
            expect(window.sessionStorage.setItem).toHaveBeenCalledWith('password', 'test');

            expect(_authStorage.getUsername()).toEqual('test');
            expect(_authStorage.getPassword()).toEqual('test');

            expect(window.sessionStorage.getItem).toHaveBeenCalledWith('username');
            expect(window.sessionStorage.getItem).toHaveBeenCalledWith('password');
        });

        it('should clear the credentials', function()
        {
            _authStorage.setCredentials('test', 'test');

            expect(_authStorage.hasServerAuth()).toBeTruthy();
            expect(_authStorage.getUsername()).toEqual('test');
            expect(_authStorage.getPassword()).toEqual('test');

            _authStorage.clearCredentials();

            expect(window.sessionStorage.removeItem).toHaveBeenCalledWith('username');
            expect(window.sessionStorage.removeItem).toHaveBeenCalledWith('password');

            expect(_authStorage.hasCredentials()).toBeFalsy();
            expect(_authStorage.getUsername()).toBeUndefined();
            expect(_authStorage.getPassword()).toBeUndefined();
        });
    });
});