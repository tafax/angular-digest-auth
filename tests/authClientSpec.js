'use strict';

describe('Authentication Client Specification', function()
{
    var createResponse = function(username, password, method, uri, nc, cnonce)
    {
        var ha1 = _md5.createHash(username + ":" + _authServer.info.realm + ":" + password);
        var ha2 = _md5.createHash(method + ":" + uri);
        return _md5.createHash(ha1 + ":" + _authServer.info.nonce + ":" + nc + ":" + cnonce + ":" + _authServer.info.qop + ":" + ha2);
    };

    var _authClient;

    var _authServer;
    var _md5;

    var _regex = {
        username: /username\=\"([a-zA-Z0-9\s\/]*)\"/,
        realm: /realm\=\"([a-zA-Z0-9\s\/]*)\"/,
        nonce: /nonce\=\"([a-zA-Z0-9\s\/]*)\"/,
        uri: /uri\=\"([a-zA-Z0-9\s\/]*)\"/,
        algorithm: /algorithm\=\"([a-zA-Z0-9\s\/]*)\"/,
        response: /response\=\"([a-zA-Z0-9\s\/]*)\"/,
        opaque: /opaque\=\"([a-zA-Z0-9\s\/]*)\"/,
        qop: /qop\=\"([a-zA-Z0-9\s\/]*)\"/,
        nc: /nc\=\"([a-zA-Z0-9\s\/]*)\"/,
        cnonce: /cnonce\=\"([a-zA-Z0-9\s\/]*)\"/
    };

    beforeEach(angular.mock.module('dgAuth'));

    beforeEach(function()
    {
        inject(function($injector)
        {
            _authClient = $injector.get('authClient');

            _authServer = $injector.get('authServer');
            _md5 = $injector.get('md5');

            _authServer.setConfig({
                realm: 'Test Authentication Client',
                domain: '/domain',
                nonce: _md5.createHash('nonce'),
                opaque: _md5.createHash('opaque'),
                algorithm: 'MD5',
                qop: 'auth'
            });

            spyOn(_authServer, 'isConfigured').andReturn(true);

            spyOn(_md5, 'createHash').andCallThrough();
        });
    });

    describe('tests the creation of header', function()
    {
        it('should return null', function()
        {
            expect(_authClient.processRequest('test', 'test', 'GET', '/some/path')).toBeNull();
        });

        it('should return the correct header', function()
        {
            var header = _authClient.processRequest('test', 'test', 'GET', '/domain/some/path');

            expect(header).not.toBeNull();

            var results = {};
            for(var i in _regex)
            {
                var exec = _regex[i].exec(header);
                results[i] = exec[1];
            }

            expect(results.username).toEqual('test');
            expect(results.realm).toEqual('Test Authentication Client');
            expect(results.nonce).toEqual(_md5.createHash('nonce'));
            expect(results.uri).toEqual('/domain/some/path');
            expect(results.algorithm).toEqual('MD5');
            expect(results.opaque).toEqual(_md5.createHash('opaque'));
            expect(results.qop).toEqual('auth');
            expect(results.nc).toEqual('00000001');

            expect(createResponse('test', 'test', 'GET', '/domain/some/path', results.nc, results.cnonce)).toEqual(results.response);
        });
    });
});