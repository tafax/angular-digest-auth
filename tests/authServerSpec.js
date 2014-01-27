'use strict';

describe('Authentication Server Specification', function()
{
    var _authServer;

    var _md5;
    var _authStorage;

    var _info;

    function Response(info)
    {
        var _header = {
            "My-Header": "Digest " +
                "realm=\"" + info.realm + "\", " +
                "domain=\"" + info.domain + "\", " +
                "nonce=\"" + info.nonce + "\", " +
                "opaque=\"" + info.opaque + "\", " +
                "algorithm=\"" + info.algorithm + "\", " +
                "qop=\"" + info.qop + "\""
        };

        return {
            headers: function(header)
            {
                return _header[header];
            }
        };
    }

    beforeEach(angular.mock.module('dgAuth'));

    beforeEach(function()
    {
        var fake = angular.module('test.config', []);
        fake.config(['dgAuthServiceProvider', function(dgAuthServiceProvider)
        {
            dgAuthServiceProvider.setHeader('My-Header');
        }]);

        module('test.config', 'dgAuth');

        inject(function($injector)
        {
            _authServer = $injector.get('authServer');

            _md5 = $injector.get('md5');
            _authStorage = $injector.get('authStorage');

            spyOn(_authStorage, 'setServerAuth');

            _info = {
                realm: 'Test Authentication Realm',
                domain: '/domain',
                nonce: _md5.createHash('nonce'),
                opaque: _md5.createHash('opaque'),
                algorithm: 'MD5',
                qop: 'auth'
            };
        });
    });

    describe('tests all methods', function()
    {
        it('should set the information with manual configuration', function()
        {
            _authServer.setConfig(_info);

            expect(_authServer.isConfigured()).toBeTruthy();
            expect(_authServer.info).toEqual(_info);
        });

        it('should set the information with response', function()
        {
            _authServer.parseHeader(new Response(_info));

            expect(_authStorage.setServerAuth).toHaveBeenCalled();

            expect(_authServer.isConfigured()).toBeTruthy();
            expect(_authServer.info).toEqual(_info);
        });
    });
});