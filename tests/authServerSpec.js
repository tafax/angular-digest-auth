'use strict';

describe('Authentication Server Specification', function()
{
    var _authServer;

    var _authStorage;
    var _cases = [
        {
            name: "Case 1",
            info: {
                realm: 'Test Authentication Realm',
                domain: '/domain',
                nonce: 'cb584e44c43ed6bd0bc2d9c7e242837d',
                opaque: '94619f8a70068b2591c2eed622525b0e',
                algorithm: 'MD5',
                qop: 'auth'
            },
        },
        {
            /* Adapted from real example using Restlet 2.3 server.
             * The important diffences are a base64 nonce with padding ('==').
             * If the padding is stripped, the authentication attempt is rejected.
             * Also that the opaque attribute is an empty string.
             */
            name: "Case 2",
            info: {
                realm: 'Test Authentication Realm',
                domain: '/domain',
                nonce: 'MTQ0NzA2MDcwOTc1OTphYTEzYWY4ZDczOTc0YTk5NjQ1Nzg0ZjU2NzgwNjIwNw==',
                opaque: '',
                algorithm: 'MD5',
                qop: 'auth'
            },
        },
    ];


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

            _authStorage = $injector.get('authStorage');

            spyOn(_authStorage, 'setServerAuth');

        });
    });

    describe('tests all methods', function()
    {
        _cases.forEach(function(_case) {
            var info = _case.info

            it('should set the information with manual configuration (case '+_case.name+')', function()
            {
                _authServer.setConfig(info);
                
                expect(_authServer.isConfigured()).toBeTruthy();
                expect(_authServer.info).toEqual(info);
            });
            
            it('should set the information with response (case '+_case.name+')', function()
            {
                _authServer.parseHeader(new Response(info));
                
                expect(_authStorage.setServerAuth).toHaveBeenCalled();
                
                expect(_authServer.isConfigured()).toBeTruthy();
                expect(_authServer.info).toEqual(info);
            });
            
        });
    });
});
