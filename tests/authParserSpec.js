'use strict';

describe('Authentication Parser Specification', function()
{

    beforeEach(angular.mock.module('dgAuth'));

    describe('tests dequote', function()
    {
        var dequote;
        beforeEach(inject(function(__dequote_)
        {
            dequote = __dequote_;
        }));

        it('should not change an unquoted string', function()
        {
            expect(dequote('foo')).toEqual('foo');
            expect(dequote('f"oo"')).toEqual('f"oo"');
            expect(dequote("'foo'")).toEqual("'foo'");
        });
        
        it('should strip enclosing quotes', function()
        {
            expect(dequote('"foo"')).toEqual('foo');
        });

        it('should unescape the enclosed value', function()
        {
            expect(dequote('"f\\"o\\"o"')).toEqual('f"o"o');
            expect(dequote('"f\\!o\\\'o"')).toEqual("f!o'o");
        });
    });

    describe('tests parseChallenge', function()
    {
        var parseChallenge;
        beforeEach(inject(function(_parseChallenge_)
        {
            parseChallenge = _parseChallenge_;
        }));

        var barelyLegal = "!#$%&'*+-.0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ^_`abcdefghijklmnopqrstuvwxyz|~";
        
        var asciiRainbow = 
            '\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10'+
            '\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20'+
            '!"#$%&\'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNO'+
            'PQRSTUVWXYZ[\]^_`abcdefghijklmnopqrstuvwxyz{|}~';
        
        // Succeeding cases
        [
            {
                value: 'Digest nonce=foo',
                scheme: 'Digest',
                params:
                {
                    nonce: 'foo'
                }
            },
            {
                value: 'Madeup nonce="foo"',
                scheme: 'Madeup',
                params:
                {
                    nonce: 'foo'
                }
            },
            {
                value: 'Digest nonce="foo"',
                scheme: 'Digest',
                params:
                {
                    nonce: 'foo'
                }
            },
            {
                value: "Digest nonce='foo'",
                scheme: 'Digest',
                params:
                {
                    nonce: "'foo'"
                }
            },
            {
                value: 'Digest nonce=""',
                scheme: 'Digest',
                params:
                {
                    nonce: ''
                }
            },
            {
                value: 'Digest nonce="\\"foo, foo! foo; foo=bar\\""',
                scheme: 'Digest',
                params:
                {
                    nonce: '"foo, foo! foo; foo=bar"'
                }
            },
            {
                // Push the limits.
                value: barelyLegal+' '+
                    barelyLegal+'1='+barelyLegal+','+
                    barelyLegal+'2="'+asciiRainbow.replace(/"/,'\\"')+'"',
                scheme: barelyLegal,
                params: (function() {
                    // Can't have computed keys in an object literal.
                    var x = {};
                    x[barelyLegal+'1'] = barelyLegal;
                    x[barelyLegal+'2'] = asciiRainbow;
                    return x;
                })()
            },

        ]
        .forEach(function(_case, ix)
        {
            it('should parse succeeding case '+(ix+1), function()
            {
                var params = {};
                var scheme;
                function runner()
                {
                    scheme = parseChallenge(_case.value, params)
                }

                expect(runner).not.toThrow();
                expect(scheme).toEqual(_case.scheme);
                expect(params).toEqual(_case.params);
            });
        });

        // Failing cases
        [
            {
                value: '',
                error: 'expected scheme token at pos 0',
            },
            {
                value: 'Digest',
                error: 'expected space delimiter following scheme at pos 6',
            },
            {
                value: 'Digest nonce',
                error: 'expected parameter expression at pos 7',
            },
            {
                value: 'Digest nonce=foo,',
                error: 'expected parameter expression at pos 17',
            },
            {
                value: 'Digest whoops failed=again',
                error: 'expected parameter expression at pos 7',
            },
            {
                value: 'non=token failed=again',
                error: 'expected space delimiter following scheme at pos 3',
            },
        ]
        .forEach(function(_case, ix)
        {
            it('should not parse failing case '+(ix+1), function()
            {
                // Jasmine 1.3 has no toThrowError() so do something equivalent.

                var error;
                function runner()
                {
                    try
                    { 
                        parseChallenge(_case.value, {})
                    }
                    catch(e)
                    {
                        error = e;
                    }
                }

                expect(runner).not.toThrow();
                expect(error).toMatch(_case.error);
            });
        });
    });

});
