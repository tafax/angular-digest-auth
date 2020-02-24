/**
 * Provides parsing services for the authentication.
 */

// These constants are mainly here in an attempt to improve the legibility
// (and testability) of the WWW-Authenticate parser

// Creates a regex group around an expression x
dgAuth.constant('_g', function(x) { return '('+x+')'; });

// Concatenates regex expressions in a sequence
dgAuth.constant('_seq', function() { return Array.prototype.join.call(arguments, ''); });

// Concatenates regex expressions in an alternation, wrapped in a non-capturing group
dgAuth.constant('_alt', function() { return '(?:'+Array.prototype.join.call(arguments, '|')+')'; });

// Token matcher regex. Any sequence of ascii chars except separators, control chars, tabs and spaces.
// i.e. ! #$%&' *+-. 0123456789 ABCDEFGHIJKLMNOPQRSTUVWXYZ ^_`abcdefghijklmnopqrstuvwxyz |~

dgAuth.constant('_tokenRx', '[!#-\x27*+.0-9A-Z^-z|~-]+')

// Quoted String matcher regex
dgAuth.factory('_quotedRx', ['_alt', 
                            function(alt)
{
    return '"'+alt('\\\\"', '[^"\\\\]+')+'*"';
}]);

// Parameter expression matcher regex
dgAuth.factory('_paramRx', ['_seq','_g','_tokenRx','_alt','_quotedRx',
                           function(seq, g, tokenRx, alt, quotedRx)
{
    return seq(g(tokenRx), '=', g(alt( quotedRx, tokenRx )), '\\s*');
}]);

// Unescapes quoted a string x, if it is quoted
dgAuth.constant('_dequote', function(x)
{
    if (x.charAt(0) !== '"')
        return x; // No-op
    return x.slice(1, -1).replace(/\\(.)/g, '$1');
});


/**
 * Parses WWW-Authenticate header to set the information.
 *
 * For details of the header's grammar,
 * see https://tools.ietf.org/html/rfc2617#section-1.2
 * and https://tools.ietf.org/html/rfc2616#section-2.1
 *
 * To summarise: The WWW-Authenticate header MUST contain
 * at least one challenge, where:
 *
 *   challenge   = auth-scheme 1*SP 1#auth-param
 * 
 *   auth-scheme = token
 *
 *   auth-param  = token "=" ( token | quoted-string )
 *
 *   token = 1*<any char except '()<>@,;:\"/[]?={}', control chars, space or horizontal tab>
 *   quoted-string  = ( <"> *(qdtext | quoted-pair ) <"> )
 *   qdtext         = <any TEXT except <">>
 *   quoted-pair    = "\" CHAR
 * 
 * This means we parse more variations, but strictly the
 * strings obtained may not be valid (tokens may contain
 * certain illegal characters). However, they should be
 * usable, since we only care about well known tokens, and
 * ignore the others.
 *
 * Note we also assume only one challenge! This will cause us
 * to fail if it is false.
 *
 * @param {String} challenge The challenge string to parse.
 * @param {String} challenge An object to store the parameters in.
 * @return The challenge scheme, on success.
 * @throws An exception if the parsing failed.
 */
dgAuth.factory('parseChallenge', ['_paramRx', '_tokenRx', '_dequote',
                                  function(paramRx, tokenRx, dequote)
{
    // Compile the regex strings, constrained to match at the start
    var schemeRx = new RegExp('^'+tokenRx);
    paramRx = new RegExp('^'+paramRx);

    return function(challenge, info)
    {
        try
        {
            if(null === challenge)
                throw "challenge string is null";

            var match = challenge.match(schemeRx);
            if (!match)
                throw "expected scheme token at pos 0";
            
            // Remove scheme token
            var scheme = match[0];
            var pos = scheme.length;
            challenge = challenge.substr(pos);

            // Match leading space delimiter
            match = challenge.match('^ +');
            if (!match)
                throw "expected space delimiter following scheme at pos "+pos;

            // Get the remaining part in params.
            pos += match[0].length;
            var params = challenge.substr(match[0].length);

            while(true) {
                match = params.match(paramRx);
                if (!match)
                    throw "expected parameter expression at pos "+pos+" of "+params;

                // Get information
                info[match[1]] = dequote(match[2]);

                // Parse next parameter
                params = params.substr(match[0].length);
                pos += match[0].length;
                if (params.length === 0)
                    break;                    
                
                // Parse next delimeter
                match = params.match(/^, */);
                if (!match)
                    throw "expected comma delimiter at pos "+pos;

                // Remove matched portion and delimiter
                params = params.substr(match[0].length);
                pos += match[0].length;
            }

            return scheme;
        }
        catch(e)
        {
            throw "Whilst parsing WWW-Authenticate challenge: "+challenge+"\n"+e;
        }        
    };
}]);
