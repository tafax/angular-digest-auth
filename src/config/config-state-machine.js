'use strict';

dgAuth.config(['stateMachineProvider', function(stateMachineProvider)
{
    stateMachineProvider.config({
        init: {
            transitions: {
                run: 'restoringCredentials'
            }
        },
        restoringCredentials: {
            transitions: {
                restored: 'settingCredentials'
            },
            //Restores the credentials and propagate
            action: ['authStorage', 'params', function(authStorage, params)
            {
                if(authStorage.hasCredentials())
                {
                    params.credentials = {
                        username: authStorage.getUsername(),
                        password: authStorage.getPassword()
                    };
                }

                return params;
            }]
        },
        settingCredentials: {
            transitions: {
                signin: 'loginRequest'
            },
            //Sets the credentials as candidate
            action: ['authService', 'params', function(authService, params)
            {
                if(params.hasOwnProperty('credentials'))
                {
                    var credentials = params.credentials;
                    authService.setCredentials(credentials.username, credentials.password);
                }
            }]
        },
        loginRequest: {
            transitions: {
                //Checks if the credentials are present(loginError) or not(waitingCredentials)
                401: [
                {
                    to: 'waitingCredentials',
                    predicate: ['authService', 'authRequests', function(authService, authRequests)
                    {
                        return (!authService.hasCredentials() && authRequests.getValid());
                    }]
                },
                {
                    to: 'loginError',
                    predicate: ['authService', 'authRequests', function(authService, authRequests)
                    {
                        return (authService.hasCredentials() && authRequests.getValid());
                    }]
                },
                {
                    to: 'failureLogin',
                    predicate: ['authRequests', function(authRequests)
                    {
                        return !authRequests.getValid();
                    }]
                }],
                201: 'loggedIn'
            },
            //Does the request to the server and save the promise
            action: ['authRequests', function(authRequests)
            {
                authRequests.signin();
            }]
        },
        loginError: {
            transitions: {
                submitted: 'settingCredentials'
            },
            //Delete the credentials that are invalid and notify the error
            action: ['authService', 'params', function(authService, params)
            {
                authService.clearCredentials();
                var callbacks = authService.getCallbacks('login.error');
                for(var i in callbacks)
                {
                    var callback = callbacks[i];
                    callback(params.response);
                }
            }]
        },
        waitingCredentials: {
            transitions: {
                submitted: 'settingCredentials'
            },
            //Checks the previous state and notify the credential need
            action: [
                'authService',
                'authIdentity',
                'authStorage',
                'name',
                'params',
            function(authService, authIdentity, authStorage, name, params)
            {
                if(name == 'logoutRequest')
                {
                    authIdentity.clear();
                    authService.clearRequest();
                    authService.clearCredentials();
                    authStorage.clearCredentials();

                    var callbacksLogout = authService.getCallbacks('logout.successful');
                    for(var i in callbacksLogout)
                    {
                        var funcSuccessful = callbacksLogout[i];
                        funcSuccessful(params.response);
                    }
                }

                authIdentity.suspend();
                authService.clearCredentials();
                authStorage.clearCredentials();
                var callbacksLogin = authService.getCallbacks('login.required');
                for(var j in callbacksLogin)
                {
                    var funcRequest = callbacksLogin[j];
                    funcRequest(params.response);
                }
            }]
        },
        loggedIn: {
            transitions: {
                signout: 'logoutRequest',
                401: 'waitingCredentials'
            },
            //Checks the previous state and creates the identity and notify the login successful
            action: [
                'authService',
                'authIdentity',
                'authStorage',
                'name',
                'params',
            function(authService, authIdentity, authStorage, name, params)
            {
                if(name == 'logoutRequest')
                {
                    var callbacksLogout = authService.getCallbacks('logout.error');
                    for(var i in callbacksLogout)
                    {
                        var funcError = callbacksLogout[i];
                        funcError(params.response);
                    }
                }

                if(name == 'loginRequest')
                {
                    if(authIdentity.isSuspended())
                        authIdentity.restore();

                    if(!authIdentity.has())
                        authIdentity.set(null, params.response.data);

                    authService.clearRequest();

                    var credentials = authService.getCredentials();
                    authStorage.setCredentials(credentials.username, credentials.password);

                    var callbacksLogin = authService.getCallbacks('login.successful');
                    for(var j in callbacksLogin)
                    {
                        var funcSuccessful = callbacksLogin[j];
                        funcSuccessful(params.response);
                    }
                }
            }]
        },
        logoutRequest: {
            transitions: {
                401: 'loggedIn',
                201: 'waitingCredentials'
            },
            //Does the request to the server and save the promise
            action: ['authRequests', function(authRequests)
            {
                authRequests.signout();
            }]
        },
        failureLogin: {
            action: [
                'authService',
                'authIdentity',
                'params',
            function(authService, authIdentity, params)
            {
                authIdentity.clear();
                authService.clearCredentials();

                var callbacksLogin = authService.getCallbacks('login.limit');
                for(var j in callbacksLogin)
                {
                    var funcLimit = callbacksLogin[j];
                    funcLimit(params.response);
                }
            }]
        }
    });
}]);