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
            action: ['authStorage', 'object', function(authStorage, object)
            {
                if(authStorage.hasCredentials())
                {
                    object.credentials = {
                        username: authStorage.getUsername(),
                        password: authStorage.getPassword()
                    };
                }

                return object;
            }]
        },
        settingCredentials: {
            transitions: {
                signin: 'loginRequest'
            },
            //Sets the credentials as candidate
            action: ['authService', 'object', function(authService, object)
            {
                if(object.hasOwnProperty('credentials'))
                {
                    var credentials = object.credentials;
                    authService.setCredentials(credentials.username, credentials.password);
                }
            }]
        },
        loginRequest: {
            transitions: {
                //Checks if the credentials are present(loginError) or not(waitingCredentials)
                401: [{
                    to: 'waitingCredentials',
                    predicate: ['authService', function(authService)
                    {
                        return !authService.hasCredentials();
                    }]
                },
                {
                    to: 'loginError',
                    predicate: ['authService', function(authService)
                    {
                        return authService.hasCredentials();
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
            action: ['authService', 'response', function(authService, response)
            {
                authService.clearCredentials();
                var callbacks = authService.getCallbacks('login.error');
                for(var i in callbacks)
                {
                    var callback = callbacks[i];
                    callback(response);
                }
            }]
        },
        waitingCredentials: {
            transitions: {
                submitted: 'settingCredentials'
            },
            //Checks the previous state and notify the credential need
            action: ['authService', 'authIdentity', 'name', 'response', function(authService, authIdentity, name, response)
            {
                if(name == 'logoutRequest')
                {
                    authIdentity.clear();
                    var callbacks = authService.getCallbacks('logout.successful');
                    for(var i in callbacks)
                    {
                        var callback = callbacks[i];
                        callback(response);
                    }
                }

                authService.clearCredentials();
                callbacks = authService.getCallbacks('login.request');
                for(var j in callbacks)
                {
                    var func = callbacks[j];
                    func(response);
                }
            }]
        },
        loggedIn: {
            transitions: {
                signout: 'logoutRequest'
            },
            //Checks the previous state and creates the identity and notify the login successful
            action: ['authService', 'authIdentity', 'name', 'response', function(authService, authIdentity, name, response)
            {
                if(name == 'logoutRequest')
                {
                    var callbacksLogout = authService.getCallbacks('logout.error');
                    for(var i in callbacksLogout)
                    {
                        var funcError = callbacksLogout[i];
                        funcError(response);
                    }
                }

                if(name == 'loginRequest')
                {
                    authIdentity.set(null, response.data);

                    var callbacksLogin = authService.getCallbacks('login.successful');
                    for(var j in callbacksLogin)
                    {
                        var funcSuccessful = callbacksLogin[j];
                        funcSuccessful(response);
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
        }
    });
}]);
