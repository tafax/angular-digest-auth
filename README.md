#AngularJS HTTP Digest Authentication [![Build Status](https://travis-ci.org/tafax/angular-digest-auth.png?branch=master)](https://travis-ci.org/tafax/angular-digest-auth)
It is an AngularJS module to manage HTTP Digest Authentication. It provides basic functionality
to sign in and sign out. It automatically manages the synchronization between the client and the
server after the user did the login.

**NB:** *the module is under development and so some features or APIs can change.*

#Installation
You can download this by:
* Using bower and running `bower install angular-digest-auth --save` (recommended)
* Downloading manually the [unminified version](https://raw.github.com/tafax/angular-digest-auth/master/dist/angular-digest-auth.js) or
the [minified production version](https://raw.github.com/tafax/angular-digest-auth/master/dist/angular-digest-auth.min.js)

Import the module in your app.
````javascript
var app = angular.module('myApp', ['dgAuth']);
````

#Dependencies
This module depends on [angular](https://github.com/angular/angular.js), [angular-cookies](https://github.com/angular/bower-angular-cookies)
and [angular-md5](https://github.com/gdi2290/angular-md5).

#Configuration
You have to provide a few configurations in order to work.

###Login and logout
How to configure the urls to sing in and sign out.
````javascript
app.config(['authServiceProvider', function(authServiceProvider)
{
    authServiceProvider.setConfig({
        login: {
            method: 'POST',
            url: '/signin'
            ...
            //Other HTTP configurations.
        },
        logout: {
            method: 'POST',
            url: '/signout'
            ...
            //Other HTTP configurations.
        }
    });
}]);
````

###Header
How to configure the header to search server information.
````javascript
app.config(['authServerProvider', function(authServerProvider)
{
    authServerProvider.setHeader('Your-Header-For-Authentication');
}]);
````

###Calbacks
How to configure what happens at the user login and/or logout.
````javascript
app.config(['authServiceProvider', function(authServiceProvider)
{
    /**
     * You can add the callbacks to manage what happens after
     * successful of the login.
     */
    authServiceProvider.callbacks.login.push(['serviceInject', function(serviceInject)
    {
        return {
            successful: function(data)
            {
                //Your code to manage the login successful.
            },
            error: function(error)
            {
                //Your code to manage the login error.
            },
            required: function()
            {
                //Your code to manage the need for a login.
            }
        };
    }]);

    //This is the same for the logout.

    /**
     * You can add the callbacks to manage what happens after
     * successful of the logout.
     */
    authServiceProvider.callbacks.logout.push(['serviceInject', function(serviceInject)
    {
        return {
            successful: function(data)
            {
                //Your code to manage the logout successful.
            },
            error: function(error)
            {
                //Your code to manage the logout error.
            }
        };
    }]);
}]);
````

###Storage
By default, after the user has made the login, the credentials are stored in **sessionStorage** and the module
processes all further requests with this credentials. If you want the user is automatically reconnected when
he returns in your app, you can specify the **localStorage** as default storage.
````javascript
app.config(['authStorageProvider', 'authServiceProvider', function(authStorageProvider, authServiceProvider)
{
    /**
     * Tells to service that it can be reconnect the user
     * even if he has signed out or he has closed the browser.
     */
    authServiceProvider.setAutomatic(true);

    /**
     * Uses localStorage instead the sessionStorage.
     * The service can automatically reconnect the user
     * only with localStorage.
     */
    authStorageProvider.setStorage(localStorage);
}]);
````

Obviously, if you want to specify your own storage object, you can :).

#Usage
For basic usage, you can launch the `signin()` when your app goes run.
````javascript
app.run(['authService', function(authService)
{
    /**
     * It tries to sign in. If the service doesn't find
     * the credentials stored or the user is not signed in yet,
     * the service executes the required function.
     */
    authService.signin();
}]);
````

In your login controller you should provide the credentials submitted by user.
Then you have to sign in another time.
````javascript
$scope.submit = function(user)
{
    authService.setCredentials(user.username, user.password);
    authService.signin();
};
````

#Authorization
You can use a functionality of authService to authorize the user to navigate in your app.
````javascript
app.config(['$routeProvider', function($routeProvider)
{
    /**
     * Define the routing to the login.
     */
    $routeProvider.when('path/to/login', {...});

    /**
     * Use a variable in resolve to authorize the users.
     * The method 'isAuthenticated()' returns a promise
     * which you can use to validate the requests.
     */
    $routeProvider.when('some/path', {
        ...
        resolve: {
            auth: ['authService', '$q', '$location', function(authService, $q, $location)
            {
                var deferred = $q.defer();

                authService.isAuthenticated().then(function()
                {
                    deferred.resolve();
                },
                function()
                {
                    deferred.reject();
                    $location.path('path/to/login');
                });

                return deferred.promise;
            }]
        }
    });
}]);
````

#Events
You can use the events to handle the module environment.
````javascript
authentication: {
    headerNotFound: //After a login request no header has been found.
    header: //A valid header is found in server response.
    request: //After a login request a valid authentication request is found in the server response.
},
process: {
    request: //A request is processed by the module.
    response: //A response with status 401 is processed by the module.
},
login: {
    successful: //The login is successful.
    error: //The login responds with an error.
    required: //The login is required to access a functionality.
},
logout: {
    successful: //The logout is successful
    error: //The logout responds with an error.
},
credential: {
    submitted: //The new credentials are submitted.
    stored: //The credentials are stored in the auth storage.
    restored: //The credentials in the storage are restored.
}
````

Use the `authEvents` service to handle the events and do your own tasks. For example, with
`authEvents.getEvent('login.error')` you can handle if an error appears in the login procedure and
afterwards you can notify this error in your view to the user.
Also you can specify your events.
````javascript
app.config(['authEventsProvider', function(authEventsProvider)
{
    authEventsProvider.setEvents({
        authentication: {
            header: 'my_header_event'
        },
        credential: {
            restored: 'my_credential_event'
        }
        ...
    });
}]);
````

#License
[MIT](https://github.com/tafax/angular-digest-auth/blob/master/LICENSE)