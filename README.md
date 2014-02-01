#AngularJS HTTP Digest Authentication [![Build Status](https://travis-ci.org/tafax/angular-digest-auth.png?branch=master)](https://travis-ci.org/tafax/angular-digest-auth)
It is an AngularJS module to manage HTTP Digest Authentication. It provides basic functionality
to sign in and sign out. It automatically manages the synchronization between the client and the
server after the user did the login.

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
This module depends on [angular](https://github.com/angular/angular.js), [angular-state-machine](https://github.com/tafax/angular-state-machine)
and [angular-md5](https://github.com/gdi2290/angular-md5).

#Configuration
You have to provide a few configurations in order to work.

###Login and logout
How to configure the urls to sing in and sign out.
````javascript
app.config(['dgAuthServiceProvider', function(dgAuthServiceProvider)
{
    dgAuthServiceProvider.setConfig({
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
app.config(['dgAuthServiceProvider', function(dgAuthServiceProvider)
{
    dgAuthServiceProvider.setHeader('Your-Header-For-Authentication');
}]);
````

###Limit
How to configure the limit of number requests to sign in. When the limit is exceeded
`limit` of login callbacks is invoked. The default limit is 4.
N.B.: the limit includes the request to sign in place during the invocation of the `start` method.
````javascript
app.config(['dgAuthServiceProvider', function(dgAuthServiceProvider)
{
    /**
     * Sets the limit to 5 requests.
     * 4 requests after the invocation of start method.
     */
    dgAuthServiceProvider.setLimit(5);

    /**
     * Sets the limit of requests to infinite.
     */
    dgAuthServiceProvider.setLimit('inf');
}]);
````

###Calbacks
How to configure what happens at the user login and/or logout.
````javascript
app.config(['dgAuthServiceProvider', function(dgAuthServiceProvider)
{
    /**
     * You can add the callbacks to manage what happens after
     * successful of the login.
     */
    dgAuthServiceProvider.callbacks.login.push(['serviceInject', function(serviceInject)
    {
        return {
            successful: function(response)
            {
                //Your code...
            },
            error: function(response)
            {
                //Your code...
            },
            required: function(response)
            {
                //Your code...
            },
            limit: function(response)
            {
                //Your code...
            }
        };
    }]);

    //This is the same for the logout.

    /**
     * You can add the callbacks to manage what happens after
     * successful of the logout.
     */
    dgAuthServiceProvider.callbacks.logout.push(['serviceInject', function(serviceInject)
    {
        return {
            successful: function(response)
            {
                //Your code...
            },
            error: function(response)
            {
                //Your code...
            }
        };
    }]);
}]);
````

###Storage
By default, after the user has made the login, the credentials are stored in `sessionStorage` and the module
processes all further requests with this credentials. If you want to restore the user credentials when
he returns in your app, you can specify the `localStorage` as default storage.
````javascript
app.config(['dgAuthServiceProvider', function(dgAuthServiceProvider)
{
    /**
     * Uses localStorage instead the sessionStorage.
     */
    dgAuthServiceProvider.setStorage(localStorage);
}]);
````

Obviously, if you want to specify your own storage object, you can :).

#Usage
For basic usage, you can launch the `start()` when your app goes run.
````javascript
app.run(['dgAuthService', function(dgAuthService)
{
    /**
     * It tries to sign in. If the service doesn't find
     * the credentials stored or the user is not signed in yet,
     * the service executes the required function.
     */
    dgAuthService.start();
}]);
````

In your login controller you should provide the credentials submitted by user.
Then you have to sign in another time.
````javascript
$scope.submit = function(user)
{
    dgAuthService.setCredentials(user.username, user.password);
    dgAuthService.signin();
};
````

#Authorization
You can use a functionality of dgAuthService to authorize the user to navigate in your app.
````javascript
app.config(['$routeProvider', function($routeProvider)
{
    /**
     * Use a variable in resolve to authorize the users.
     * The method 'isAuthorized()' returns a promise
     * which you can use to authorize the requests.
     */
    $routeProvider.when('some/path', {
        ...
        resolve: {
            auth: ['dgAuthService', '$q', '$location', function(dgAuthService, $q, $location)
            {
                var deferred = $q.defer();

                dgAuthService.isAuthorized().then(function(authorized)
                {
                    if(authorized)
                        deferred.resolve();
                    else
                        deferred.reject();
                },
                function(authorized)
                {
                    deferred.reject();
                });

                return deferred.promise;
            }]
        }
    });
}]);
````

#License
[MIT](https://github.com/tafax/angular-digest-auth/blob/master/LICENSE)

[![Bitdeli Badge](https://d2weczhvl823v0.cloudfront.net/tafax/angular-digest-auth/trend.png)](https://bitdeli.com/free "Bitdeli Badge")

