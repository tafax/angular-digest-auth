#AngularJS HTTP Digest Authentication
[![Build Status](https://travis-ci.org/tafax/angular-digest-auth.png?branch=master)](https://travis-ci.org/tafax/angular-digest-auth)
[![Bitdeli Badge](https://d2weczhvl823v0.cloudfront.net/tafax/angular-digest-auth/trend.png)](https://bitdeli.com/free "Bitdeli Badge")

It is an AngularJS module to manage [HTTP Digest Authentication](http://en.wikipedia.org/wiki/Digest_access_authentication) in the REST API web apps.
It provides functionality to avoid the default form of browsers and use your own. The login and logout are based on digest access authentication
and the module helps to manage the user identity in the client side.
You can use this module in order to protect your app and authorize the user to navigate inside it.

#Features
* Using your own login and logout
* Interceptor to pass the authorization in all further requests after the login
* Protection for login with a limitation for the number of requests
* Storage for reusing credentials
* Managing identity with `authIdentity` service
* Authorization checking as promise with `dgAuthService`
* Custom header to parse server information(realm, opaque, domain, etc...)
* Custom callbacks to handle all authorization states(login successful, login error, login required, etc...)

#Installation
You can download this by:
* Using bower and running `bower install angular-digest-auth --save` (recommended)
* Using npm: `npm install tafax/angular-digest-auth`
* Downloading manually the [unminified version](https://raw.github.com/tafax/angular-digest-auth/master/dist/angular-digest-auth.js) or
the [minified production version](https://raw.github.com/tafax/angular-digest-auth/master/dist/angular-digest-auth.min.js)

After installation, import the module in your app.
````javascript
var app = angular.module('myApp', ['dgAuth']);
````

#Dependencies
This module depends on [angular](https://github.com/angular/angular.js), [angular-state-machine](https://github.com/tafax/angular-state-machine)
and [angular-md5](https://github.com/gdi2290/angular-md5).

#Configuration
You need to configure the module as follows.

###Login and logout
You need to provide two URLs on your webserver to simulate the login and
the logout in your app. The `signin` URL should return the user identity in a JSON response.
You can access this information via the `authIdentity` service.
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
How to configure the header to parse server information. 

There is no good non-intrusive method for disabling the custom browser
pop-up at the time of writing.  See for example these Stack Overflow
questions:

* [How can I supress the browser's authentication dialog?](https://stackoverflow.com/questions/86105)
* [How to prevent browser to invoke basic auth popup and handle 401 error using Jquery?](https://stackoverflow.com/questions/9859627)

The solution assumed here is that web server sends a custom
alternative to the WWW-Authenticate header in order to avoid the
browser opening the default authentication dialog. For example,
X-WWW-Authenticate. The value should be the same as it would be for
WWW-Authenticate.
````javascript
app.config(['dgAuthServiceProvider', function(dgAuthServiceProvider)
{
    /**
     * Specifies the header to look for server information.
     * The header you have used in the server side.
     */
    dgAuthServiceProvider.setHeader('Your-Header-For-Authentication');
}]);
````

Note, for more general interoperation, the server could be configured
to send this alternative header only if it sees the following header
in the request, which is usally sent by default in AJAX calls.

    X-Requested-With: XMLHttpRequest

This way, HTTP-Digest works as normal on non-AJAX clients.

AngularJS as of v1.3.0 [needs to be instructed to include this](http://www.nabito.net/angularjs-http-not-sending-x-requested-with-header/)
as follows:

    myAppModule.config(['$httpProvider', function($httpProvider) {
        $httpProvider.defaults.headers.common["X-Requested-With"] = 'XMLHttpRequest';
    }]);

###Limit
Configure the maximum number requests to sign in as in the example below. When the limit is exceeded,
the `limit` method in the configured callbacks is invoked. The default limit is 4.
N.B.: the limit includes the initial request to sign in following the invocation of the `start` method.
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

###Callbacks
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
By default, after the user has logged in, the credentials are stored in `sessionStorage` and the module
processes all further requests with these credentials. If you want these user credentials
to persist for more than a single visit to your app, you can specify the `localStorage` as default storage.
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
For basic usage, you can launch the `start()` when your app runs.
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

You should provide the credentials to submit on behalf of the user in your login controller.
Then you have to sign in again.
````javascript
$scope.submit = function(user)
{
    dgAuthService.setCredentials(user.username, user.password);
    dgAuthService.signin();
};
````

If the login is successful, all further requests for the API in the domain specified by the server header,
will contain the credentials to authorize the user.

#Authorization
You can use this functionality of `dgAuthService` to authorize the user to navigate in your app.
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

