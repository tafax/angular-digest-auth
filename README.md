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
This module depends on [angular](https://github.com/angular/angular.js), [angular-cookies](https://github.com/angular/bower-angular-cookies)
and [angular-md5](https://github.com/gdi2290/angular-md5).

#Configuration
How to configure the urls to sing in and sign out.
````javascript
app.config(['$authConfigProvider', function($authConfigProvider)
{
    $authConfigProvider.setSign({
        signin: '/path/to/signin',
        signin: '/path/to/signout'
    });
}]);
````
How to configure the header to search server information.
````javascript
app.config(['$authConfigProvider', function($authConfigProvider)
{
    $authConfigProvider.setSign({
        signin: '/path/to/signin',
        signin: '/path/to/signout'
    });

    $authConfigProvider.setHeader('X-Header-For-Authentication');
}]);
````

By default, after the user has made the login, the credentials are stored in **sessionStorage** and the module
processes all further requests with this credentials. If you want the user is reconnected when he returns in your
app, you can specify the **localStorage** as default storage.
````javascript
app.config(['$authStorageProvider', function($authStorageProvider)
{
    $authStorageProvider.setStorage(localStorage);
}]);
````

Obviously, if you want to specify your own storage object, you can :).

#Usage
For basic usage, you can launch the `signin()` when your app goes run. Then, you can handle two events: `signin.required`
and `signin.successful`.
````javascript
app.run(['$authConfig', '$authService', function($authConfig, $authService)
{
    $authService.signin();

    $authService.$on($authConfig.getEvent('signin.required'), function(event)
    {
        //Redirect user to your login page. Ex: $location.path('/path/to/login');
    });

    $authService.$on($authConfig.getEvent('signin.successful'), function(event, data)
    {
        //Redirect user to you home page. Ex: $location.path('/path/to/home');
    });
}]);
````

In your login controller you should provide the credentials submitted by user.
````javascript
$scope.submit = function(user)
{
    $authService.setRequest(user.username, user.password);
};
````

After this, the service performs a login again without doing any more.

#Events
The module uses several events to provide its functionality. You can use the list of all events to handle
the module environment.
````javascript
authentication: {
    header: //A valid header is found in server response
},
process: {
    request: //A request is processed by the module
    response: //A response with status 401 is processed by the module
},
signin: {
    successful: //The login is successful
    error: //The login is incorrect
    required: //The login is required to access a functionality
},
signout: {
    successful: //The logout is successful
    error: //The logout is in error
},
credential: {
    submitted: //The new credentials are submitted
    stored: //The credentials are stored in the auth storage
    restored: //The credentials in the storage are restore
}
````

You can use the `$authConfig` service to handle the events and do your own tasks. For example, with
`$authConfig.getEvent('signin.error')` you can handle if an error appears in the login procedure and
afterwards you can notify this error in your view to the user.
Also you can specify your events.
````javascript
app.config(['$authConfigProvider', function($authConfigProvider)
{
    $authConfigProvider.setEvents({
        authentication: {
            header: 'my_header_event'
        },
        credential: {
            restored: 'my_credential_event'
        }
    });
}]);
````

#License
[MIT](https://github.com/tafax/angular-digest-auth/blob/master/LICENSE)