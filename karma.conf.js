// Karma configuration
// Generated on Sat Jan 11 2014 13:56:03 GMT+0100 (CET)

module.exports = function(config) {
  config.set({

    // base path, that will be used to resolve files and exclude
    basePath: '',


    // frameworks to use
    frameworks: ['jasmine'],


    // list of files / patterns to load in the browser
    files: [
      'lib/angular/angular.js',
      'lib/angular-mocks/angular-mocks.js',
      'lib/angular-md5/angular-md5.js',
      'lib/angular-state-machine/src/angular-state-machine.js',
      'lib/angular-state-machine/src/services/state-machine.js',
      'src/angular-digest-auth.js',
      'src/config/config-module.js',
      'src/config/config-state-machine.js',
      'src/services/dg-auth-service.js',
      'src/services/auth-client.js',
      'src/services/auth-identity.js',
      'src/services/auth-server.js',
      'src/services/auth-service.js',
      'src/services/auth-requests.js',
      'src/services/auth-storage.js',
      'tests/**/*Spec.js'
    ],


    // list of files to exclude
    exclude: [
      
    ],


    // test results reporter to use
    // possible values: 'dots', 'progress', 'junit', 'growl', 'coverage'
    reporters: ['progress'],


    // web server port
    port: 9876,


    // enable / disable colors in the output (reporters and logs)
    colors: true,


    // level of logging
    // possible values: config.LOG_DISABLE || config.LOG_ERROR || config.LOG_WARN || config.LOG_INFO || config.LOG_DEBUG
    logLevel: config.LOG_INFO,


    // enable / disable watching file and executing tests whenever any file changes
    autoWatch: true,


    // Start these browsers, currently available:
    // - Chrome
    // - ChromeCanary
    // - Firefox
    // - Opera (has to be installed with `npm install karma-opera-launcher`)
    // - Safari (only Mac; has to be installed with `npm install karma-safari-launcher`)
    // - PhantomJS
    // - IE (only Windows; has to be installed with `npm install karma-ie-launcher`)
    browsers: ['Chrome', 'Firefox', 'Opera'],


    // If browser does not capture in given timeout [ms], kill it
    captureTimeout: 60000,


    // Continuous Integration mode
    // if true, it capture browsers, run tests and exit
    singleRun: false
  });
};
