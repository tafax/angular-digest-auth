describe('angular-digest-auth', function()
{
    var $authStorage;
    var $authConfig;
    var $authService;
    var $httpBackend;
    var $rootScope;

    beforeEach(angular.mock.module('dgAuth'));

    beforeEach(function()
    {
        var fakeModule = angular.module('test.config', []);
        fakeModule.config(['$authConfigProvider', function($authConfigProvider)
        {
            $authConfigProvider.setSign({
                signin: '/signin'
            });

            $authConfigProvider.setHeader('X-Auth-Digest');
        }]);

        module('dgAuth', 'test.config');

        inject(function($injector)
        {
            $authConfig = $injector.get('$authConfig');
            $authService = $injector.get('$authService');
            $rootScope = $injector.get('$rootScope');
            spyOn($rootScope, '$broadcast').andCallThrough();

            $authStorage = $injector.get('$authStorage');
            $authStorage.clear();

            $httpBackend = $injector.get('$httpBackend');
            $httpBackend.whenPOST($authConfig.getSign().signin).respond(function(method, url, data, headers)
            {
                return [401, "", headers];
            });
        });
    });

    afterEach(function()
    {
        $httpBackend.verifyNoOutstandingExpectation();
        $httpBackend.verifyNoOutstandingRequest();
    });

    describe('ALL', function()
    {
        it('performs the first sign in', function()
        {
            $authService.signin();

            expect($rootScope.$broadcast).toHaveBeenCalledWith('$authRequestSignin', jasmine.any(Object));
            //expect($rootScope.$broadcast).toHaveBeenCalledWith($authConfig.getEvent('authentication.header'), jasmine.any(Object));

            $httpBackend.expectPOST($authConfig.getSign().signin);
            $httpBackend.flush();
        });
    });
});