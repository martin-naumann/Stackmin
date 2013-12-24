var Cloudmin = angular.module("Cloudmin", []);

Cloudmin.factory("apiSvc", function($rootScope, $q) {
  var self = {};
  var apiClient = null;

  //TODO refactor this into a generic load<stuff> function wrapper    
  self.loadTemplates = function() {
    var async = $q.defer();
    apiClient.exec("listTemplates", {templatefilter: "executable"}, function(err, res) {
      $rootScope.$apply(function() {
        console.log(err, res);
        async.resolve(res.template);
      });
    });
    return async.promise;
  };

  //TODO refactor this into a generic load<stuff> function wrapper
  self.loadZones = function() {
    var async = $q.defer();
    apiClient.exec("listZones", {}, function(err, res) {
      $rootScope.$apply(function() {
        console.log(err, res);
        async.resolve(res.zone);
      });
    });
    return async.promise;
  };

  //TODO refactor this into a generic load<stuff> function wrapper
  self.loadServices = function() {
    var async = $q.defer();
    apiClient.exec("listServiceOfferings", {}, function(err, res) {
      $rootScope.$apply(function() {
        console.log(err, res);
        async.resolve(res.serviceoffering);
      });
    });
    return async.promise;
  };

  //TODO refactor this into a generic load<stuff> function wrapper
  self.loadNetworks = function() {
    var async = $q.defer();
    apiClient.exec("listNetworks", {}, function(err, res) {
      $rootScope.$apply(function() {
        console.log(err, res);
        async.resolve(res.network);
      });
    });
    return async.promise;
  };
    
  self.loadRunningInstances = function() {
    var async = $q.defer();
    
    apiClient.exec("listVirtualMachines", {state: "Running"}, function(err, res) {
      $rootScope.$apply(function() {
        console.log(err, res);
        async.resolve(res);
      });
    });    
      
    return async.promise;
  };
    
  self.connect = function(url, key, secret) {
    connectAPI(url, key, secret, function(result) {
      apiClient = result;
      $rootScope.$emit("connect");
    });
  };   

  return self;
});

Cloudmin.factory("settingsSvc", function($q, $rootScope) {
  var self = {};

  self.getConnectionSettings = function() {
    var async = $q.defer();

    chrome.storage.local.get("apiConnectionSettings", function(config) {
      $rootScope.$apply(function() {
        async.resolve(config.apiConnectionSettings);
      });
    });

    return async.promise;
  };

  self.storeConnectionSettings = function(settings) {
    chrome.storage.local.set({apiConnectionSettings: settings}, function() { console.log("Result", chrome.runtime.lastError); });
  };

  return self;
});