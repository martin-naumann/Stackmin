var Cloudmin = angular.module("Cloudmin", []);

Cloudmin.factory("apiSvc", function($rootScope, $q) {
  var self = {};
  var apiClient = null;

  var loadOptionsFromApi = function(whatToList, params) {
    var async = $q.defer();
    apiClient.exec("list" + whatToList, params || {}, function(err, res) {
      $rootScope.$apply(function() {
        console.log(err, res);
        async.resolve(res[whatToList.slice(0, -1).toLowerCase()]);
      });
    });
    return async.promise;
  }

  self.loadTemplates = function() {
    return loadOptionsFromApi("Templates", {templatefilter: "executable"});
  };

  self.loadZones = function() {
    return loadOptionsFromApi("Zones");
  };

  self.loadServices = function() {
    return loadOptionsFromApi("ServiceOfferings");
  };

  self.loadNetworks = function() {
    return loadOptionsFromApi("Networks");
  };

  self.loadInstances = function() {
    var async = $q.defer();

    apiClient.exec("listVirtualMachines", {}, function(err, res) {
      $rootScope.$apply(function() {
        console.log(err, res);
        async.resolve(res);
      });
    });    

    return async.promise;
  };

  var performAction = function(action, params, expectedTargetState) {
    var async = $q.defer();

    apiClient.exec(action + "VirtualMachine", params, function(err, res) {
      console.log(err, res);
      setTimeout(function queryJobState() {
        apiClient.exec("queryAsyncJobResult", {jobid: res.jobid}, function(err, jobState) {
          console.log(err, jobState);
          if(jobState.jobstatus == 0) {
            setTimeout(queryJobState, 1000);
          } else {
            $rootScope.$apply(function() {
              if(jobState.jobresult.virtualmachine.state == expectedTargetState) async.resolve();
              else async.reject();
            });
          }
        });
      }, 1000);
    });
    return async.promise;    
  };

  self.createVm = function(service, template, zone, network) {
    return performAction("deploy", {
      serviceofferingid: service,
      templateid: template,
      zoneid: zone,
      networkids: [network]
    }, "Running");
  };

  self.startVm = function(id) {
    return performAction("start", {id: id}, "Running");
  };

  self.rebootVm = function(id) {
    return performAction("reboot", {id: id}, "Running");
  };

  self.stopVm = function(id) {
    return performAction("stop", {id: id}, "Stopped");
  };

  self.destroyVm = function(id) {
    return performAction("destroy", {id: id}, "Destroyed");
  };
    
  self.connect = function(url, key, secret) {
    connectAPI(url, key, secret, function(result) {
      apiClient = result;
      $rootScope.$emit("connect");
    });
  };   

  return self;
});

Cloudmin.factory("notificationSvc", function() {
  var self = {};

  self.notifySuccess = function(title, msg) {
    chrome.notifications.create("", {type: "basic", title: "Yeha! " + title, message: msg, iconUrl: "icons/success.png"}, function() {});
  };

  self.notifyFailure = function(title, msg) {
    chrome.notifications.create("", {type: "basic", title: "Oh noes! " + title, message: msg, iconUrl: "icons/error.png"}, function() {});
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