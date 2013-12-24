function ConnectionCtrl($scope, $rootScope, apiSvc, settingsSvc) {
    
  settingsSvc.getConnectionSettings().then(function(settings) {
    $scope.connectionSettings = settings;
  });
    
  $scope.connect = function() {
    var connSettings = $scope.connectionSettings;
    settingsSvc.storeConnectionSettings(connSettings);
    apiSvc.connect(connSettings.url, connSettings.key, connSettings.secret);
  };
}

function DeployCtrl($scope, $rootScope, apiSvc) {
  $rootScope.$on("connect", function() {
    apiSvc.loadTemplates().then(function(templates) {
      console.log("Templates", templates);
      $scope.templates = templates;
    });
      
    apiSvc.loadZones().then(function(zones) {
      $scope.zones = zones;
    });
      
    apiSvc.loadNetworks().then(function(networks) {
      $scope.networks = networks;
    });

    apiSvc.loadServices().then(function(services) {
      $scope.services = services;
    });
      
  });
}

function InstanceCtrl($scope, $rootScope, apiSvc, notificationSvc) {
  $rootScope.$on("connect", function() {
    apiSvc.loadInstances().then(function(apiResult) {
      console.log(apiResult);
      $scope.instances = apiResult.virtualmachine;
    });
  });

  $scope.showVm = function(id) {
    console.log(id);
    for(var i=0;i<$scope.instances.length;i++) {
      if($scope.instances[i].id == id) {
        $scope.vmInfo = $scope.instances[i];
        break;
      }
    }
  };

  $scope.startVm = function(id) {
    apiSvc.startVm(id).then(function success() {
      notificationSvc.notifySuccess("VM started", "VM " + id + " was successfully started!");
    }, function failure() {
      notificationSvc.notifyFailure("ERROR", "VM " + id + " couldn't be started!");
    });
  };

  $scope.stopVm = function(id) {
    apiSvc.stopVm(id).then(function success() {
      notificationSvc.notifySuccess("VM stopped", "VM " + id + " was successfully stopped!");
    }, function failure() {
      notificationSvc.notifyFailure("ERROR", "VM " + id + " couldn't be stopped!");
    });
  };

  $scope.rebootVm = function(id) {
    apiSvc.startVm(id).then(function success() {
      notificationSvc.notifySuccess("VM rebooted", "VM " + id + " was successfully rebooted!");
    }, function failure() {
      notificationSvc.notifyFailure("ERROR", "VM " + id + " couldn't be rebooted!");
    });
  };

  $scope.deleteVm = function(id) {
    apiSvc.destroyVm(id).then(function success() {
      notificationSvc.notifySuccess("VM deleted", "VM " + id + " was successfully deleted!");
    }, function failure() {
      notificationSvc.notifyFailure("ERROR", "VM " + id + " couldn't be deleted!");
    });
  };
}