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

function DeployCtrl($scope, $rootScope, apiSvc, notificationSvc) {
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

  $scope.createVm = function() {
    $scope.deploying = true;
    apiSvc.createVm($scope.service, $scope.template, $scope.zone, $scope.network).then(function success() {
      notificationSvc.notifySuccess("VM started", "VM " + id + " was successfully started!");
      $scope.deploying = false;
    }, function failure() {
      notificationSvc.notifyFailure("ERROR", "VM " + id + " couldn't be started!");
      $scope.deploying = false;
    });
  }
}

function InstanceCtrl($scope, $rootScope, apiSvc, notificationSvc) {
  $scope.msg = "";

  var refreshInstanceList = function() {
    apiSvc.loadInstances().then(function(apiResult) {
      console.log(apiResult);
      $scope.instances = apiResult.virtualmachine;
    });
  };

  $rootScope.$on("connect", function() {
    refreshInstanceList();
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
    $scope.msg = "Starting VM...";
    apiSvc.startVm(id).then(function success() {
      notificationSvc.notifySuccess("VM started", "VM " + id + " was successfully started!");
      $scope.msg = "";
      refreshInstanceList();
    }, function failure() {
      notificationSvc.notifyFailure("ERROR", "VM " + id + " couldn't be started!");
      $scope.msg = "";
    });
  };

  $scope.stopVm = function(id) {
    $scope.msg = "Stopping VM...";
    apiSvc.stopVm(id).then(function success() {
      notificationSvc.notifySuccess("VM stopped", "VM " + id + " was successfully stopped!");
      $scope.msg = "";
      refreshInstanceList();
    }, function failure() {
      notificationSvc.notifyFailure("ERROR", "VM " + id + " couldn't be stopped!");
      $scope.msg = "";
    });
  };

  $scope.rebootVm = function(id) {
    $scope.msg = "Rebooting VM...";
    apiSvc.startVm(id).then(function success() {
      notificationSvc.notifySuccess("VM rebooted", "VM " + id + " was successfully rebooted!");
      $scope.msg = "";
      refreshInstanceList();
    }, function failure() {
      notificationSvc.notifyFailure("ERROR", "VM " + id + " couldn't be rebooted!");
      $scope.msg = "";
    });
  };

  $scope.deleteVm = function(id) {
    $scope.msg = "Deleting VM...";
    apiSvc.destroyVm(id).then(function success() {
      notificationSvc.notifySuccess("VM deleted", "VM " + id + " was successfully deleted!");
      $scope.msg = "";
      refreshInstanceList();
    }, function failure() {
      notificationSvc.notifyFailure("ERROR", "VM " + id + " couldn't be deleted!");
      $scope.msg = "";
    });
  };
}