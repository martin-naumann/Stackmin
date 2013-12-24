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

function InstanceCtrl($scope, $rootScope, apiSvc) {
  $rootScope.$on("connect", function() {
    apiSvc.loadRunningInstances().then(function(apiResult) {
      console.log(apiResult);
      $scope.instances = apiResult.virtualmachine;
    });
  });

  $scope.showVM = function(id) {
    for(var i=0;i<$scope.instances.length;i++) {
      if($scope.instances[i].id == id) {
        $scope.vmInfo = $scope.instances[i];
        break;
      }
    }
  }
}