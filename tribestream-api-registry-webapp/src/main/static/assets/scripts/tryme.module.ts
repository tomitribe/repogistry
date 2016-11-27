import {TryMeService} from './tryme.service.ts';
import {TryMeController} from './tryme.controller.ts';

angular.module('tribe-tryme', [
  'ngDialog', 'ngAnimate', 'vAccordion', 'ui.codemirror', 'ui.select',
  'tribe-widget-password', 'tribe-option-picker', 'tomitribe-dropdown' ])

  .service('TryMeService', ['$http', $http => new TryMeService($http)])

  .controller('TryMeController', [
    '$scope', '$routeParams', 'tribeEndpointsService', 'tribeLinkHeaderService', 'systemMessagesService', 'ngDialog', 'TryMeService',
    ($scope, $routeParams, tribeEndpointsService, tribeLinkHeaderService, systemMessagesService, ngDialog, TryMeService) =>
      new TryMeController($scope, $routeParams, tribeEndpointsService, tribeLinkHeaderService, systemMessagesService, ngDialog, TryMeService)])

  .config(['uiSelectConfig', function(uiSelectConfig) { uiSelectConfig.theme = 'selectize'; }]);
