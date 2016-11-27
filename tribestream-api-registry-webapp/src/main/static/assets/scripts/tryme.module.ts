import {TryMeService} from './tryme.service.ts';
import {TryMeController} from './tryme.controller.ts';

angular.module('tribe-tryme', [
  'ui.codemirror', 'ui.select',
  'tribe-widget-password', 'tribe-option-picker', 'tomitribe-dropdown' ])

  .service('TryMeService', ['$http', $http => new TryMeService($http)])

  .controller('TryMeController', TryMeController)

  .config(['uiSelectConfig', function(uiSelectConfig) { uiSelectConfig.theme = 'selectize'; }]);
