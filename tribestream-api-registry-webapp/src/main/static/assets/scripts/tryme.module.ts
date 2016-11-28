import {TryMeService} from './tryme.service.ts';
import {TryMeController} from './tryme.controller.ts';

angular.module('tribe-tryme', [
  'ui.codemirror', 'ui.select',
  'tomitribe-button', 'tomitribe-dropdown', 'tomitribe-fab',
  'tribe-widget-password', 'tribe-option-picker'
]).service('TryMeService', TryMeService)
  .controller('TryMeController', TryMeController)
  // should be moved to be global but not yet the case
  .config(['uiSelectConfig', function(uiSelectConfig) { uiSelectConfig.theme = 'selectize'; }]);
