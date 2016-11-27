import {TribePassword} from './widget.password.field';

angular.module('tribe-option-picker', [])
  .directive('tribePasswordField', [() => new TribePassword()]);
