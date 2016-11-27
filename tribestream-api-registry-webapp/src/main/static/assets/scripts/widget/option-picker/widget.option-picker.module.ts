import {TribeOptionPicker} from './widget.option.picker';

angular.module('tribe-widget-password', [])
  .directive('tribeOptionPicker', ['$document', '$timeout', ($doc, $to) => new TribeOptionPicker($doc, $to)]);
