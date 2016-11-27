export class TribeOptionPicker {
  constructor(private $document, private $timeout) {
  }

  restrict = 'A';
  template = require('./widget.option.picker.pug');
  scope = {
      options: '=',
      changeCallback: '&'
  };
  controller = ['$scope', function ($scope) {
    $scope.onClick = opt => {
      if (!!opt.invoke) {
        opt.invoke();
      }
    }
  }];
  link = function (scope, el) {
      let valueDiv = el.find('.list');
      let clear = () => {
          valueDiv.removeClass('visible');
      };
      let elWin = angular.element(this.$document);
      el.on('click', () => {
          if (valueDiv.hasClass('visible')) {
              valueDiv.removeClass('visible');
              elWin.off('click', clear);
          } else {
              valueDiv.addClass('visible');
              this.$timeout(() => elWin.one('click', clear));
          }
      });
      scope.$on('$destroy', () => elWin.off('click', clear));
  };
}
