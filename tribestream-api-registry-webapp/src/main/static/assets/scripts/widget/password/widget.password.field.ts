export class TribePassword {
  restrict = 'A';
  template = require('./widget.password.field.pug');
  scope = {
      value: "=value",
      placeholder: "@"
  };
  controller = ['$scope', function ($scope) {
    $scope.types = ['password', 'text'];
    $scope.type = $scope.types[0];
    $scope.showPassword = false;

    $scope.showPasswordHandler = () => {
        $scope.showPassword = !$scope.showPassword;
        $scope.type = $scope.showPassword ? $scope.types[1] : $scope.types[0];
    }
  }];
}
