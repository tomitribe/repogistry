export class TryMeService {
  static $inject = ['$http'];
  constructor(private $http) {
  }

  crypt(value) {
    return this.$http.post('api/try/crypt', {data: angular.toJson(value)}).then(d => d.data.data);
  }

  request(request) {
    return this.$http.post('api/try/invoke', request);
  }

  getOAuth2Header(request, ignoreSsl) {
    return this.$http.post('api/try/header/oauth2?ignore-ssl=' + (!!ignoreSsl ? 'true' : 'false'), request);
  }

  getSignatureHeader(request) {
    return this.$http.post('api/try/header/signature', request);
  }

  getBasicHeader(request) {
    return this.$http.post('api/try/header/basic', request);
  }
}
