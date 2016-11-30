import {TryMeService} from './tryme.service';

export class TryMeController {
  static $inject = [
    '$rootScope','$scope', '$routeParams', '$window', '$timeout',
    'tribeEndpointsService', 'tribeLinkHeaderService', 'systemMessagesService',
    'TryMeService' ,'currentAuthProvider'
  ];
  constructor(private $rootScope,
              private $scope,
              private $routeParams,
              private $window,
              private $timeout,
              private tribeEndpointsService,
              private tribeLinkHeaderService,
              private systemMessagesService,
              private tryMeService: TryMeService,
              private currentAuthProvider) {
    $scope.endpoint = { httpMethod:  '', path: '', operation: {} };
    $scope.endpointUrlInfo = {
        applicationName: $routeParams.application,
        verb: $routeParams.verb,
        endpointPath: $routeParams.endpoint,
        version: $routeParams.version
    };

    $scope.signatureAlgorithmOptions = [
      'hmac-sha1', 'hmac-sha224', 'hmac-sha256', 'hmac-sha384', 'hmac-sha512',
      'rsa-sha1', 'rsa-sha256', 'rsa-sha384', 'rsa-sha512',
      'dsa-sha1', 'dsa-sha224', 'dsa-sha256'
    ];
    $scope.digestOptions = ['md2', 'md4', 'md5', 'sha-1', 'sha-224', 'sha-256', 'sha-384', 'sha-512'];

    $scope.onPickerSelect = value => {
      if (!!value.invoke) {
        value.invoke();
      }
    };

    $scope.stopScenarioExecution = () => {
      console.log("Going to spot execution");

      this.$scope.request.scenario.$$executionHandler && this.$scope.request.scenario.$$executionHandler();

      this.$scope.request.scenario.$$executing = false;
    };

    $scope.removeHeader = h => {
      this.$scope.headers = this.$scope.headers.filter(i => i.name != h.name);
    };
    $scope.removePathParameter = p => {
      this.$scope.pathParameters = this.$scope.pathParameters.filter(i => i.name != p.name);
    };
    $scope.removeQueryParameter = p => {
      this.$scope.queryParameters = this.$scope.queryParameters.filter(i => i.name != p.name);
    };

    $scope.onHeaderChange = (name, header) => {
      if (!name) {
        if (!!header.$$proposals) {
          header.$$proposals = [];
        }
        return;
      }
      if ((name == 'Content-Type' || name == 'Accept') && !header.$$proposals) {
        header.$$proposals = ['application/json', 'application/xml', 'application/x-www-form-urlencoded', 'text/plain'];
      } else if (name == 'Date' && !header.$$proposals) {
        header.$$proposals = [new Date().toUTCString()];
      } else if (!!header.$$proposals) {
        header.$$proposals = [];
      }
    };

    this.$scope.tryIt = () => {
      this.$scope.request.scenario.$$executing = true;
      // convert headers, better than watching it which would be slow for no real reason
      this.$scope.request.headers = this.$scope.headers.filter(h => !!h.name && !!h.value).reduce((accumulator, e) => {
        accumulator[e.name] = e.value;
        return accumulator;
      }, {});

      this.$scope.request.signature.headers = this.$scope.headers.filter(h => !!h.$$useForSignature && !!h.name).map(h => h.name);
      if (!!this.$scope.request.signature.$$requestTarget && this.$scope.request.signature.headers.indexOf('(request-target)') < 0) {
        this.$scope.request.signature.headers.push('(request-target)');
      }
      if (!!this.$scope.request.oauth2.$$useForSignature) {
        this.$scope.request.signature.headers.push(this.$scope.request.oauth2.header);
      }
      if (!!this.$scope.request.basic.$$useForSignature) {
        this.$scope.request.signature.headers.push(this.$scope.request.basic.header);
      }
      if (!!this.$scope.request.digest.$$useForSignature) {
        this.$scope.request.signature.headers.push(this.$scope.request.digest.header);
      }

      // cleanup scenario model to enable duration case (GUI can have messed it up) and potentially convert duration to a parseable value
      if (!!this.$scope.request.scenario.$$useDuration) {
        this.$scope.request.scenario.invocations = -1;
        this.$scope.request.scenario.duration = (this.$scope.request.scenario.$$durationTime || '1') + ' ' + (this.$scope.request.scenario.$$durationUnit || 'seconds');
      } else {
        this.$scope.request.scenario.duration = undefined;
      }

      // reset response for new invocation
      this.$scope.response = undefined;
      this.$scope.responseStream = undefined;

      // check it is a scenario or a simple call
      if (this.$scope.request.scenario && (this.$scope.request.scenario.threads > 1 || (!!this.$scope.request.scenario.duration && this.$scope.request.scenario.$$useDuration) || this.$scope.request.scenario.invocations > 1)) {
        if(!window['EventSource']) {
          systemMessagesService.error('No Server Send Event support, use a browser support it please.');
          return;
        }
        this.$scope.responseStream = this.$scope.responseStream || {items:[], $$scrollOnOutput: true};

        currentAuthProvider.get().getAuthorizationHeader().then(header => {
          tryMeService.crypt({http:this.$scope.request, identity:header}).then(d => {
            let source = new window['EventSource']('api/try/invoke/stream?request=' + d);
            const onDone = () => {
              this.$scope.request.scenario.$$executionHandler = undefined;
              source.close();
              this.$scope.responseStream.finished = true;
              tryMeService.crypt({data:this.$scope.responseStream.items, identity:header}).then(d => {
                this.$scope.responseStream.csvLink = this.$rootScope.baseFullPath + 'api/try/download?output-type=csv' +
                    '&filename=' + encodeURIComponent(this.$scope.endpointUrlInfo.verb + '_' +
                        this.$scope.endpointUrlInfo.endpointPath
                          .replace(' ', '').replace(':', '')
                          .replace('{', '').replace('}', '')
                          .replace('/', '_') + '_' +
                        (this.$scope.endpointUrlInfo.version || '')) +
                    '&data=' + d;
              });
            };
            this.$scope.request.scenario.$$executionHandler = onDone;
            source.onerror = error => {
              onDone();
              this.$scope.$apply(() => systemMessagesService.error(JSON.stringify(error)));
            };
            source.onmessage = event => {
                this.$scope.$apply(() => {
                  const object = JSON.parse(event.data);
                  if (!!object.total) { // done, we don't use "event" to define the type cause of the number of messages we can get
                    this.$scope.responseStream.stats = object;
                    this.$scope.responseStream.stats.$$countPerStatusArray = Object.keys(object.countPerStatus || {})
                      .map(k => {
                        return {status: k, count: object.countPerStatus[k]};
                      });
                    onDone();
                  } else {
                    this.$scope.responseStream.items.push(object);
                    if (this.$scope.responseStream.$$scrollOnOutput) {
                      this.$timeout(() => $window.scrollTo(0, $window.innerHeight));
                    }
                  }
                });
            };
          });
        });
      } else {
        tryMeService.request(this.$scope.request)
          .success(result => {
            this.$scope.request.scenario.$$executing = false;
            this.$scope.response = result;
            this.$scope.response.payloadOptions = this.$scope.payloadOptions;
            this.$scope.response.statusDescription = this.statusDescription(result.status);
            this.$scope.response.headers = Object.keys(this.$scope.response.headers).map(key => {
               return {name: key, value: this.$scope.response.headers[key]};
            });
          })
          .error(err => this.systemMessagesService.error('Can\'t execute the request, check the information please'));
      }
    };

    $scope.mainMenuOptions = [{
      displayName: 'Invoke',
      icon: 'fa-bolt',
      invoke: () => this.$scope.tryIt()
    }, {
      displayName: 'Invoke & Download',
      icon: 'fa-cloud-download',
      invoke: () => {
        alert('TODO: not yet implemented');
      }
    }, {
      displayName: 'Import & Share',
      icon: 'fa-cloud-upload',
      invoke: () => {
        alert('TODO: not yet implemented');
      }
    }];

    $scope.menuOptions = [{
      displayName: 'Add OAuth 2.0',
      invoke: () => this.$scope.request.oauth2.$$show = true
    }, {
      displayName: 'Add HTTP Signature',
      invoke: () => {
        this.$scope.request.signature = {
          header: 'Authorization',
          headers: ['(request-target)'],
          algorithm: 'hmac-sha256',
          $$show: true,
          $$requestTarget: true
        };
      }
    }, {
      displayName: 'Add Basic Auth',
      invoke: () => this.$scope.request.basic.$$show = true
    }, {
      displayName: 'Add Digest',
      invoke: () => this.$scope.request.digest.$$show = true
    }, {
      displayName: 'Add Scenario Configuration',
      invoke: () => this.$scope.request.scenario.$$show = true
    }, {
      // separator
    }, {
      displayName: 'Save As',
      invoke: () => {
        alert('TODO: not yet done');
      }
    }, {
      displayName: 'Save result',
      invoke: () => {
        alert('TODO: not yet done');
      }
    }, {
      displayName: 'Update Samples',
      invoke: () => {
        alert('TODO: not yet done');
      }
    }];
    $scope.oauth2Options = [{
      displayName: 'Resource Owner',
      invoke: () => this.$scope.request.oauth2.$$resourceOwner = true
    }, {
      displayName: 'Client Credentials',
      invoke: () => this.$scope.request.oauth2.$$client = true
    }, {
      displayName: 'Force Token Type',
      invoke: () => {
        this.$scope.request.oauth2.$$tokenType = true;
        this.$scope.request.oauth2.tokenType = 'Bearer';
      }
    }];
    $scope.parametersOptions = [{
      displayName: 'Add Header',
      invoke: () => this.$scope.headers.push({})
    }, {
      displayName: 'Add Path Parameter',
      invoke: () => this.$scope.pathParameters.push({})
    }, {
      displayName: 'Add Query Parameter',
      invoke: () => this.$scope.queryParameters.push({})
    }];

    $scope.removeOAuth2Client = () => {
      this.$scope.request.oauth2.$$client=false;
      this.$scope.request.oauth2.clientId = undefined;
      this.$scope.request.oauth2.clientSecret = undefined;
    };
    $scope.removeOAuth2ResourceOwner = () => {
      this.$scope.request.oauth2.$$resourceOwner=false;
      this.$scope.request.oauth2.username = undefined;
      this.$scope.request.oauth2.password = undefined;
    };
    $scope.removeOAuth2TokenType = () => {
      this.$scope.request.oauth2.$$tokenType = false;
      this.$scope.request.oauth2.tokenType = undefined;
    };
    $scope.removeOAuth2 = () => {
      this.$scope.request.oauth2.$$show = false;
      this.$scope.request.oauth2.endpoint = undefined;
      this.$scope.removeOAuth2Client();
      this.$scope.removeOAuth2ResourceOwner();
    };
    $scope.removeSignature = () => {
      this.$scope.request.signature.alias = undefined;
      this.$scope.request.signature.$$show = false;
      this.$scope.request.signature.secret = undefined;
    };
    $scope.removeBasic = () => {
      this.$scope.request.basic.$$show = false;
      this.$scope.request.basic.username = undefined;
      this.$scope.request.basic.password = undefined;
    };
    $scope.removeDigest = () => {
      this.$scope.request.digest.$$show = false;
      this.$scope.request.digest.algorithm = undefined;
    };
    $scope.removeScenario = () => {
      this.$scope.request.scenario.$$show = false;
      this.$scope.request.scenario.$$useDuration = false;
      // should we reset the values?
      this.$scope.request.scenario.threads = 1;
      this.$scope.request.scenario.iterations = 1;
      this.$scope.request.scenario.duration = undefined;
      this.$scope.request.scenario.$$executing = false;
    };

    tribeEndpointsService.getDetailsFromMetadata($scope.endpointUrlInfo).then(detailsResponse => {
        const detailsData = detailsResponse['data'];
        this.$scope.endpoint = {
          httpMethod:  detailsData['httpMethod'],
          path: detailsData.path,
          operation: detailsData.operation
        };

        tribeEndpointsService.getApplicationDetails(tribeLinkHeaderService.parseLinkHeader(detailsData.operation['x-tribestream-api-registry'].links).application)
          .then(applicationDetails => {
            this.$scope.application = applicationDetails['data'];
            this.init();
          });
      });
  }

  private init() {
    const swagger = this.$scope.application.swagger;
    const url = (swagger.schemes && swagger.schemes.length ? swagger.schemes[0] || 'http' : 'http') + '://' +
                    swagger.host + (swagger.basePath === '/' ? '' : swagger.basePath) + this.$scope.endpoint.path;
    const parameters = ((this.$scope.endpoint.operation || {}).parameters || {});
    const querySample = parameters.filter(p => p['in'] === 'query' && !!p['name'])
      .reduce((acc, param) => acc + (!!acc ? '&' : '?') + param['name'] + '=' + this.sampleValue(param['type']), '');

    // should we check parameters for a Body? this is rarely done actually
    const payload = this.$scope.endpoint.httpMethod === 'post' || this.$scope.endpoint.httpMethod === 'put' ? '{}' : undefined;

    this.$scope.endpoint = this.$scope.endpoint;
    this.$scope.payloadOptions = {lineNumbers: true, mode: 'javascript'};
    this.$scope.request = {
      ignoreSsl: url.indexOf('https') == 0,
      method: this.$scope.endpoint.httpMethod.toUpperCase(),
      url: url + querySample,
      payload: payload,
      oauth2: {
        header: 'Authorization',
        grantType: 'password',
        endpoint: this.tryMeService.oauth2DefaultEndpoint,
        // for the ui
        $$show: false,
        $$resourceOwner: false,
        $$client: false
      },
      signature: {
        header: 'Authorization',
        algorithm: 'hmac-sha256',
        headers: ['(request-target)'],
        // ui
        $$show: false
      },
      basic: {
        header: 'Authorization',
        // ui
        $$show: false
      },
      digest: {
        header: 'Digest',
        // ui
        $$show: false
      },
      scenario: {
        threads: 1,
        iterations: 1,
        duration: undefined,
        // ui
        $$show: false,
        $$useDuration: false,
        $$durationUnit: 'seconds',
        $$executing: false
      },
      // ui
      $$forceBody: false
    };

    // we pre-fill all headers of the operation + accept/content-type if consumes/produces are there
    this.$scope.headers = parameters.filter(p => p['in'] === 'header' && !!p['name'])
      .filter(p => 'digest' !== (p['name'] || '').toLowerCase() && 'content-type' !== (p['name'] || '').toLowerCase() && 'accept' !== (p['name'] || '').toLowerCase())
      .map(p => {
        return { name: p['name'], value: this.sampleValue(p['type']), required: p.required || false, description: p.description, type: p.type };
      });
    const authMethods = ((this.$scope.endpoint.operation['x-tribestream-api-registry'] || {})['auth-methods'] || []).map(e => e.toLowerCase());
    if (authMethods.indexOf('http signatures') >= 0) {
      this.$scope.request.signature.$$show = true;
    }
    if (authMethods.indexOf('bearer') >= 0) {
      this.$scope.menuOptions[1].invoke();
    }
    if (authMethods.indexOf('basic') >= 0) {
      this.$scope.request.basic.$$show = true;
    }
    if (_.find(parameters, p => p['in'] === 'header' && (p['name'] || '').toLowerCase() === 'digest') || authMethods.indexOf('digest') >= 0) {
      this.$scope.request.digest.$$show = true;
    }
    if (this.$scope.endpoint.operation.consumes && this.$scope.endpoint.operation.consumes.length) {
      this.$scope.headers.push({ name: 'Content-Type', value: this.$scope.endpoint.operation.consumes[0], description: 'The payload mime type', type: 'string' });
    }
    if (this.$scope.endpoint.operation.produces && this.$scope.endpoint.operation.produces.length) {
      this.$scope.headers.push({ name: 'Accept', value: this.$scope.endpoint.operation.produces[0], description: 'The payload mime type', type: 'string' });
    }
    this.$scope.headerOptions = [];
    this.$scope.headers.forEach(h => this.$scope.headerOptions.push(h.name));
    [ 'Content-Type', 'Accept', 'Date' ].forEach(o => {
      if (undefined === _.find(this.$scope.headerOptions, i => i.toString().toLowerCase() == o.toLowerCase())) {
        this.$scope.headerOptions.push(o);
      }
    });

    this.$scope.queryParameters = parameters.filter(p => p['in'] === 'query' && !!p['name'])
      .map(p => {
        return { name: p['name'], value: this.sampleValue(p['type']), required: p.required || false, description: p.description, type: p.type };
      });
    this.$scope.queryParameterOptions = this.$scope.queryParameters.map(h => h.name);

    this.$scope.pathParameters = parameters.filter(p => p['in'] === 'path' && !!p['name'])
      .map(p => {
        return { name: p['name'], value: this.sampleValue(p['type']), required: p.required || false, description: p.description, type: p.type };
      });
    this.$scope.pathParameterOptions = this.$scope.pathParameters.map(h => h.name);

    ['queryParameters', 'pathParameters'].forEach(n => this.$scope.$watch(n, (newVal, oldVal) => this.recomputeUrl(url), true));
  }

  private recomputeUrl(url) {
    this.$scope.request.url = url;
    ['queryParameters', 'pathParameters'].forEach(n => {
      this.$scope[n].filter(p => !!p.name && !!p.value).forEach(p => {
        this.$scope.request.url = this.$scope.request.url
          .replace('{' + p.name + '}', p.value)
          .replace(':' + p.name, p.value)/*this one should be legacy*/;
      });
    });
    this.$scope.queryParameters.filter(p => !!p.name && !!p.value).forEach(p => { // add query params not in swagger
      if (this.$scope.request.url.indexOf('{' + p.name + '}') < 0 && this.$scope.request.url.indexOf(':' + p.name) < 0) {
        this.$scope.request.url = this.$scope.request.url + (this.$scope.request.url.indexOf('?') < 0 ? '?' : '&') + p.name + '=' + encodeURIComponent(p.value);
      }
    });
  };

  private sampleValue(type) {
    switch(type || 'string') {
      case 'boolean':
        return 'true';
      case 'integer':
      case 'long':
      case 'int32':
      case 'int64':
      case 'number':
        return '10';
      case 'float':
      case 'double':
        return '10.0';
      default:
        return 'value';
    }
  }

  private statusDescription(httpStatus) { // generated from wikipedia
    switch(httpStatus || -1) {
      case 200: return 'OK (Standard response for successful HTTP requests. The actual response will depend on the request method used. In a GET request, the response will contain an entity corresponding to the requested resource. In a POST request, the response will contain an entity describing or containing the result of the action.[7])';
      case 201: return 'Created (The request has been fulfilled, resulting in the creation of a new resource.[8])';
      case 202: return 'Accepted (The request has been accepted for processing, but the processing has not been completed. The request might or might not be eventually acted upon, and may be disallowed when processing occurs.[9])';
      case 203: return 'Non-Authoritative Information (since HTTP/1.1) (The server is a transforming proxy (e.g. a Web accelerator) that received a 200 OK from its origin, but is returning a modified version of the origin\'s response.[10][11])';
      case 204: return 'No Content (The server successfully processed the request and is not returning any content.[12])';
      case 205: return 'Reset Content (The server successfully processed the request, but is not returning any content. Unlike a 204 response, this response requires that the requester reset the document view.[13])';
      case 206: return 'Partial Content (RFC 7233) (The server is delivering only part of the resource (byte serving) due to a range header sent by the client. The range header is used by HTTP clients to enable resuming of interrupted downloads, or split a download into multiple simultaneous streams.[14])';
      case 207: return 'Multi-Status (WebDAV; RFC 4918) (The message body that follows is an XML message and can contain a number of separate response codes, depending on how many sub-requests were made.[15])';
      case 208: return 'Already Reported (WebDAV; RFC 5842) (The members of a DAV binding have already been enumerated in a previous reply to this request, and are not being included again.[16])';
      case 226: return 'IM Used (RFC 3229) (The server has fulfilled a request for the resource, and the response is a representation of the result of one or more instance-manipulations applied to the current instance.[17])';
      case 300: return 'Multiple Choices (Indicates multiple options for the resource from which the client may choose (via agent-driven content negotiation). For example, this code could be used to present multiple video format options, to list files with different filename extensions, or to suggest word-sense disambiguation.[19])';
      case 301: return 'Moved Permanently (This and all future requests should be directed to the given URI.[20])';
      case 302: return 'Found (This is an example of industry practice contradicting the standard. The HTTP/1.0 specification (RFC 1945) required the client to perform a temporary redirect (the original describing phrase was "Moved Temporarily"),[21] but popular browsers implemented 302 with the functionality of a 303 See Other. Therefore, HTTP/1.1 added status codes 303 and 307 to distinguish between the two behaviours.[22] However, some Web applications and frameworks use the 302 status code as if it were the 303.[23])';
      case 303: return 'See Other (since HTTP/1.1) (The response to the request can be found under another URI using a GET method. When received in response to a POST (or PUT/DELETE), the client should presume that the server has received the data and should issue a redirect with a separate GET message.[24])';
      case 304: return 'Not Modified (RFC 7232) (Indicates that the resource has not been modified since the version specified by the request headers If-Modified-Since or If-None-Match. In such case, there is no need to retransmit the resource since the client still has a previously-downloaded copy.[25])';
      case 305: return 'Use Proxy (since HTTP/1.1) (The requested resource is available only through a proxy, the address for which is provided in the response. Many HTTP clients (such as Mozilla[26] and Internet Explorer) do not correctly handle responses with this status code, primarily for security reasons.[27])';
      case 306: return 'Switch Proxy (No longer used. Originally meant "Subsequent requests should use the specified proxy."[28])';
      case 307: return 'Temporary Redirect (since HTTP/1.1) (In this case, the request should be repeated with another URI; however, future requests should still use the original URI. In contrast to how 302 was historically implemented, the request method is not allowed to be changed when reissuing the original request. For example, a POST request should be repeated using another POST request.[29])';
      case 308: return 'Permanent Redirect (RFC 7538) (The request and all future requests should be repeated using another URI. 307 and 308 parallel the behaviors of 302 and 301, but do not allow the HTTP method to change. So, for example, submitting a form to a permanently redirected resource may continue smoothly.[30])';
      case 400: return 'Bad Request (The server cannot or will not process the request due to an apparent client error (e.g., malformed request syntax, too large size, invalid request message framing, or deceptive request routing).[32])';
      case 401: return 'Unauthorized (RFC 7235) (Similar to 403 Forbidden, but specifically for use when authentication is required and has failed or has not yet been provided. The response must include a WWW-Authenticate header field containing a challenge applicable to the requested resource. See Basic access authentication and Digest access authentication.[33] 401 semantically means "unauthenticated",[34] i.e. the user does not have the necessary credentials.)';
      case 402: return 'Payment Required (Reserved for future use. The original intention was that this code might be used as part of some form of digital cash or micropayment scheme, but that has not happened, and this code is not usually used. Google Developers API uses this status if a particular developer has exceeded the daily limit on requests.[35])';
      case 403: return 'Forbidden (The request was a valid request, but the server is refusing to respond to it. The user might be logged in but does not have the necessary permissions for the resource.)';
      case 404: return 'Not Found (The requested resource could not be found but may be available in the future. Subsequent requests by the client are permissible.[36])';
      case 405: return 'Method Not Allowed (A request method is not supported for the requested resource; for example, a GET request on a form which requires data to be presented via POST, or a PUT request on a read-only resource.)';
      case 406: return 'Not Acceptable (The requested resource is capable of generating only content not acceptable according to the Accept headers sent in the request.[37] See Content negotiation.)';
      case 407: return 'Proxy Authentication Required (RFC 7235) (The client must first authenticate itself with the proxy.[38])';
      case 408: return 'Request Time-out (The server timed out waiting for the request. According to HTTP specifications: "The client did not produce a request within the time that the server was prepared to wait. The client MAY repeat the request without modifications at any later time."[39])';
      case 409: return 'Conflict (Indicates that the request could not be processed because of conflict in the request, such as an edit conflict between multiple simultaneous updates.)';
      case 410: return 'Gone (Indicates that the resource requested is no longer available and will not be available again. This should be used when a resource has been intentionally removed and the resource should be purged. Upon receiving a 410 status code, the client should not request the resource in the future. Clients such as search engines should remove the resource from their indices.[40] Most use cases do not require clients and search engines to purge the resource, and a "404 Not Found" may be used instead.)';
      case 411: return 'Length Required (The request did not specify the length of its content, which is required by the requested resource.[41])';
      case 412: return 'Precondition Failed (RFC 7232) (The server does not meet one of the preconditions that the requester put on the request.[42])';
      case 413: return 'Payload Too Large (RFC 7231) (The request is larger than the server is willing or able to process. Previously called "Request Entity Too Large".[43])';
      case 414: return 'URI Too Long (RFC 7231) (The URI provided was too long for the server to process. Often the result of too much data being encoded as a query-string of a GET request, in which case it should be converted to a POST request.[44] Called "Request-URI Too Long" previously.[45])';
      case 415: return 'Unsupported Media Type (The request entity has a media type which the server or resource does not support. For example, the client uploads an image as image/svg+xml, but the server requires that images use a different format.)';
      case 416: return 'Range Not Satisfiable (RFC 7233) (The client has asked for a portion of the file (byte serving), but the server cannot supply that portion. For example, if the client asked for a part of the file that lies beyond the end of the file.[46] Called "Requested Range Not Satisfiable" previously.[47])';
      case 417: return 'Expectation Failed (The server cannot meet the requirements of the Expect request-header field.[48])';
      case 418: return 'I\'m a teapot (RFC 2324) (This code was defined in 1998 as one of the traditional IETF April Fools\' jokes, in RFC 2324, Hyper Text Coffee Pot Control Protocol, and is not expected to be implemented by actual HTTP servers. The RFC specifies this code should be returned by teapots requested to brew coffee.[49] This HTTP status is used as an easter egg in some websites, including Google.com.[50])';
      case 421: return 'Misdirected Request (RFC 7540) (The request was directed at a server that is not able to produce a response (for example because a connection reuse).[51])';
      case 422: return 'Unprocessable Entity (WebDAV; RFC 4918) (The request was well-formed but was unable to be followed due to semantic errors.[15])';
      case 423: return 'Locked (WebDAV; RFC 4918) (The resource that is being accessed is locked.[15])';
      case 424: return 'Failed Dependency (WebDAV; RFC 4918) (The request failed due to failure of a previous request (e.g., a PROPPATCH).[15])';
      case 426: return 'Upgrade Required (The client should switch to a different protocol such as TLS/1.0, given in the Upgrade header field.[52])';
      case 428: return 'Precondition Required (RFC 6585) (The origin server requires the request to be conditional. Intended to prevent "the \'lost update\' problem, where a client GETs a resource\'s state, modifies it, and PUTs it back to the server, when meanwhile a third party has modified the state on the server, leading to a conflict."[53])';
      case 429: return 'Too Many Requests (RFC 6585) (The user has sent too many requests in a given amount of time. Intended for use with rate-limiting schemes.[53])';
      case 431: return 'Request Header Fields Too Large (RFC 6585) (The server is unwilling to process the request because either an individual header field, or all the header fields collectively, are too large.[53])';
      case 451: return 'Unavailable For Legal Reasons (A server operator has received a legal demand to deny access to a resource or to a set of resources that includes the requested resource.[54] The code 451 was chosen as a reference to the novel Fahrenheit 451.)';
      case 500: return 'Internal Server Error (A generic error message, given when an unexpected condition was encountered and no more specific message is suitable.[57])';
      case 501: return 'Not Implemented (The server either does not recognize the request method, or it lacks the ability to fulfill the request. Usually this implies future availability (e.g., a new feature of a web-service API).[citation needed])';
      case 502: return 'Bad Gateway (The server was acting as a gateway or proxy and received an invalid response from the upstream server.[58])';
      case 503: return 'Service Unavailable (The server is currently unavailable (because it is overloaded or down for maintenance). Generally, this is a temporary state.[59])';
      case 504: return 'Gateway Time-out (The server was acting as a gateway or proxy and did not receive a timely response from the upstream server.[60])';
      case 505: return 'HTTP Version Not Supported (The server does not support the HTTP protocol version used in the request.[61])';
      case 506: return 'Variant Also Negotiates (RFC 2295) (Transparent content negotiation for the request results in a circular reference.[62])';
      case 507: return 'Insufficient Storage (WebDAV; RFC 4918) (The server is unable to store the representation needed to complete the request.[15])';
      case 508: return 'Loop Detected (WebDAV; RFC 5842) (The server detected an infinite loop while processing the request (sent in lieu of 208 Already Reported).)';
      case 510: return 'Not Extended (RFC 2774) (Further extensions to the request are required for the server to fulfill it.[63])';
      case 511: return 'Network Authentication Required (RFC 6585) (The client needs to authenticate to gain network access. Intended for use by intercepting proxies used to control access to the network (e.g., "captive portals" used to require agreement to Terms of Service before granting full Internet access via a Wi-Fi hotspot).[53])';
      default:
        return 'unknown';
    }
  }
}
