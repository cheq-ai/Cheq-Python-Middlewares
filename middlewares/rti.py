import types
import requests
import time
from functools import wraps
from flask import abort, redirect#, request
from http.cookies import SimpleCookie
frameworks = ['flask', 'django']
rtiMode = {
    'MONITORING': 'monitoring',
    'BLOCKING': 'blocking'
}

rti_actions = {
    'block_redirect': [2, 3, 6, 7, 10, 11, 16, 18],
    'captcha': [4, 5, 13, 14, 15, 17]
}


class RtiMiddleware:
    def __init__(self, framework, api_key, tag_hash, redirect_url, callback, mode=rtiMode['BLOCKING']):
        if framework not in frameworks:
            raise ValueError('framework is invalid, must be on of ' + ', '.join(frameworks))
        self.api_key = api_key
        self.tag_hash = tag_hash
        self.mode = mode
        self.redirect_url = redirect_url
        self.callback = callback
        self.framework = framework

    def rti_decorator(self, event_type, request_handler):
        def _rti_decorator(f):
            @wraps(f)
            def __rti_decorator(*args, **kwargs):
                try:
                    request_params = None
                    if self.framework == 'django':
                        request = args[0]
                        request_params = dict(request.headers)
                        request_params['HeaderNames'] = ','.join(dict(request.headers).keys())
                        request_params['Client-IP'] = request.META.get('REMOTE_ADDR', None)
                        request_params['Method'] = request.META.get('REQUEST_METHOD', None)
                        request_params['Remote-Addr'] = request.META.get('REMOTE_ADDR', None)
                        request_params['CheqCookie'] = cookie_parser(request_params.get('Cookie', None))
                        request_params['RequestURL'] = request.build_absolute_uri()
                    else:
                        request_params = dict(request_handler.headers.to_wsgi_list())
                        request_params['HeaderNames'] = ','.join(dict(request_handler.headers).keys())
                        request_params['Client-IP'] = request_handler.remote_addr
                        request_params['Method'] = request_handler.method
                        request_params['Remote-Addr'] = request_handler.remote_addr
                        request_params['CheqCookie'] = cookie_parser(request_params.get('Cookie', None))
                        request_params['RequestURL'] = request_handler.url

                    params = rti_request_builder(request_params, event_type, self.api_key, self.tag_hash)
                    rti_response = get_rti_response(params)

                    if rti_response is None or rti_response['threatTypeCode'] is None or not isinstance(
                            rti_response['isInvalid'], bool) or self.mode == rtiMode['MONITORING']:
                        return f(*args, **kwargs)

                    if rti_response['threatTypeCode'] in rti_actions['block_redirect'] and \
                            rti_response['isInvalid'] and self.mode == rtiMode['BLOCKING']:
                        if self.redirect_url is not None:
                            return redirect(self.redirect_url)
                        else:
                            return abort(403)
                    if rti_response['threatTypeCode'] in rti_actions['captcha'] and rti_response['isInvalid'] and \
                            self.mode == rtiMode['BLOCKING'] and isinstance(self.callback, types.FunctionType):
                        return self.callback(*args, **kwargs)
                    else:
                        return f(*args, **kwargs)
                except Exception as e:
                    return f(*args, **kwargs)

            return __rti_decorator

        return _rti_decorator


def rti_request_builder(headers, event_type, api_key, tag_hash, channel='', ja3=''):
    x = 1

    predefined_params = {
        'ApiKey': api_key,
        'TagHash': tag_hash,
        'EventType': event_type,
        'RequestTime': time.time(),
        'JA3': ja3,
        'Channel': channel,
    }

    prams = [
        ['ClientIP', 'Client-IP'],
        ['ResourceType', 'Resource-Type'],
        ['Method', 'Method'],
        ['UserAgent', 'User-Agent'],
        ['Accept', 'Accept'],
        ['AcceptLanguage', 'Accept-Language'],
        ['AcceptCharset', 'Accept-Charset'],
        ['XForwardedFor', 'X-Forwarded-For'],
        ['Referer', 'REFERER'],
        ['Origin', 'Origin'],
        ['XRequestedWith', 'X-Requested-With'],
        ['Connection', 'Connection'],
        ['Pragma', 'Pragma'],
        ['CacheControl', 'Cache-Control'],
        ['ContentType', 'Content-Type'],
        ['TrueClientIP', 'True-Client-Ip'],
        ['RemoteAddr', 'Remote-Addr'],
        ['XRealIP', 'X-Real-IP'],
        ['Forwarded', 'Forwarded'],
        ['CheqCookie', 'CheqCookie'],
        ['Host', 'Host'],
        ['RequestURL', 'RequestURL'],
        ['HeaderNames', 'HeaderNames']
    ]

    for p in prams:
        val = headers.get(p[1], None)
        if val:
            predefined_params[p[0]] = val

    return predefined_params


def get_rti_response(params={}):
    URL = "https://obstaging.cheqzone.com/v1/realtime-interception"

    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    r = None
    try:
        res = requests.post(URL, params, headers, timeout=5.001)
        if res:
            r = res.json() # TODO SET TIMEOUT BEFORE PUBLISH
    except Exception as e:
        print(e)

    return r


def cookie_parser(cookie):
    c = SimpleCookie()
    c.load(cookie)
    cheq_cookie = c.get('_cheq_rti', None)
    if cheq_cookie:
        return cheq_cookie.value
    return None
