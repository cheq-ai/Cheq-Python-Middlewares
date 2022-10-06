import types
from werkzeug.wrappers import Request
from cheq_rti_wsgi_middleware.constants.rti_constants import rti_mode, api_endpoints, invalid_default_block_redirect_codes, invalid_default_captcha_codes
from cheq_rti_wsgi_middleware.utils.request_builder import rti_request_builder
from cheq_rti_wsgi_middleware.constants import errors
from cheq_rti_wsgi_middleware.utils.logger import RtiLogger
import requests
import re


def is_valid_uris(uris):
    if not isinstance(uris, list):
        return False
    else:
        for uri in uris:
            if type(uri) is not str and not isinstance(re.compile(uri), re.Pattern):
                return False
    return True


class RtiMiddleware(object):
    def __init__(self, options):
        if not options:
            raise Exception(errors.MISSING_RTI_OPTIONS)

        app = options.get('app', None)
        if not options.get('app', None):
            raise Exception(errors.MISSING_WSGI_APP)

        api_key = options.get('api_key', None)
        if not options.get('api_key', None):
            raise Exception(errors.MISSING_API_KEY)

        tag_hash = options.get('tag_hash', None)
        if not options.get('tag_hash', None):
            raise Exception(errors.MISSING_TAG_HASH)

        api_endpoint = options.get('api_endpoint', None)
        if not api_endpoint or api_endpoint not in api_endpoints:
            raise Exception(errors.MISSING_API_ENDPOINT)

        mode = options.get('mode', None)
        if not mode or (mode != rti_mode['MONITORING'] and mode != rti_mode['BLOCKING']):
            options['mode'] = rti_mode['MONITORING']

        uri_exclusion = options.get('uri_exclusion', None)
        if not uri_exclusion:
            options['uri_exclusion'] = []
        elif not is_valid_uris(uri_exclusion):
            raise Exception(errors.INVALID_URI_EXCLUSION_LIST)

        invalid_block_redirect_codes = options.get('invalid_block_redirect_codes', invalid_default_block_redirect_codes)
        invalid_captcha_codes = options.get('invalid_captcha_codes', invalid_default_captcha_codes)

        if not isinstance(invalid_block_redirect_codes, list) or \
                not all(isinstance(code, int) for code in invalid_block_redirect_codes) or \
                not isinstance(invalid_captcha_codes, list) or \
                not all(isinstance(code, int) for code in invalid_captcha_codes):
            raise Exception(errors.INVALID_THREAT_CODE_LIST)
        if any(any(captcha_code == block_redirect_code for captcha_code in invalid_captcha_codes) \
               for block_redirect_code in invalid_block_redirect_codes):
            raise Exception(errors.DUPLICATE_THREAT_CODE)

        self.prams = {
            'app': app,
            'api_key': api_key,
            'tag_hash': tag_hash,
            'mode': mode,
            'uri_exclusion': [],
            'api_endpoint': api_endpoint,
            'redirect_url': options.get('redirect_url', None),
            'callback': options.get('callback', None),
            'route_to_event_type': options.get('rout_to_event_type', dict()),
            'invalid_block_redirect_codes': invalid_block_redirect_codes,
            'invalid_captcha_codes': invalid_captcha_codes,
            'trusted_ip_header': options.get('trusted_ip_header', ''),
            'get_ja3': options.get('get_ja3', None),
            'get_resource_type': options.get('get_resource_type', None),
            'timeout': options.get('timeout', None),
            'get_channel': options.get('get_channel', None),

        }

        self.logger = RtiLogger(api_key, tag_hash)

    def __call__(self, environ, start_response):
        self.logger.info('incoming request', 'tests')
        app = self.prams.get('app')
        request = Request(environ)
        req_prams = rti_request_builder(request, self.prams)
        custom_start_response = start_response

        if should_skip_route(request.path, self.prams.get('uri_exclusion')):
            return app(environ, start_response)

        try:
            def set_cookie(cookie):
                def set_cookie_start_response(status, headers, exc_info=None):
                    headers.append(('Set-Cookie', cookie))
                    return start_response(status, headers, exc_info)
                return set_cookie_start_response

            res = requests.post(f"{self.prams.get('api_endpoint')}/v1/realtime-interception",
                                req_prams, headers={'Content-Type': 'application/x-www-form-urlencoded'})
            rti_response = res.json()

            if rti_response is None or rti_response.get('threatTypeCode', None) is None or not isinstance(
                    rti_response['isInvalid'], bool) or not rti_response['isInvalid'] or self.prams['mode'] == rti_mode['MONITORING']:
                return app(environ, start_response)

            cookie = rti_response.get('setCookie', None)
            if cookie:
                custom_start_response = set_cookie(cookie)

            threat_type_code = rti_response.get('threatTypeCode', None)
            is_invalid = rti_response.get('isInvalid', None)
            invalid_captcha_codes = self.prams.get('invalid_default_captcha_codes', [])
            invalid_block_redirect_codes = self.prams.get('invalid_block_redirect_codes', [])
            callback = self.prams.get('callback', None)
            redirect_url = self.prams.get('redirect_url', None)

            if threat_type_code in invalid_block_redirect_codes and is_invalid:
                if redirect_url is not None:
                    return start_response('302', [('Location', self.prams.get('redirect_url'))])
                else:
                    return start_response('403')

            if threat_type_code in invalid_captcha_codes and isinstance(callback, types.FunctionType):
                return callback(app, environ, custom_start_response)
        except Exception as e:
            self.logger.error('rti', e.msg)
            pass
        return app(environ, custom_start_response)


def should_skip_route(path, uri_exclusion):
    if path in uri_exclusion:
        return True
    else:
        return False

