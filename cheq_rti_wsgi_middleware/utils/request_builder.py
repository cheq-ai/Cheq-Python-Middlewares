from datetime import datetime
from http.cookies import SimpleCookie
import pkg_resources


def cookie_parser(cookie):
    if not cookie:
        return None
    c = SimpleCookie()
    c.load(cookie)
    cheq_cookie = c.get('_cheq_rti', None)
    if cheq_cookie:
        return cheq_cookie.value
    return None


def get_client_ip(request):
    try:
        return request.environ['HTTP_X_FORWARDED_FOR'].split(',')[-1].strip()
    except KeyError:
        return request.environ['REMOTE_ADDR']


def get_header_names(headers):
    headers_names = []
    for h in str(headers).splitlines():
        headers_names.append(h.split(':')[0])
    return ','.join(headers_names)


def none_func(request):
    return None


def rti_request_builder(request, params):
    req_params = dict()

    get_resource_type = params.get('get_resource_type', none_func) or none_func
    get_ja3 = params.get('get_ja3', none_func) or none_func
    get_channel = params.get('get_channel', none_func) or none_func

    req_params['EventType'] = params.get('route_to_event_type', {}).get(request.path, None) or 'page_load'
    req_params['ApiKey'] = params['api_key']
    req_params['TagHash'] = params['tag_hash']
    req_params['ResourceType'] = get_resource_type(request) or 'text/html'
    req_params['CheqCookie'] = cookie_parser(request.headers.get('Cookie', None))
    req_params['Method'] = request.headers.environ['REQUEST_METHOD'],
    req_params['ClientIP'] = request.headers.get(params.get('trusted_ip_header', ''), None) or get_client_ip(request),
    req_params['RequestURL'] = request.url,
    req_params['RequestTime'] = int(datetime.now().strftime("%Y%m%d%H%M%S")),
    req_params['HeaderNames'] = get_header_names(request.headers),
    req_params['Host'] = request.headers.get('host', None),
    req_params['UserAgent'] = request.headers.get('user-agent', None),
    req_params['XForwardedFor'] = request.headers.get('x-forwarded-for', None),
    req_params['Referer'] = request.headers.get('referer', None),
    req_params['Accept'] = request.headers.get('accept', None),
    req_params['AcceptEncoding'] = request.headers.get('accept-encoding', None),
    req_params['AcceptLanguage'] = request.headers.get('accept-language', None),
    req_params['AcceptCharset'] = request.headers.get('accept-charset', None),
    req_params['Origin'] = request.headers.get('origin', None),
    req_params['XRequestedWith'] = request.headers.get('x-requested-with', None),
    req_params['Connection'] = request.headers.get('connection', None),
    req_params['Pragma'] = request.headers.get('pragma', None),
    req_params['CacheControl'] = request.headers.get('cache-control', None),
    req_params['ContentType'] = request.headers.get('content-type', None),
    req_params['TrueClientIP'] = request.headers.get('true-client-ip', None),
    req_params['XRealIP'] = request.headers.get('x-real-ip', None),
    req_params['RemoteAddr'] = request.headers.get('remote-addr', None),
    req_params['Forwarded'] = request.headers.get('forwarded', None),
    req_params['JA3'] = get_ja3(request),
    req_params['Channel'] = get_channel(request),
    req_params['MiddlewareVersion'] = f"python_{pkg_resources.require('cheq-rti-wsgi-middleware')[0].version}"

    return req_params

