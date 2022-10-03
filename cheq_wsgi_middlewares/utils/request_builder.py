from datetime import datetime
from http.cookies import SimpleCookie


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

    req_params['ApiKey'] = params['api_key']
    req_params['TagHash'] = params['tag_hash']
    req_params['EventType'] = params.get('rout_to_event_type', {}).get(request.path) or 'page_load'
    req_params['ClientIP'] = request.headers.get(params.get('trusted_ip_header', ''), None) or get_client_ip(request),
    req_params['RequestURL'] = request.url,
    req_params['ResourceType'] = params.get('resourceType', None) or 'text/html'
    req_params['Method'] = request.headers.environ['REQUEST_METHOD'],
    req_params['Host'] = request.headers.get('host', None),
    req_params['UserAgent'] = request.headers.get('user-agent', None),
    req_params['Accept'] = request.headers.get('accept', None),
    req_params['AcceptLanguage'] = request.headers.get('accept-language', None),
    req_params['AcceptEncoding'] = request.headers.get('accept-encoding', None),
    req_params['AcceptCharset'] = request.headers.get('accept-charset', None),
    req_params['HeaderNames'] = get_header_names(request.headers),
    req_params['CHEQ_COOKIE'] = cookie_parser(request.headers.get('Cookie', None))
    req_params['RequestTime'] = int(datetime.now().strftime("%Y%m%d%H%M%S")),
    req_params['XForwardedFor'] = request.headers.get('x-forwarded-for', None),
    req_params['Referer'] = request.headers.get('referer', None),
    req_params['Origin'] = request.headers.get('origin', None),
    req_params['XRequestedWith'] = request.headers.get('x-requested-with', None),
    req_params['Connection'] = request.headers.get('connection', None),
    req_params['Pragma'] = request.headers.get('pragma', None),
    req_params['CacheControl'] = request.headers.get('cache-control', None),
    req_params['ContentType'] = request.headers.get('content-type', None),
    req_params['TrueClientIP'] = request.headers.get('true-client-ip', None),
    req_params['XRealIP'] = request.headers.get('x-real-ip', None),
    req_params['Forwarded'] = request.headers.get('forwarded', None),
    req_params['JA3'] = params.get('get_ja3', none_func)(request),
    req_params['Channel'] = params.get('get_channel', none_func)(request),
    req_params['MiddlewareVersion'] = 'MiddlewareVersion'

    return req_params




'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9' \
'Accept-Language: en-US,en;q=0.9' \
'Cache-Control: no-cache' \
'Connection: keep-alive' \
'Cookie: _cheq_rti=Jn+lslBrK5oQwhKuNKScI7/Pu+s=VFZ3/ylvPRMzM5FTqC213V9Dp5kIjtjNb1691nBqi8nq4GJsYywlg2TIwVVWucndIDawpw69z5PrMvzamPsFhzMVzLTFlK6vQBL1JlkGh8OoJXPcTAPdrV0KX2lWhSQc' \
'Pragma: no-cache' \
'Sec-Fetch-Dest: document' \
'Sec-Fetch-Mode: navigate' \
'Sec-Fetch-Site: none' \
'Sec-Fetch-User: ?1' \
'Upgrade-Insecure-Requests: 1' \
'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.0.0 Safari/537.36' \
'client-ip: 109.226.44.241' \
'sec-ch-ua: "Chromium";v="104", " Not A;Brand";v="99", "Google Chrome";v="104"' \
'sec-ch-ua-mobile: ?0' \
'sec-ch-ua-platform: "macOS"' \
