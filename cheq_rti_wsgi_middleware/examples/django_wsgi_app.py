from django.core.wsgi import get_wsgi_application
from cheq_rti_wsgi_middleware.RtiWsgiMiddleware import RtiMiddleware
import os

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "hellodjango.settings")
application = get_wsgi_application()

options = {
    'app': application,
    'api_key': "62fdc812-be58-492f-9417-66a1f22b4da1",
    'tag_hash': "5f863bea211c957865e067b148f2471b",
    'api_endpoint': 'https://rti-us-east-1.cheqzone.com',
    'route_to_event_type': dict(),
    'mode': 'blocking',
    'uri_exclusion': [],
    'invalid_block_redirect_codes': [],
    'invalid_captcha_codes': [],
    'trusted_ip_header': 'Client-Ip'

}


application = RtiMiddleware(options)
