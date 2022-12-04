from flask import Flask
from cheq_rti_wsgi_middleware.RtiWsgiMiddleware import RtiMiddleware

api_key = "62fdc812-be58-492f-9417-66a1f22b4da1"
tag_hash = "5f863bea211c957865e067b148f2471b"
app = Flask(__name__)


options = {
    'app': app.wsgi_app,
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


app.wsgi_app = RtiMiddleware(options)


@app.route("/")
def index():
    return "Hello this is the new version!"


if __name__ == '__main__':
    app.run('0.0.0.0', 8080)
