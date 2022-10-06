# cheq-rti-wsgi-middleware
CHEQ Real Time Interception middleware for Python 3 wsgi application



## Features

* [Installation](#installation)
* [Real time interception](#real-time-interception)
    * [Required configuration](#required-configuration)
        * [API key](#api-key)
        * [Tag hash](#tag-hash)
        * [API endpoint](#api-endpoint)
    * [Optional configuration](#optional-configuration)
        * [Mode](#mode)
        * [Event Type](#event-type)
        * [Threat type codes](#threat-type-codes)
        * [Redirect URL](#redirect-url)
        * [Callback function](#callback-function)
        * [Ja3](#ja3)
        * [Resource type](#resource-type)
        * [IP header](#ip-header)
        * [URI Exclusion](#uri-exclusion)
        * [Timeout](#timeout)
        * [Custom event name](#custom-event-name)
    * [Usage example](#usage-example)
        * [Flask](#flask)
        * [Django](#django)
   


## Installation
````bash
$ pip install cheq-rti-wsgi-middleware
````

## Real time interception

Real-Time Interception (RTI) supports API calls to provide detection of invalid traffic (IVT) to your site, in absolute real-time.  RTI will intercept IVT to prevent invalid visitors from harming your conversion efforts.

### Configuration

#### Required configuration

##### API key

Available on the Paradome platform under “Management -> RTI”

```` python
options = {
    ...
    'api_key': '11abc111-aa11-11aa-1111-11a11a11111'
    ...
}
````

##### Tag hash

Appears in your CHEQ tag. 

```` python
options = {
    ...
    'tag_hash': 'c99651e7936e27743ce51c728492aac9'
    ...
}
````

##### API endpoint
The nearest API endpoint to your server. Must be the same region as your tag domain.<br>Select the appropriate endpoint:
- US: https://rti-us-east-1.cheqzone.com
- EU: https://rti-eu-west-1.cheqzone.com

```` python
options = {
    ...
    'api_endpoint': 'https://rti-eu-west1.cheqzone.com'
    ...
}
````

#### Optional configuration

##### Mode

- `monitoring` - Will not perform any action

- `blocking` - Will block Invalid traffic or redirect them to a different url (defind in [Redirect URL](#redirect-url)).

The default value will be `monitoring`.

```` python
options = {
    ...
    'mode': 'blocking'
    ...
}
````

##### Event type

- `route_to_event_type` - A dictionary of routes as keys and cheq event type as value.<br> Default `page_load` will be used as event type   

```` python
options = {
    ...
    'route_to_event_type': {
        '/': 'page_load',
        '/subscribe': 'subscribe',
        .....
        .....
    }
    ...
}
````

##### Threat type codes

Threat types are devided to two groups:

1. Block/Redirect - traffic detected as threat types in this group would be blocked or redirected to a different page (defind in [Redirect URL](#redirect-url).<br>
        Default threat type codes for this group:  2,3,6,7,10,11,16,18.
        
2. Captcha - threat type codes in this group would be reffered to [Callback function](#callback-function). <br>
        Default threat type codes for this group:  4,5,13,14,15,17.
Threat type must be unique for each list. 

```` python
options = {
    ...
    'invalid_block_redirect_codes': [2, 3, 6, 7, 10, 11, 16, 18],
    'invalid_captcha_codes': [4, 5, 13, 14, 15, 17]
    ...
};
````
##### Redirect URL

A URL you would like to redirect invalid users to. 

If it is empty the response will be status code 403 and the user will be blocked.

```` python
options = {
    ...
     'redirect_url': 'https://invalid-user.com'
    ...
}
````

##### Callback function

A custom callback option, for instance to redirect to captcha page.
If it is empty, will use start_response to route.

```` python
def callback(app, environ, start_response):
     #do somthing or call app(environ, start_response)
     
options = {
    ...
     'callback': callback 
    ...
}
````
##### Ja3

Recommended - A function that extracts ja3 fingerprint from the request.<br>
SSL/TLS client fingerprints

```` python
from urllib.parse import urlparse
from urllib.parse import parse_qs

def get_ja3(request):
        parsed_url = urlparse(reuest.url)
        captured_value = parse_qs(parsed_url.query)['ja3'][0] 
options = {
    ... 
    'get_ja3': get_ja3
    ...
}
````
##### Resource type

A function to get the response content-type header. 

This is recommended to improve detection.

```` python
def get_resource_type(request):
    if request.headers.environ['REQUEST_METHOD'] == 'POST'):
        return 'application/json'
    elif request.pth == '/':
        return 'text/html'

options = {
  ...
  'get_resource_type': get_resource_type
  ...
}
````

##### IP header

Specify a trusted IP header to be used as client IP
```` python
options = {
  ...
  'trusted_ip_header': 'client-ip'
  ...
};
````

##### URI Exclusion

An array of regular expressions or path that will be excluded

```` python
options = {
  ...
  'uri_exclusion': ['/about', '/careers']
  ...
};
````


##### Timeout

Optional timeout in milliseconds, if absent value will be set to 100 milliseconds.

```` python
options = {
    ...
     'timeout': 1000 // one second
    ...
}
````

##### Custom event name

In case a custom event name is used, this function extracts the name of the custom event.<br> 

```` python
from urllib.parse import urlparse
from urllib.parse import parse_qs

def get_channel(request):
        parsed_url = urlparse(reuest.url)
        captured_value = parse_qs(parsed_url.query)['channel'][0] 
options = {
    ...
     'get_channel': get_channel
    ...
}
````



### Usage example

##### Flask
```` python
from flask import Flask
from cheq_wsgi_middlewares.RtiWsgiMiddleware import RtiMiddleware

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
    return "Hello World"


if __name__ == '__main__':
    app.run('0.0.0.0', 8080)
````
##### Django
```` python
from django.core.wsgi import get_wsgi_application
from cheq_wsgi_middlewares.RtiWsgiMiddleware import RtiMiddleware
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

````

