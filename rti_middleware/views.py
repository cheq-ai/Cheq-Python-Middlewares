from django.shortcuts import render
from django.http import HttpResponse
from django.core.handlers.wsgi import WSGIRequest

from django.utils.decorators import decorator_from_middleware
from middlewares import rti

api_key = "62fdc812-be58-492f-9417-66a1f22b4da1"
tag_hash = "5f863bea211c957865e067b148f2471b"

rti_middleware = rti.RtiMiddleware('django', api_key, tag_hash, 'https://invalid-user.com', None, 'blocking')


# rti_decorator1 = decorator_from_middleware(rti_middleware.rti_decorator)
# api_key, tag_hash, redirect_url, callback, mode=rtiMode['BLOCKING'])


@rti_middleware.rti_decorator('page_load', WSGIRequest)
def hello_world(*args, **kwargs):
    return HttpResponse('Hello World')
