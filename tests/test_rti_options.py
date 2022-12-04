import unittest

import pkg_resources
from werkzeug.testapp import test_app
from cheq_rti_wsgi_middleware.RtiWsgiMiddleware import RtiMiddleware
from cheq_rti_wsgi_middleware.constants import errors


class TestRtiOptions(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        super(TestRtiOptions, self).__init__(*args, **kwargs)
        self.base_options = {
            'app': test_app,
            'api_key': 'api_key',
            'tag_hash': 'tag_hash',
            'api_endpoint': 'https://rti-us-east-1.cheqzone.com',
            'mode': 'mode',
            'uri_exclusion': [],
            'invalid_block_redirect_codes': [],
            'invalid_captcha_codes': [],
            'redirect_url': 'https://invalid-user.com',
            'callback': 'callback',
            'route_to_event_type': dict(),
            'trusted_ip_header': 'Client-IP'

        }

    def test_missing_options(self):
        with self.assertRaises(Exception) as context:
            RtiMiddleware(None)
        self.assertTrue(errors.MISSING_RTI_OPTIONS, context.exception)

    def test_missing_wsgi_app(self):
        options = self.base_options.copy()
        options.update({'app': None})
        with self.assertRaises(Exception) as context:
            RtiMiddleware(options)
        self.assertTrue(errors.MISSING_WSGI_APP, context.exception)

    def test_missing_api_key(self):
        options = self.base_options.copy()
        options.update({'api_key': None})
        with self.assertRaises(Exception) as context:
            RtiMiddleware(options)
        self.assertTrue(errors.MISSING_API_KEY, context.exception)

    def test_missing_tag_hash(self):
        options = self.base_options.copy()
        options.update({'tag_hash': None})
        with self.assertRaises(Exception) as context:
            RtiMiddleware(options)
        self.assertTrue(errors.MISSING_TAG_HASH, context.exception)

    def test_missing_api_endpoint(self):
        options = self.base_options.copy()
        options.update({'api_endpoint': None})
        with self.assertRaises(Exception) as context:
            RtiMiddleware(options)
        self.assertTrue(errors.MISSING_API_ENDPOINT, context.exception)

    def test_invalid_uri_exclusion_list(self):
        options = self.base_options.copy()
        options.update({'uri_exclusion': 'uri_exclusion'})
        with self.assertRaises(Exception) as context:
            RtiMiddleware(options)
        self.assertEqual(context.exception.args[0], errors.INVALID_URI_EXCLUSION_LIST)

    def test_invalid_thereat_code_lists(self):
        options = self.base_options.copy()
        options.update({'invalid_block_redirect_codes': 'invalid_block_redirect_codes'})
        with self.assertRaises(Exception) as context:
            RtiMiddleware(options)
        self.assertEqual(context.exception.args[0], errors.INVALID_THREAT_CODE_LIST)
        options.update({'invalid_block_redirect_codes': ['1']})
        options.update({'invalid_captcha_codes': 'invalid_captcha_codes'})
        with self.assertRaises(Exception) as context:
            RtiMiddleware(options)
        self.assertEqual(context.exception.args[0], errors.INVALID_THREAT_CODE_LIST)
        options.update({'invalid_captcha_codes': ['1']})


