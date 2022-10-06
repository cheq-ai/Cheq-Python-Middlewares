from requests import request
import json

class Singleton(type):
    _instances = {}

    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(Singleton, cls).__call__(*args, **kwargs)
        return cls._instances[cls]


class RtiLogger(metaclass=Singleton):
    def __init__(self, api_key, tag_hash):
        self.api_key = api_key
        self.tag_hash = tag_hash

    def audit(self, message, action):
        log('audit', self.api_key, self.tag_hash, message, action)

    def info(self, message, action):
        log('info', self.api_key, self.tag_hash, message, action)

    def warn(self, message, action):
        log('warn', self.api_key, self.tag_hash, message, action)

    def error(self, message, action):
        log('error', self.api_key, self.tag_hash, message, action)


def log(level, api_key, tag_hash, message, action):
    body = {
        "level": level,
        "apiKey": api_key,
        "tagHash": tag_hash,
        "action": action,
        "application": 'rti-python-wsgi-middleware',  # TODO get package version
        "message": message
    }

    try:
        request('POST', 'https://rtilogger.production.cheq-platform.com', json=json.dumps(body))
    except Exception as e:
        x = 1
        pass
