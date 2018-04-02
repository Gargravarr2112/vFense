import simplejson as json

import logging
import logging.config
from vFense import VFENSE_LOGGING_CONFIG
from vFense.core.api.base import BaseHandler
from vFense.db.client import *
from vFense.utils.common import *
from vFense.core.logger.logger import vFenseLogger, VFENSE_LOGGING_CONFIG
from vFense.core.decorators import authenticated_request


logging.config.fileConfig(VFENSE_LOGGING_CONFIG)
logger = logging.getLogger('rvapi')


class LoggingModifyerHandler(BaseHandler):
    @authenticated_request
    def post(self):
        username = self.get_current_user()
        host = self.get_argument('host', None)
        port = self.get_argument('port', None)
        proto = self.get_argument('proto', 'UDP')
        level = self.get_argument('level', 'INFO')
        proto = proto.upper()
        level = level.upper()
        if host and port and proto and level:
            rvlogger = vFenseLogger()
            connected = rvlogger.connect_to_loghost(host, port, proto)
            if connected:
                rvlogger.create_config(loglevel=level, loghost=host,
                        logport=port, logproto=proto)
                results = rvlogger.results
            else:
                results = {
                        'pass': False,
                        'message': 'Cant connect to %s on %s using proto %s' %\
                                (host, port, proto)
                        }
        elif level and not host and not port:
            rvlogger = vFenseLogger()
            rvlogger.create_config(loglevel=level)
            results = rvlogger.results
        else:
            results = {
                    'pass': False,
                    'message': 'incorrect parameters passed'
                    }
        self.set_header('Content-Type', 'application/json')
        self.write(json.dumps(results, indent=4))


class LoggingListerHandler(BaseHandler):
    @authenticated_request
    def get(self):
        rvlogger = vFenseLogger()
        rvlogger.get_logging_config()
        results = rvlogger.results
        self.set_header('Content-Type', 'application/json')
        self.write(json.dumps(results, indent=4))
