import re
import sys
import logging
import logging.config
from vFense import VFENSE_LOGGING_CONFIG

from vFense.db.client import db_create_close, r, db_connect
from vFense.errorz.error_messages import GenericResults, PackageResults
from vFense.plugins.vuln.cve import *
from vFense.plugins.vuln.cve._constants import *
from vFense.plugins.vuln.cve.cve import get_cve_data

logging.config.fileConfig(VFENSE_LOGGING_CONFIG)
logger = logging.getLogger('cve')

class RetrieveByCveId(object):
    def __init__(
        self, username, customer_name, cve_id,
        uri=None, method=None, count=30, offset=0
        ):

        self.cve_id = cve_id
        self.username = username
        self.customer_name = customer_name
        self.uri = uri
        self.method = method
        self.count = count
        self.offset = offset

    def get_cve(self):
        data = get_cve_data(self.cve_id)
        if data:
            status = (
                GenericResults(
                    self.username, self.uri, self.method
                ).information_retrieved(data, 1)
            )

        else:
            status = (
                GenericResults(
                    self.username, self.uri, self.method
                ).invalid_id(self.cve_id, 'cve id')
            )

        return(status)
