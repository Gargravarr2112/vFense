import re
import logging
import logging.config
from vFense import VFENSE_LOGGING_CONFIG

from vFense.errorz.error_messages import GenericResults
from vFense.plugins.vuln.cve import *
from vFense.plugins.vuln.cve._constants import *
import vFense.plugins.vuln.ubuntu.usn as usn
import vFense.plugins.vuln.windows.ms as ms

logging.config.fileConfig(VFENSE_LOGGING_CONFIG)
logger = logging.getLogger('cve')

class RetrieveByVulnerabilityId(object):
    def __init__(
        self, username, customer_name, vuln_id,
        uri=None, method=None, count=30, offset=0
        ):

        self.vuln_id = vuln_id
        self.username = username
        self.customer_name = customer_name
        self.uri = uri
        self.method = method
        self.count = count
        self.offset = offset
        self.__os_director()

    def __os_director(self):
        if re.search('^MS', self.vuln_id, re.IGNORECASE):
            self.get_vuln_by_id = ms.get_vuln_data_by_vuln_id

        elif re.search('^USN-', self.vuln_id, re.IGNORECASE):
            self.get_vuln_by_id = usn.get_vuln_data_by_vuln_id

    def get_vuln(self):
        data = self.get_vuln_by_id(self.vuln_id)
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
                ).invalid_id(self.vuln_id, 'vulnerability id')
            )

        return(status)
