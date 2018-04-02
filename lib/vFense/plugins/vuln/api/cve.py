import simplejson as json

from vFense.core.api.base import BaseHandler
import logging
import logging.config
from vFense import VFENSE_LOGGING_CONFIG

from vFense.plugins.vuln.search.by_cve_id import RetrieveByCveId

from vFense.core.decorators import authenticated_request

from vFense.core.user import UserKeys
from vFense.core.user.users import get_user_property

logging.config.fileConfig(VFENSE_LOGGING_CONFIG)
logger = logging.getLogger('rvapi')


class CveIdHandler(BaseHandler):
    @authenticated_request
    def get(self, cve_id):
        username = self.get_current_user().encode('utf-8')
        customer_name = (
            get_user_property(username, UserKeys.CurrentCustomer)
        )
        uri = self.request.uri
        method = self.request.method
        vuln = (
            RetrieveByCveId(
                username, customer_name, cve_id,
                uri, method
            )
        )
        results = vuln.get_cve()

        self.set_status(results['http_status'])
        self.set_header('Content-Type', 'application/json')
        self.write(json.dumps(results, indent=4))

 
