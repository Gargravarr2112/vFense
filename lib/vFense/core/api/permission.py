import json
import logging
import logging.config
from vFense import VFENSE_LOGGING_CONFIG

from vFense.core.api.base import BaseHandler
from vFense.core.decorators import authenticated_request

from vFense.core.permissions._constants import *
from vFense.core.agent import *
from vFense.core.user import *
from vFense.errorz.error_messages import GenericResults

logging.config.fileConfig(VFENSE_LOGGING_CONFIG)
logger = logging.getLogger('rvapi')


class RetrieveValidPermissionsHandler(BaseHandler):

    @authenticated_request
    def get(self):
        active_user = self.get_current_user()
        uri = self.request.uri
        method = self.request.method
        count = 0
        permissions = []
        try:
            permissions = Permissions.VALID_PERMISSIONS
            count = len(permissions)
            results = (
                GenericResults(
                    active_user, uri, method
                ).information_retrieved(permissions, count)
            ) 
            self.set_status(results['http_status'])
            self.set_header('Content-Type', 'application/json')
            self.write(json.dumps(results, indent=4))

        except Exception as e:
            results = (
                GenericResults(
                    active_user, uri, method
                ).something_broke(active_user, 'permissions', e)
            )
            logger.exception(e)
            self.set_status(results['http_status'])
            self.set_header('Content-Type', 'application/json')
            self.write(json.dumps(results, indent=4))
