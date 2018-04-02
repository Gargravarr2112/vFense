import logging
from json import dumps

from vFense import VFENSE_LOGGING_CONFIG
from vFense.core.api.base import BaseHandler
from vFense.core.decorators import agent_authenticated_request
from vFense.core.queue.uris import get_result_uris
from vFense.errorz.error_messages import GenericResults


logging.config.fileConfig(VFENSE_LOGGING_CONFIG)
logger = logging.getLogger('rvlistener')


class ResultURIs(BaseHandler):
    @agent_authenticated_request
    def get(self, agent_id):
        username = self.get_current_user()
        uri = self.request.uri
        method = self.request.method
        try:
            results = get_result_uris(agent_id, username, uri, method)
            self.set_header('Content-Type', 'application/json')
            self.write(dumps(results, indent=4))

        except Exception as e:
            status = (
                GenericResults(
                    username, uri, method
                ).something_broke('uris', 'refresh_response_uris', e)
            )
            logger.exception(e)
            self.write(dumps(status, indent=4))
