import logging
from json import dumps

from vFense import VFENSE_LOGGING_CONFIG
from vFense.core.agent.agents import update_agent_status
from vFense.errorz.error_messages import GenericResults, AgentResults
from vFense.core.api.base import BaseHandler
from vFense.core.decorators import agent_authenticated_request

from vFense.receiver.corehandler import process_queue_data

from vFense.core.user import UserKeys
from vFense.core.user.users import get_user_property

logging.config.fileConfig(VFENSE_LOGGING_CONFIG)
logger = logging.getLogger('rvlistener')


class CheckInV1(BaseHandler):
    @agent_authenticated_request
    def get(self, agent_id):
        username = self.get_current_user()
        customer_name = (
            get_user_property(username, UserKeys.CurrentCustomer)
        )
        uri = self.request.uri
        method = self.request.method
        try:
            agent_queue = (
                process_queue_data(
                    agent_id, username, customer_name, uri, method
                )
            )
            status = (
                AgentResults(
                    username, uri, method
                ).check_in(agent_id, agent_queue)
            )
            logger.info(status)
            update_agent_status(
                agent_id, username, self.request.uri,
                self.request.method
            )
            self.set_status(status['http_status'])
            self.set_header('Content-Type', 'application/json')
            self.write(dumps(status))

        except Exception as e:
            status = (
                GenericResults(
                    username, uri, method
                ).something_broke(agent_id, 'check_in', e)
            )
            logger.exception(e)
            self.set_status(status['http_status'])
            self.set_header('Content-Type', 'application/json')
            self.write(dumps(status))

