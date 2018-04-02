import logging
from json import dumps

from vFense import VFENSE_LOGGING_CONFIG
from vFense.core.api.base import BaseHandler
from vFense.core.decorators import agent_authenticated_request, \
    convert_json_to_arguments

from vFense.core.operations.agent_results import AgentOperationResults
from vFense.db.notification_sender import send_notifications
from vFense.errorz.error_messages import GenericResults

from vFense.core.user import UserKeys
from vFense.core.user.users import get_user_property

#from server.handlers import *

logging.config.fileConfig(VFENSE_LOGGING_CONFIG)
logger = logging.getLogger('rvlistener')


class RebootResultsV1(BaseHandler):
    @agent_authenticated_request
    @convert_json_to_arguments
    def put(self, agent_id):
        username = self.get_current_user()
        customer_name = (
            get_user_property(username, UserKeys.CurrentCustomer)
        )
        uri = self.request.uri
        method = self.request.method
        try:
            operation_id = self.arguments.get('operation_id')
            error = self.arguments.get('error', None)
            success = self.arguments.get('success')
            results = (
                AgentOperationResults(
                    username, agent_id, operation_id,
                    success, error, uri, method
                )
            )
            results_data = results.reboot()
            self.set_status(results_data['http_status'])
            self.set_header('Content-Type', 'application/json')
            self.write(dumps(results_data, indent=4))
            send_notifications(username, customer_name, operation_id, agent_id)
        except Exception as e:
            results = (
                GenericResults(
                    username, uri, method
                ).something_broke(agent_id, 'reboot results', e)
            )
            logger.exception(results)

            self.set_status(results['http_status'])
            self.set_header('Content-Type', 'application/json')
            self.write(dumps(results, indent=4))
            

class ShutdownResultsV1(BaseHandler):
    @agent_authenticated_request
    @convert_json_to_arguments
    def put(self, agent_id):
        username = self.get_current_user()
        customer_name = (
            get_user_property(username, UserKeys.CurrentCustomer)
        )
        uri = self.request.uri
        method = self.request.method
        try:
            operation_id = self.arguments.get('operation_id')
            error = self.arguments.get('error', None)
            success = self.arguments.get('success')
            results = (
                AgentOperationResults(
                    username, agent_id, operation_id,
                    success, error, uri, method
                )
            )
            results_data = results.shutdown()
            self.set_status(results_data['http_status'])
            self.set_header('Content-Type', 'application/json')
            self.write(dumps(results_data, indent=4))
            send_notifications(username, customer_name, operation_id, agent_id)
        except Exception as e:
            results = (
                GenericResults(
                    username, uri, method
                ).something_broke(agent_id, 'shutdown results', e)
            )
            logger.exception(results)

            self.set_status(results['http_status'])
            self.set_header('Content-Type', 'application/json')
            self.write(dumps(results, indent=4))
            
