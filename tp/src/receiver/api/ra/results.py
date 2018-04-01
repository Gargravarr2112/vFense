import logging
import simplejson as json

from vFense import VFENSE_LOGGING_CONFIG
from vFense.core.api.base import BaseHandler
from vFense.core.decorators import authenticated_request, \
    convert_json_to_arguments

from vFense.plugins.remote_assistance.operations.ra_results import RaOperationResults

from vFense.plugins.remote_assistance.processor import Processor

logging.config.fileConfig(VFENSE_LOGGING_CONFIG)
logger = logging.getLogger('rvlistener')


class RemoteDesktopResults(BaseHandler):

    @authenticated_request
    @convert_json_to_arguments
    def post(self):

        username = self.get_current_user()
        uri = self.request.uri
        method = self.request.method
        agent_id = self.arguments.get('agent_id')
        operation_id = self.arguments.get('operation_id')
        success = self.arguments.get('success')
        error = self.arguments.get('error', None)
        status_code = self.arguments.get('status_code', None)

        logger.info(
            'Data received on remote desktop results: %s' %
            (self.request.body)
        )

        processor = Processor()
        processor.handle(self.arguments)

        logger.info("self.arguments: {0}".format(self.arguments))
        results = (
            RaOperationResults(
                username, agent_id,
                operation_id, success, error,
                status_code, uri, method
            )
        )
        results_data = results.ra()

        #result = AgentResults(
        #    username, self.request.uri, "POST"
        #).ra_results(agent_id)

        self.set_header('Content-Type', 'application/json')
        self.write(json.dumps(results_data))
