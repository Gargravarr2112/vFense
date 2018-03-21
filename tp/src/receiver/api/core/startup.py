import logging

from json import dumps

from vFense import VFENSE_LOGGING_CONFIG
from vFense.core.api.base import BaseHandler
from vFense.core.decorators import convert_json_to_arguments, \
    agent_authenticated_request

from vFense.core.agent import *
from vFense.errorz.error_messages import GenericResults
from vFense.core.agent.agents import update_agent
from vFense.core.queue.uris import get_result_uris

from vFense.operations._constants import AgentOperations
from vFense.operations import AgentOperationKeys

from vFense.receiver.rvhandler import RvHandOff
import plugins.ra.handoff as RaHandoff

from vFense.core.user import UserKeys
from vFense.core.user.users import get_user_property
#from server.handlers import *

logging.config.fileConfig(VFENSE_LOGGING_CONFIG)
logger = logging.getLogger('rvlistener')


class StartUpV1(BaseHandler):
    @agent_authenticated_request
    @convert_json_to_arguments
    def put(self, agent_id):
        try:
            username = self.get_current_user()
            customer_name = (
                get_user_property(username, UserKeys.CurrentCustomer)
            )
            uri = self.request.uri
            method = self.request.method
            rebooted = self.arguments.get(AgentKeys.Rebooted)
            plugins = self.arguments.get(AgentKeys.Plugins)
            system_info = self.arguments.get(AgentKeys.SystemInfo)
            hardware = self.arguments.get(AgentKeys.Hardware)
            logger.info(
                'data received on startup: %s' % self.request.body
            )
            agent_data = (
                update_agent(
                    agent_id, system_info,
                    hardware, rebooted,
                    username, customer_name,
                    uri, method,
                )
            )
            uris = get_result_uris(agent_id, username, uri, method)
            uris[AgentOperationKeys.Operation] = (
                AgentOperations.REFRESH_RESPONSE_URIS
            )
            agent_data.pop('data')
            agent_data['data'] = [uris]
            self.set_status(agent_data['http_status'])

            if agent_data['http_status'] == 200:
                if 'rv' in plugins:
                    RvHandOff(
                        username, customer_name, uri, method
                    ).startup_operation(agent_id, plugins['rv']['data'])

                if 'ra' in plugins:
                    RaHandoff.startup(agent_id, plugins['ra'])

            self.set_header('Content-Type', 'application/json')
            self.write(dumps(agent_data))

        except Exception as e:
            status = (
                GenericResults(
                    username, uri, method
                ).something_broke(agent_id, 'startup', e)
            )

            logger.exception(status['message'])
            self.write(dumps(status))
