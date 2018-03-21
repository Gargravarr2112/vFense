import logging

from json import dumps

from vFense import VFENSE_LOGGING_CONFIG
from vFense.core.api.base import BaseHandler
from vFense.core.decorators import convert_json_to_arguments, agent_authenticated_request
from vFense.core.agent import *
from vFense.operations import *
from vFense.operations._constants import AgentOperations
from vFense.core.agent.agents import add_agent
from vFense.core.queue.uris import get_result_uris
from vFense.errorz._constants import ApiResultKeys
from vFense.errorz.error_messages import GenericResults
from vFense.errorz.status_codes import AgentResultCodes
from vFense.receiver.rvhandler import RvHandOff

from vFense.core.user import UserKeys
from vFense.core.user.users import get_user_property

import plugins.ra.handoff as RaHandoff
#from server.handlers import *

logging.config.fileConfig(VFENSE_LOGGING_CONFIG)
logger = logging.getLogger('rvlistener')


class NewAgentV1(BaseHandler):
    @agent_authenticated_request
    @convert_json_to_arguments
    def post(self):
        username = self.get_current_user()
        customer_name = self.arguments.get(AgentKeys.CustomerName)
        plugins = self.arguments.get(AgentKeys.Plugins)
        rebooted = self.arguments.get(AgentKeys.Rebooted)
        system_info = self.arguments.get(AgentKeys.SystemInfo)
        hardware = self.arguments.get(AgentKeys.Hardware)
        uri = self.request.uri
        method = self.request.method
        logger.info('data received on newagent: %s' % (self.request.body))
        self.set_header('Content-Type', 'application/json')

        try:
            new_agent_results = (
                add_agent(
                    system_info, hardware, username, customer_name, uri, method
                )
            )
            self.set_status(
                new_agent_results[ApiResultKeys.HTTP_STATUS_CODE]
            )

            if (
                    new_agent_results[ApiResultKeys.VFENSE_STATUS_CODE] ==
                    AgentResultCodes.NewAgentSucceeded
                ):

                agent_info = new_agent_results[ApiResultKeys.DATA][-1]
                agent_id = (
                    new_agent_results[ApiResultKeys.GENERATED_IDS].pop()
                )
                uris = get_result_uris(agent_id, username, uri, method)
                uris[AgentOperationKeys.Operation] = (
                    AgentOperations.REFRESH_RESPONSE_URIS
                )
                json_msg = {
                    AgentOperationKeys.Operation: "new_agent_id",
                    AgentOperationKeys.OperationId: "",
                    OperationPerAgentKeys.AgentId: agent_id
                }
                new_agent_results[ApiResultKeys.DATA] = [json_msg, uris]
                try:
                    if 'rv' in plugins:
                        RvHandOff(
                            username, customer_name, uri, method
                        ).new_agent_operation(
                            agent_id,
                            plugins['rv']['data'],
                            agent_info
                        )

                    if 'ra' in plugins:
                        RaHandoff.startup(agent_id, plugins['ra'])

                except Exception as e:
                    logger.exception(e)

                self.write(dumps(new_agent_results, indent=4))

            else:
                self.write(dumps(new_agent_results, indent=4))

        except Exception as e:
            status = (
                GenericResults(
                    username, uri, method
                ).something_broke('agent', 'new_agent', e)
            )
            logger.exception(e)
            self.write(dumps(status, indent=4))
