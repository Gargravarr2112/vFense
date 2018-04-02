import logging
import logging.config
from vFense import VFENSE_LOGGING_CONFIG
from copy import deepcopy
from vFense.operations._constants import vFenseObjects
from vFense.operations.agent_operations import AgentOperation
from vFense.operations import OperationPerAgentKeys, AgentOperationKeys
from vFense.core.decorators import results_message
from vFense.core.queue.queue import AgentQueue
from vFense.core.tag.tagManager import get_agent_ids_from_tag
from vFense.errorz._constants import ApiResultKeys
from vFense.errorz.status_codes import GenericCodes, AgentOperationCodes, \
    GenericFailureCodes, AgentOperationFailureCodes

logging.config.fileConfig(VFENSE_LOGGING_CONFIG)
logger = logging.getLogger('rvapi')


class StoreAgentOperation(object):
    """This is the base class for storing operations in an agent"""
    def __init__(
            self, username, customer_name,
            uri, method, server_queue_ttl=None,
            agent_queue_ttl=None
        ):
        """
        Args:
            username (str): The name of the user who called this class
            customer_name (str): The current logged in customer
            uri (str): The api uri that was used to get here.
            method (str): The http method that was used to get here.

        Kwargs:
            server_queue_ttl (int): The number of minutes,
                until the operation expires in the server queue.
            agent_queue_ttl (int): The number of minutes,
                until the operation expires in the agent queue.

        Attributes:
            customer_name
            username
            uri
            method
            server_queue_ttl
            agent_queue_ttl

        Basic Usage:
            >>> from vFense.operations.store_agent_operation import StoreAgentOperation
            >>> username = 'admin'
            >>> customer_name = 'default'
            >>> uri = '/api/v1/agent/33ba8521-b2e5-47dc-9bdc-0f1e3384049d'
            >>> method = 'POST'
            >>> store = StoreAgentOperation(username, customer_name, uri, method)
        """
        self.customer_name = customer_name
        self.username = username
        self.uri = uri
        self.method = method
        self.server_queue_ttl = server_queue_ttl
        self.agent_queue_ttl = agent_queue_ttl

    def _store_in_agent_queue(self, operation):
        """Add the operation inside of the agent queue collection
        Args:
            operation (dict): The dictionary of the operation.
        """
        agent_queue = (
            AgentQueue(
                operation[OperationPerAgentKeys.AgentId],
                self.customer_name
            )
        )
        agent_queue.add(operation, self.server_queue_ttl, self.agent_queue_ttl)

    @results_message
    def generic_operation(
            self, action, plugin,
            agentids=None, tag_id=None
        ):
        """This will do all the necessary work, to add the operation
            into the agent_queue. This method is to be used for operations
            that do not need any extra manipulation, in order to be added into
            the queue.
        Args:
            action (str): This is the action that will be performed,
                on the agent.
                Examples.... reboot, shutdown, install_os_apps, etc..
            plugin (str): The plugin that this operation is for.
                Examples... core, rv, ra, vuln
            agentids (list): List of agent ids, this operation will
                be performed on.
            tag_id (str): The tag id that this operation will be performed on.

        Basic Usage:
            >>> from vFense.operations.store_agent_operation import StoreAgentOperation
            >>> username = 'admin'
            >>> customer_name = 'default'
            >>> uri = '/api/v1/agent/33ba8521-b2e5-47dc-9bdc-0f1e3384049d'
            >>> method = 'POST'
            >>> store = StoreAgentOperation(username, customer_name, uri, method)
            >>> store.generic_operation(
                    'reboot', 'core',
                    agentids=['33ba8521-b2e5-47dc-9bdc-0f1e3384049d']
                )

        Returns:
            Dictionary
            {
                "rv_status_code": 6000,
                "http_method": "POST",
                "http_status": 200,
                "unchanged_ids": [],
                "generated_ids": [
                    "d5fb023c-82a0-4552-adc1-b3f83de7ae8a"
                ],
                "message": "operation created",
                "data": [
                    {
                        "operation_id": "d5fb023c-82a0-4552-adc1-b3f83de7ae8a",
                        "operation": "reboot",
                        "agent_id": "456404f1-b185-4f4f-8fb7-bfb21b3a5d53",
                        "plugin": "core"
                    }
                ],
                "uri": "/api/v1/456404f1-b185-4f4f-8fb7-bfb21b3a5d53/"

            }
        """
        data = []
        performed_on = vFenseObjects.AGENT
        if tag_id:
            performed_on = vFenseObjects.TAG
            if not agentids:
                agentids = get_agent_ids_from_tag(tag_id)

            elif agentids:
                agentids += get_agent_ids_from_tag(tag_id)

        results = {
            ApiResultKeys.DATA: [],
            ApiResultKeys.USERNAME: self.username,
            ApiResultKeys.URI: self.uri,
            ApiResultKeys.HTTP_METHOD: self.method
        }

        operation = (
            AgentOperation(
                self.username, self.customer_name,
            )
        )

        operation_id = (
            operation.create_operation(
                action, plugin, agentids, tag_id,
                performed_on=performed_on
            )
        )
        if operation_id:
            msg = 'operation created'
            status_code = GenericCodes.ObjectCreated
            vfense_status_code = AgentOperationCodes.Created
            results[ApiResultKeys.GENERATED_IDS] = [operation_id]
            results[ApiResultKeys.GENERIC_STATUS_CODE] = status_code
            results[ApiResultKeys.VFENSE_STATUS_CODE] = vfense_status_code
            results[ApiResultKeys.MESSAGE] = msg

            for agent_id in agentids:
                operation_data = {
                    AgentOperationKeys.Operation: action,
                    AgentOperationKeys.OperationId: operation_id,
                    AgentOperationKeys.Plugin: plugin,
                    OperationPerAgentKeys.AgentId: agent_id,
                }
                agent_data = deepcopy(operation_data)
                data.append(agent_data)
                self._store_in_agent_queue(operation_data)
                operation.add_agent_to_operation(agent_id, operation_id)

            results[ApiResultKeys.DATA] = data

        else:
            msg = 'operation failed to create'
            status_code = GenericFailureCodes.FailedToCreateObject
            vfense_status_code = (
                AgentOperationFailureCodes.FailedToCreateOperation
            )
            results[ApiResultKeys.GENERATED_IDS] = [operation_id]
            results[ApiResultKeys.GENERIC_STATUS_CODE] = status_code
            results[ApiResultKeys.VFENSE_STATUS_CODE] = vfense_status_code
            results[ApiResultKeys.MESSAGE] = msg
            results[ApiResultKeys.DATA] = data

        return results
