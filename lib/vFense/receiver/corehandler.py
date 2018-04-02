import logging

from vFense import VFENSE_LOGGING_CONFIG
from vFense.operations.agent_operations import AgentOperation
from vFense.operations import AgentOperationKeys
from vFense.operations._constants import AgentOperations
from vFense.core.queue.queue import AgentQueue

logging.config.fileConfig(VFENSE_LOGGING_CONFIG)
logger = logging.getLogger('rvapi')

#process that data!!


def process_queue_data(agent_id, username, customer_name, uri, method):
    agent_queue = AgentQueue(agent_id, customer_name).pop_agent_queue()
    for operation in agent_queue:
        if operation.get(AgentOperationKeys.OperationId):
            oper = (
                AgentOperation(
                    username, customer_name
                )
            )
            oper.update_operation_pickup_time(
                operation[AgentOperationKeys.OperationId], agent_id
            )

    return agent_queue
