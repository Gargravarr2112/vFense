#!/usr/bin/env python
import logging
import logging.config
from vFense import VFENSE_LOGGING_CONFIG

from vFense.core._constants import CommonKeys
from vFense.operations._constants import AgentOperations
from vFense.core.agent import AgentKeys
from vFense.core.agent.agents import update_agent_field
from vFense.operations.results import OperationResults

logging.config.fileConfig(VFENSE_LOGGING_CONFIG)
logger = logging.getLogger('rvapi')

class AgentOperationResults(OperationResults):
    """Update an operation for an agent, based on the results received."""

    def reboot(self):
        """This will update the needs_reboot flag in the agent collection as
            well as update the operation with reboot succeeded
        """
        oper_type = AgentOperations.REBOOT
        results = self.update_operation(oper_type)

        if self.success == CommonKeys.TRUE:
            update_agent_field(
                self.agent_id,
                AgentKeys.NeedsReboot,
                CommonKeys.NO, self.username,
                self.uri, self.method
            )

        return(results)

    def shutdown(self):
        """This will update the operation with shutdown succeeded"""
        oper_type = AgentOperations.SHUTDOWN
        results = self.update_operation(oper_type)
        return(results)

