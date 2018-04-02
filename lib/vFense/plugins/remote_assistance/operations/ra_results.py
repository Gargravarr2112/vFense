#!/usr/bin/env python
import logging
import logging.config
from vFense import VFENSE_LOGGING_CONFIG

from vFense.operations._constants import AgentOperations
from vFense.operations.results import OperationResults

logging.config.fileConfig(VFENSE_LOGGING_CONFIG)
logger = logging.getLogger('rvapi')

class RaOperationResults(OperationResults):
    """Update an operation for an agent, based on the results received."""

    def ra(self):
        """This will update the results of the ra operation
        """
        oper_type = AgentOperations.RA
        results = self.update_operation(oper_type)
        return(results)

