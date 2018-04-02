#!/usr/bin/env python
import logging
import logging.config
from vFense import VFENSE_LOGGING_CONFIG

from vFense.core._constants import CommonKeys
from vFense.core.decorators import results_message
from vFense.core.agent import AgentKeys
from vFense.errorz._constants import ApiResultKeys
from vFense.core.agent.agents import get_agent_info
from vFense.core._db_constants import DbTime
from vFense.operations.agent_operations import AgentOperation, \
    operation_for_agent_exist, get_agent_operation

from vFense.errorz.status_codes import AgentOperationCodes, GenericCodes, \
    GenericFailureCodes, AgentFailureResultCodes, AgentResultCodes


logging.config.fileConfig(VFENSE_LOGGING_CONFIG)
logger = logging.getLogger('rvapi')

class OperationResults(object):
    """Update an operation for an agent, based on the results received.
        This is the base class for adding results to an aegnt operation"""
    def __init__(
            self, username, agent_id, operation_id,
            success, error=None, status_code=None,
            uri=None, method=None
        ):
        """
        Args:
            username (str): The name of the user who made this api call
            agent_id (str): 36 character UUID of the agent.
            operation_id (str): 36 character UUID of the operation.
            success (str): true or false.

        Kwargs:
            error (str): The error message, if the operation failed.
            status_code (int): The exact status of this operation.
            uri (str): The uri which was called for the results.
            method (str): The method used to call this api.

        Basic Usage:
            >>> from vFense.operations.results import OperationResults
            >>> username = 'admin'
            >>> operation_id = '8fed3dc7-33d4-4278-9bd4-398a68bf7f22'
            >>> agent_id = 'db6bf07-c5da-4494-93bb-109db205ca64'
            >>> success = 'true'
            >>> results = OperationResults(
                    username, agent_id, operation_id, success
                )
        """

        self.agent_id = agent_id
        self.operation_id = operation_id
        self.username = username
        self.uri = uri
        self.method = method
        self.agent_data = get_agent_info(self.agent_id)
        self.operation_data = get_agent_operation(self.operation_id)
        self.customer_name = self.agent_data[AgentKeys.CustomerName]
        self.date_now = DbTime.time_now()
        self.begining_of_time = DbTime.begining_of_time()
        self.error = error
        self.success = success
        self.status_code = status_code
        self.operation = (
            AgentOperation(
                self.username, self.customer_name,
            )
        )

    @results_message
    def update_operation(self, oper_type):
        """Update an agent operation
        Args:
            oper_type (str): This is the operation type, such as
                reboot, shutdown, install_os_apps, etc...

        Basic Usage:
            >>> from vFense.operations.results import OperationResults
            >>> username = 'admin'
            >>> operation_id = '8fed3dc7-33d4-4278-9bd4-398a68bf7f22'
            >>> agent_id = 'db6bf07-c5da-4494-93bb-109db205ca64'
            >>> success = 'true'
            >>> results = OperationResults(
                    username, agent_id, operation_id, success
                )
            >>> results.update_operation('reboot')

        Returns:
            Dictionary
            {
                "rv_status_code": 3203,
                "http_method": PUT,
                "updated_ids": [
                    "d5fb023c-82a0-4552-adc1-b3f83de7ae8a"
                ],
                "http_status": 200,
                "unchanged_ids": [],
                "message": "Results updated for operation id d5fb023c-82a0-4552-adc1-b3f83de7ae8a",
                "data": [],
                "uri": "rvl/v1/456404f1-b185-4f4f-8fb7-bfb21b3a5d53/core/results/reboot"
            }
        """

        results = {
            ApiResultKeys.DATA: [],
            ApiResultKeys.USERNAME: self.username,
            ApiResultKeys.URI: self.uri,
            ApiResultKeys.HTTP_METHOD: self.method
        }

        oper_exists = (
            operation_for_agent_exist(
                self.operation_id, self.agent_id
            )
        )

        if oper_exists:
            if (
                    self.success == CommonKeys.TRUE or
                    self.success == CommonKeys.FALSE
                ):

                if self.success == CommonKeys.TRUE:
                    status_code = AgentOperationCodes.ResultsReceived
                else:
                    status_code = AgentOperationCodes.ResultsReceivedWithErrors

                operation_updated = (
                    self.operation.update_operation_results(
                        self.operation_id, self.agent_id,
                        status_code, oper_type, self.error
                    )
                )

                if operation_updated:
                    msg = (
                        'Results updated for operation id %s' %
                        (self.operation_id)
                    )
                    results[ApiResultKeys.GENERIC_STATUS_CODE] = (
                        GenericCodes.ObjectUpdated
                    )

                    results[ApiResultKeys.VFENSE_STATUS_CODE] = (
                        AgentResultCodes.ResultsUpdated
                    )

                    results[ApiResultKeys.MESSAGE] = msg

                    results[ApiResultKeys.UPDATED_IDS] = (
                        [self.operation_id]
                    )

                else:
                    msg = (
                        'Results failed to update operation id %s' %
                        (self.operation_id)
                    )
                    results[ApiResultKeys.GENERIC_STATUS_CODE] = (
                        GenericFailureCodes.FailedToUpdateObject
                    )

                    results[ApiResultKeys.VFENSE_STATUS_CODE] = (
                        AgentFailureResultCodes.ResultsFailedToUpdate
                    )

                    results[ApiResultKeys.MESSAGE] = msg

                    results[ApiResultKeys.UNCHANGED_IDS] = (
                        [self.operation_id]
                    )

            else:
                msg = (
                    'Invalid operation id %s' %
                    (self.operation_id)
                )
                results[ApiResultKeys.GENERIC_STATUS_CODE] = (
                    GenericFailureCodes.FailedToUpdateObject
                )

                results[ApiResultKeys.VFENSE_STATUS_CODE] = (
                    AgentFailureResultCodes.InvalidSuccessValue
                )

                results[ApiResultKeys.MESSAGE] = msg

                results[ApiResultKeys.UNCHANGED_IDS] = (
                    [self.operation_id]
                )

        else:
            msg = 'Invalid operation id'
            results[ApiResultKeys.GENERIC_STATUS_CODE] = (
                GenericFailureCodes.InvalidId
            )

            results[ApiResultKeys.VFENSE_STATUS_CODE] = (
                AgentFailureResultCodes.InvalidOperationId
            )

            results[ApiResultKeys.MESSAGE] = msg

            results[ApiResultKeys.UNCHANGED_IDS] = (
                [self.operation_id]
            )

        return results
