from vFense.operations import OperationPerAgentKeys, \
    OperationPerAppKeys
from vFense.operations.agent_operations import AgentOperation
from vFense.core._db_constants import DbTime
from vFense.operations._db_agent import update_operation_per_agent, \
    group_operations_per_app_by_results, update_operation_per_app, \
    update_errors_and_pending_count, update_failed_and_pending_count, \
    update_completed_and_pending_count, insert_agent_into_agent_operations, \
    insert_app_into_agent_operations

from vFense.errorz.status_codes import DbCodes, AgentOperationCodes, \
    OperationPerAgentCodes


class PatchingOperation(AgentOperation):
    """Creates the operations for the patching plugin."""

    def add_agent_to_install_operation(
            self, agent_id, operation_id, applications
        ):
        """Add an install operation for an agent
        Args:
            agent_id (str): the agent id.
            operation_id (str): the operation id.
            applications (list): List of application dictionairies.

        Basic Usage:
            >>> from vFense.operations.agent_operations import AgentOperation
            >>> username = 'admin'
            >>> customer_name = 'default'
            >>> oper = AgentOperation(username, customer_name)
            >>> operation_id = '5dc03727-de89-460d-b2a7-7f766c83d2f1'
            >>> agent_id = '38c1c67e-436f-4652-8cae-f1a2ac2dd4a2'
            >>> applications = [
                    {
                        'app_id': '70d462913faad1ecaa85eda4c448a607164fe39414c8be44405e7ab4f7f8467c',
                        'app_name': 'linux-firmware'
                    }
                ]
            >>> oper.add_agent_to_install_operation(
                    agent_id, operation_id, applications
                )

        Returns:
            Boolean
        """
        completed = False
        operation_data = {
            OperationPerAgentKeys.AgentId: agent_id,
            OperationPerAgentKeys.OperationId: operation_id,
            OperationPerAgentKeys.CustomerName: self.customer_name,
            OperationPerAgentKeys.Status: OperationPerAgentCodes.PendingPickUp,
            OperationPerAgentKeys.PickedUpTime: DbTime.begining_of_time(),
            OperationPerAgentKeys.ExpiredTime: DbTime.begining_of_time(),
            OperationPerAgentKeys.CompletedTime: DbTime.begining_of_time(),
            OperationPerAgentKeys.AppsTotalCount: len(applications),
            OperationPerAgentKeys.AppsPendingCount: len(applications),
            OperationPerAgentKeys.AppsFailedCount: self.INIT_COUNT,
            OperationPerAgentKeys.AppsCompletedCount: self.INIT_COUNT,
            OperationPerAgentKeys.Errors: None
        }

        status_code, count, errors, generated_ids = (
            insert_agent_into_agent_operations(operation_data)
        )
        if status_code == DbCodes.Inserted:
            apps = []
            for app in applications:
                apps.append(
                    {
                        OperationPerAppKeys.AgentId: agent_id,
                        OperationPerAppKeys.OperationId: operation_id,
                        OperationPerAppKeys.CustomerName: self.customer_name,
                        OperationPerAppKeys.Results: (
                            AgentOperationCodes.ResultsPending
                        ),
                        OperationPerAppKeys.ResultsReceivedTime: (
                            DbTime.begining_of_time()
                        ),
                        OperationPerAppKeys.AppId: app[OperationPerAppKeys.AppId],
                        OperationPerAppKeys.AppName: (
                            app[OperationPerAppKeys.AppName]
                        ),
                        OperationPerAppKeys.AppVersion: (
                            app[OperationPerAppKeys.AppVersion]
                        ),
                        OperationPerAppKeys.AppsRemoved: [],
                        OperationPerAppKeys.Errors: None
                    }
                )

            status_code, count, errors, generated_ids = (
                insert_app_into_agent_operations(apps)
            )
            if status_code == DbCodes.Inserted:
                completed = True

        return completed

    def update_app_results(
            self, operation_id, agent_id, app_id,
            status=AgentOperationCodes.ResultsReceived,
            errors=None, apps_removed=None
        ):
        """Update the results for an application.
        Args:
            operation_id (str): The operation id.
            agent_id (str): The agent id.
            app_id (str): The application id.

        Kwargs:
            status (int): The operation status code.
                default = 6002
            errors (str): The error message.
                default = None.
            apps_removed (list): list of dictionaries
                of the app name and app version
                default = None.

        Basic Usage:
            >>> from vFense.operations.agent_operations import AgentOperation
            >>> username = 'admin'
            >>> customer_name = 'default'
            >>> oper = AgentOperation(username, customer_name)
            >>> operation_id = '5dc03727-de89-460d-b2a7-7f766c83d2f1'
            >>> agent_id = '38c1c67e-436f-4652-8cae-f1a2ac2dd4a2'
            >>> app_id = '70d462913faad1ecaa85eda4c448a607164fe39414c8be44405e7ab4f7f8467c'
            >>> status_code = 6006
            >>> oper.update_operation_results(
                    operation_id, agent_id, app_id, status_code
                )

        Returns:
            Boolean
        """
        completed = False
        if not apps_removed:
            apps_removed = []

        operation_data = (
            {
                OperationPerAppKeys.Results: status,
                OperationPerAppKeys.ResultsReceivedTime: self.db_time,
                OperationPerAppKeys.AppsRemoved: apps_removed,
                OperationPerAppKeys.Errors: errors
            }
        )
        status_code, count, errors, generated_ids = (
            update_operation_per_app(
                operation_id, agent_id, app_id, operation_data
            )
        )

        if status_code == DbCodes.Replaced or status_code == DbCodes.Unchanged:
            self._update_app_stats(operation_id, agent_id, app_id)
            completed = True

        return completed

    def _update_app_stats(self, operation_id, agent_id, app_id):

        """Update the total counts based on the status code.
        Args:
            operation_id (str): The operation id.
            agent_id (str): The agent id.
            app_id (str): The application id.

        Basic Usage:
            >>> from vFense.operations.agent_operations import AgentOperation
            >>> username = 'admin'
            >>> customer_name = 'default'
            >>> oper = AgentOperation(username, customer_name)
            >>> operation_id = '5dc03727-de89-460d-b2a7-7f766c83d2f1'
            >>> agent_id = '38c1c67e-436f-4652-8cae-f1a2ac2dd4a2'
            >>> app_id = '70d462913faad1ecaa85eda4c448a607164fe39414c8be44405e7ab4f7f8467c'
            >>> oper._update_app_stats(
                    operation_id, agent_id, app_id,
                )

        Returns:
            Boolean
        """

        completed = False
        pending_count, completed_count, failed_count = (
            group_operations_per_app_by_results(
                operation_id, agent_id
            )
        )
        operation_data = {
            OperationPerAgentKeys.AppsCompletedCount: completed_count,
            OperationPerAgentKeys.AppsFailedCount: failed_count,
            OperationPerAgentKeys.AppsPendingCount: pending_count,
        }

        status_code, count, errors, generated_ids = (
            update_operation_per_agent(operation_id, agent_id, operation_data)
        )

        if status_code == DbCodes.Replaced or status_code == DbCodes.Unchanged:
            self._update_agent_stats_by_app_stats(
                operation_id, agent_id, completed_count,
                failed_count, pending_count
            )
            completed = True

        return completed

    def _update_agent_stats_by_app_stats(
            self, operation_id, agent_id,
            completed_count, failed_count,
            pending_count
        ):
        """Update the total counts based on the status code.
        Args:
            operation_id (str): the operation id.
            agent_id (str): the agent id.
            completed_count (int): the completed count.
            failed_count (int): the failed count.
            pending_count (int): the pending count.

        Basic Usage:
            >>> from vFense.operations.agent_operations import AgentOperation
            >>> username = 'admin'
            >>> customer_name = 'default'
            >>> oper = AgentOperation(username, customer_name)
            >>> operation_id = '5dc03727-de89-460d-b2a7-7f766c83d2f1'
            >>> agent_id = '38c1c67e-436f-4652-8cae-f1a2ac2dd4a2'
            >>> completed_count = 1
            >>> pending_count = 0
            >>> failed_count = 0
            >>> oper._update_agent_stats_by_app_stats(
                    operation_id, agent_id, completed_count,
                    failed_count, pending_count
                )

        Returns:
            Boolean
        """
        completed = False
        total_count = completed_count + failed_count + pending_count
        if total_count == completed_count:
            status_code, count, errors, generated_ids = (
                update_completed_and_pending_count(operation_id, self.db_time)
            )

            if (status_code == DbCodes.Replaced or
                    status_code == DbCodes.Unchanged):
                self._update_completed_time_on_agents(operation_id, agent_id)
                self._update_operation_status_code(operation_id)
                completed = True

        elif total_count == failed_count:
            status_code, count, errors, generated_ids = (
                update_failed_and_pending_count(operation_id, self.db_time)
            )

            if (status_code == DbCodes.Replaced or
                    status_code == DbCodes.Unchanged):
                self._update_completed_time_on_agents(operation_id, agent_id)
                self._update_operation_status_code(operation_id)
                completed = True

        elif total_count == (failed_count + completed_count):
            status_code, count, errors, generated_ids = (
                update_errors_and_pending_count(operation_id, self.db_time)
            )

            if (status_code == DbCodes.Replaced or
                    status_code == DbCodes.Unchanged):
                self._update_completed_time_on_agents(operation_id, agent_id)
                self._update_operation_status_code(operation_id)
                completed = True

        return completed
