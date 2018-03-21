import re
import logging
import logging.config
from vFense import VFENSE_LOGGING_CONFIG

from json import loads

from vFense.core._constants import CommonKeys
from vFense.core.decorators import results_message
from vFense.core.agent import AgentKeys
from vFense.core.agent.agents import update_agent_field
from vFense.errorz._constants import ApiResultKeys
from vFense.operations import AgentOperationKeys
from vFense.operations._constants import AgentOperations
from vFense.operations.results import OperationResults
from vFense.operations.agent_operations import \
    operation_for_agent_and_app_exist

from vFense.errorz.status_codes import AgentOperationCodes, GenericCodes, \
    GenericFailureCodes, AgentFailureResultCodes, AgentResultCodes

from vFense.plugins.patching import AppCollections
from vFense.plugins.patching._constants import SharedAppKeys, CommonAppKeys
from vFense.plugins.patching._db import fetch_app_data

from vFense.plugins.patching.patching import \
    update_app_data_by_agentid_and_appid, \
    delete_apps_from_agent_by_name_and_version

from vFense.plugins.patching.operations.patching_operations import \
    PatchingOperation

from vFense.plugins.patching.apps.incoming_apps import \
    incoming_applications_from_agent

logging.config.fileConfig(VFENSE_LOGGING_CONFIG)
logger = logging.getLogger('rvapi')

class PatchingOperationResults(OperationResults):
    """This will update the results of an install, uninstall,
        and refresh_apps, as well as update the operation itself.
    """

    def __init__(
            self, username, agent_id, operation_id,
            success, error=None, status_code=None,
            uri=None, method=None
        ):
        super(PatchingOperationResults, self).__init__(
            username, agent_id, operation_id, success,
            error, status_code, uri, method
        )

        self.operation = (
            PatchingOperation(
                self.username, self.customer_name,
            )
        )

    def _set_global_properties(
            self, app_id, reboot_required,
            apps_to_delete, apps_to_add
        ):
        """Set global properties
        Args:
            app_id (str): The application id.
            reboot_required (bool):  True or False
            apps_to_delete (list): list of dictionaires,
                [{"app_name": "foo", "app_version": "1.2.3"}]
            apps_to_add (list): list of dictionaires,

        Attributes:
            self.app_id
            self.reboot_required
            self.apps_to_delete
            self.apps_to_add
            self.operation_type
        """

        self.apps_to_add = apps_to_add
        self.apps_to_delete = apps_to_delete
        self.app_id = app_id
        self.reboot_required = reboot_required
        self.operation_type = self.operation_data[AgentOperationKeys.Operation]

    def apps_refresh(self):
        operation_type = AgentOperations.REFRESH_APPS
        results = self.update_operation(operation_type)
        return results

    def install_os_apps(
            self, app_id, reboot_required,
            apps_to_delete, apps_to_add
        ):
        self._set_global_properties(
            app_id, reboot_required,
            apps_to_delete, apps_to_add
        )
        results = self._update_app_status(AppCollections.UniqueApplications)

        return results

    def install_custom_apps(
            self, app_id, reboot_required,
            apps_to_delete, apps_to_add
        ):
        self._set_global_properties(
            app_id, reboot_required,
            apps_to_delete, apps_to_add
        )
        results = self._update_app_status(AppCollections.CustomApps)

        return results

    def install_supported_apps(
            self, app_id, reboot_required,
            apps_to_delete, apps_to_add
        ):
        self._set_global_properties(
            app_id, reboot_required,
            apps_to_delete, apps_to_add
        )
        results = self._update_app_status(AppCollections.SupportedApps)

        return results

    def install_agent_apps(
            self, app_id, reboot_required,
            apps_to_delete, apps_to_add
        ):
        self._set_global_properties(
            app_id, reboot_required,
            apps_to_delete, apps_to_add
        )
        results = self._update_app_status(AppCollections.vFenseApps)
        return results

    def _apps_to_add(self):
        """Add apps to agent
        """
        try:
            self.apps_to_add = [loads(x) for x in self.apps_to_add]
        except Exception as e:
            pass

        incoming_applications_from_agent(
            self.username,
            self.customer_name,
            self.agent_id,
            self.agent_data[AgentKeys.OsCode],
            self.agent_data[AgentKeys.OsString],
            self.apps_to_add,
            delete_afterwards=False
        )

    def _apps_to_delete(self):
        """Delete apps from agent
        """
        try:
            self.apps_to_delete = [loads(x) for x in self.apps_to_delete]
        except Exception as e:
            pass

        for apps in self.apps_to_delete:
            delete_apps_from_agent_by_name_and_version(
                self.agent_id,
                apps[CommonAppKeys.NAME],
                apps[CommonAppKeys.VERSION],
            )

    @results_message
    def _update_app_status(self, collection):
        """Update the application status per agent as well as update the
            operation
        """
        results = {
            ApiResultKeys.USERNAME: self.username,
            ApiResultKeys.URI: self.uri,
            ApiResultKeys.HTTP_METHOD: self.method
        }

        if self.reboot_required:
            update_agent_field(
                self.agent_id, AgentKeys.NeedsReboot,
                CommonKeys.YES, self.username
            )

        if self.success == CommonKeys.TRUE or self.success == CommonKeys.FALSE:
            if (self.success == CommonKeys.TRUE and
                    re.search(r'^install', self.operation_type)):

                status = CommonAppKeys.INSTALLED
                install_date = self.date_now

            elif (self.success == CommonKeys.TRUE and
                    re.search(r'^uninstall', self.operation_type)):

                status = CommonAppKeys.AVAILABLE
                install_date = self.begining_of_time

            elif (self.success == CommonKeys.FALSE and
                    re.search(r'^install', self.operation_type)):

                status = CommonAppKeys.AVAILABLE
                install_date = self.begining_of_time

            elif (self.success == CommonKeys.FALSE and
                    re.search(r'^uninstall', self.operation_type)):

                status = CommonAppKeys.INSTALLED
                install_date = self.begining_of_time


            data_to_update = (
                {
                    SharedAppKeys.Status: status,
                    SharedAppKeys.InstallDate: install_date
                }
            )
            app_exist = fetch_app_data(self.app_id, collection)

            if app_exist:
                if (self.operation_type == AgentOperations.INSTALL_OS_APPS or
                        self.operation_type == AgentOperations.UNINSTALL):

                    update_app_data_by_agentid_and_appid(
                        self.agent_id,
                        self.app_id,
                        data_to_update,
                        AppCollections.AppsPerAgent
                    )

                elif self.operation_type == AgentOperations.INSTALL_CUSTOM_APPS:

                    update_app_data_by_agentid_and_appid(
                        self.agent_id,
                        self.app_id,
                        data_to_update,
                        AppCollections.CustomAppsPerAgent
                    )

                elif self.operation_type == AgentOperations.INSTALL_SUPPORTED_APPS:

                    update_app_data_by_agentid_and_appid(
                        self.agent_id,
                        self.app_id,
                        data_to_update,
                        AppCollections.SupportedAppsPerAgent
                    )

                elif self.operation_type == AgentOperations.INSTALL_AGENT_UPDATE:

                    update_app_data_by_agentid_and_appid(
                        self.agent_id,
                        self.app_id,
                        data_to_update,
                        AppCollections.vFenseAppsPerAgent
                    )

            oper_app_exists = (
                operation_for_agent_and_app_exist(
                    self.operation_id, self.agent_id, self.app_id
                )
            )

            if oper_app_exists:
                if self.success == CommonKeys.TRUE:
                    status_code = AgentOperationCodes.ResultsReceived

                    if self.apps_to_delete:
                        self._apps_to_delete()

                    if self.apps_to_add:
                        self._apps_to_add()

                elif self.success == CommonKeys.FALSE:
                    status_code = AgentOperationCodes.ResultsReceivedWithErrors

                operation_updated = (
                    self.operation.update_app_results(
                        self.operation_id, self.agent_id,
                        self.app_id, status_code,
                        errors=self.error, apps_removed=self.apps_to_delete
                    )
                )
                if operation_updated:
                    msg = 'Results updated'
                    results[ApiResultKeys.GENERIC_STATUS_CODE] = (
                        GenericCodes.ObjectUpdated
                    )

                    results[ApiResultKeys.VFENSE_STATUS_CODE] = (
                        AgentResultCodes.ResultsUpdated
                    )

                    results[ApiResultKeys.MESSAGE] = msg

                else:
                    msg = 'Results failed to update'
                    results[ApiResultKeys.GENERIC_STATUS_CODE] = (
                        GenericFailureCodes.FailedToUpdateObject
                    )

                    results[ApiResultKeys.VFENSE_STATUS_CODE] = (
                        AgentFailureResultCodes.ResultsFailedToUpdate
                    )

                    results[ApiResultKeys.MESSAGE] = msg

            else:
                msg = 'Invalid operation id'
                results[ApiResultKeys.GENERIC_STATUS_CODE] = (
                    GenericFailureCodes.InvalidId
                )

                results[ApiResultKeys.VFENSE_STATUS_CODE] = (
                    AgentFailureResultCodes.InvalidOperationId
                )

                results[ApiResultKeys.MESSAGE] = msg

        else:
            msg = 'Invalid success value'
            results[ApiResultKeys.GENERIC_STATUS_CODE] = (
                GenericFailureCodes.FailedToUpdateObject
            )

            results[ApiResultKeys.VFENSE_STATUS_CODE] = (
                AgentFailureResultCodes.InvalidSuccessValue
            )

            results[ApiResultKeys.MESSAGE] = msg

        return results
