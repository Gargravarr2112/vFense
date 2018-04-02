import logging
from json import dumps

from vFense import VFENSE_LOGGING_CONFIG
from vFense.core.api.base import BaseHandler
from vFense.core.decorators import agent_authenticated_request
from vFense.core.decorators import convert_json_to_arguments
from vFense.core._constants import CommonKeys

from vFense.plugins.patching.operations.patching_results import \
    PatchingOperationResults

from vFense.db.notification_sender import send_notifications
from vFense.errorz.error_messages import GenericResults

from vFense.core.user import UserKeys
from vFense.core.user.users import get_user_property


logging.config.fileConfig(VFENSE_LOGGING_CONFIG)
logger = logging.getLogger('rvlistener')


class InstallOsAppsResults(BaseHandler):
    @agent_authenticated_request
    @convert_json_to_arguments
    def put(self, agent_id):
        username = self.get_current_user()
        customer_name = (
            get_user_property(username, UserKeys.CurrentCustomer)
        )
        uri = self.request.uri
        method = self.request.method
        try:
            logger.info(self.request.body)
            operation_id = self.arguments.get('operation_id')
            data = self.arguments.get('data', None)
            apps_to_delete = self.arguments.get('apps_to_delete', [])
            apps_to_add = self.arguments.get('apps_to_add', [])
            error = self.arguments.get('error', None)
            reboot_required = self.arguments.get('reboot_required')
            app_id = self.arguments.get('app_id')
            success = self.arguments.get('success')
            status_code = self.arguments.get('status_code', None)

            if not isinstance(reboot_required, bool):
                if reboot_required == CommonKeys.TRUE:
                    reboot_required = True
                else:
                    reboot_required = False

            results = (
                PatchingOperationResults(
                    username, agent_id,
                    operation_id, success, error,
                    status_code, uri, method
                )
            )
            results_data = (
                results.install_os_apps(
                    app_id, reboot_required,
                    apps_to_delete, apps_to_add
                )
            )
            self.set_status(results_data['http_status'])
            self.set_header('Content-Type', 'application/json')
            self.write(dumps(results_data, indent=4))
            send_notifications(username, customer_name, operation_id, agent_id)
        except Exception as e:
            results = (
                GenericResults(
                    username, uri, method
                ).something_broke(agent_id, 'install_os_apps results', e)
            )
            logger.exception(results)

            self.set_status(results['http_status'])
            self.set_header('Content-Type', 'application/json')
            self.write(dumps(results, indent=4))


class InstallCustomAppsResults(BaseHandler):
    @agent_authenticated_request
    @convert_json_to_arguments
    def put(self, agent_id):
        username = self.get_current_user()
        customer_name = (
            get_user_property(username, UserKeys.CurrentCustomer)
        )
        uri = self.request.uri
        method = self.request.method
        try:
            logger.info(self.request.body)
            operation_id = self.arguments.get('operation_id')
            data = self.arguments.get('data')
            apps_to_delete = self.arguments.get('apps_to_delete', [])
            apps_to_add = self.arguments.get('apps_to_add', [])
            error = self.arguments.get('error', None)
            reboot_required = self.arguments.get('reboot_required')
            app_id = self.arguments.get('app_id')
            success = self.arguments.get('success')
            status_code = self.arguments.get('status_code', None)
            logger.info("self.arguments: {0}".format(self.arguments))

            if not isinstance(reboot_required, bool):
                if reboot_required == CommonKeys.TRUE:
                    reboot_required = True
                else:
                    reboot_required = False

            results = (
                PatchingOperationResults(
                    username, agent_id,
                    operation_id, success, error,
                    status_code, uri, method
                )
            )
            results_data = (
                results.install_custom_apps(
                    app_id, reboot_required,
                    apps_to_delete, apps_to_add
                )
            )
            print results_data
            self.set_status(results_data['http_status'])
            self.set_header('Content-Type', 'application/json')
            self.write(dumps(results_data, indent=4))
            send_notifications(username, customer_name, operation_id, agent_id)
        except Exception as e:
            results = (
                GenericResults(
                    username, uri, method
                ).something_broke(agent_id, 'install_custom_apps results', e)
            )
            logger.exception(results)

            self.set_status(results['http_status'])
            self.set_header('Content-Type', 'application/json')
            self.write(dumps(results, indent=4))


class InstallSupportedAppsResults(BaseHandler):
    @agent_authenticated_request
    @convert_json_to_arguments
    def put(self, agent_id):
        username = self.get_current_user()
        customer_name = (
            get_user_property(username, UserKeys.CurrentCustomer)
        )
        uri = self.request.uri
        method = self.request.method
        try:
            operation_id = self.arguments.get('operation_id')
            data = self.arguments.get('data')
            apps_to_delete = self.arguments.get('apps_to_delete', [])
            apps_to_add = self.arguments.get('apps_to_add', [])
            error = self.arguments.get('error', None)
            reboot_required = self.arguments.get('reboot_required')
            app_id = self.arguments.get('app_id')
            success = self.arguments.get('success')
            status_code = self.arguments.get('status_code', None)
            logger.info("self.arguments: {0}".format(self.arguments))

            if not isinstance(reboot_required, bool):
                if reboot_required == CommonKeys.TRUE:
                    reboot_required = True
                else:
                    reboot_required = False

            results = PatchingOperationResults(
                username,
                agent_id,
                operation_id,
                success,
                error,
                status_code,
                uri,
                method
            )
            results_data = results.install_supported_apps(
                app_id, reboot_required, apps_to_delete, apps_to_add
            )

            print results_data
            self.set_status(results_data['http_status'])
            self.set_header('Content-Type', 'application/json')
            self.write(dumps(results_data, indent=4))
            send_notifications(username, customer_name, operation_id, agent_id)

        except Exception as e:
            results = (
                GenericResults(
                    username, uri, method
                ).something_broke(agent_id, 'install_supported_apps results', e)
            )
            logger.exception(results)

            self.set_status(results['http_status'])
            self.set_header('Content-Type', 'application/json')
            self.write(dumps(results, indent=4))


class InstallAgentAppsResults(BaseHandler):
    @agent_authenticated_request
    @convert_json_to_arguments
    def put(self, agent_id):
        username = self.get_current_user()
        customer_name = (
            get_user_property(username, UserKeys.CurrentCustomer)
        )
        uri = self.request.uri
        method = self.request.method
        try:
            logger.info(self.request.body)
            operation_id = self.arguments.get('operation_id')
            data = self.arguments.get('data')
            apps_to_delete = self.arguments.get('apps_to_delete', [])
            apps_to_add = self.arguments.get('apps_to_add', [])
            error = self.arguments.get('error', None)
            reboot_required = self.arguments.get('reboot_required')
            app_id = self.arguments.get('app_id')
            success = self.arguments.get('success')
            status_code = self.arguments.get('status_code', None)
            logger.info("self.arguments: {0}".format(self.arguments))

            if not isinstance(reboot_required, bool):
                if reboot_required == CommonKeys.TRUE:
                    reboot_required = True
                else:
                    reboot_required = False

            results = (
                PatchingOperationResults(
                    username, agent_id,
                    operation_id, success, error,
                    status_code, uri, method
                )
            )
            results_data = (
                results.install_agent_apps(
                    app_id, reboot_required,
                    apps_to_delete, apps_to_add
                )
            )
            print results_data
            # TODO: what is this meant for?
            #data = results.install_agent_update(data)

            self.set_status(results_data['http_status'])
            self.set_header('Content-Type', 'application/json')
            self.write(dumps(results_data, indent=4))
            send_notifications(username, customer_name, operation_id, agent_id)

        except Exception as e:
            results = (
                GenericResults(
                    username, uri, method
                ).something_broke(agent_id, 'install_agent_apps results', e)
            )
            logger.exception(results)

            self.set_status(results['http_status'])
            self.set_header('Content-Type', 'application/json')
            self.write(dumps(results, indent=4))


class UninstallAppsResults(BaseHandler):
    @agent_authenticated_request
    @convert_json_to_arguments
    def put(self, agent_id):
        username = self.get_current_user()
        customer_name = (
            get_user_property(username, UserKeys.CurrentCustomer)
        )
        uri = self.request.uri
        method = self.request.method
        try:
            logger.info(self.request.body)
            operation_id = self.arguments.get('operation_id')
            data = self.arguments.get('data')
            apps_to_delete = self.arguments.get('apps_to_delete', [])
            apps_to_add = self.arguments.get('apps_to_add', [])
            error = self.arguments.get('error', None)
            reboot_required = self.arguments.get('reboot_required')
            app_id = self.arguments.get('app_id')
            success = self.arguments.get('success')
            status_code = self.arguments.get('status_code', None)
            logger.info("self.arguments: {0}".format(self.arguments))

            if not isinstance(reboot_required, bool):
                if reboot_required == CommonKeys.TRUE:
                    reboot_required = True
                else:
                    reboot_required = False

            results = (
                PatchingOperationResults(
                    username, agent_id,
                    operation_id, success, error,
                    status_code, uri, method
                )
            )
            results_data = (
                results.install_os_apps(
                    app_id, reboot_required,
                    apps_to_delete, apps_to_add
                )
            )
            print results_data
            self.set_status(results_data['http_status'])
            self.set_header('Content-Type', 'application/json')
            self.write(dumps(results_data, indent=4))
            send_notifications(username, customer_name, operation_id, agent_id)

        except Exception as e:
            results = (
                GenericResults(
                    username, uri, method
                ).something_broke(agent_id, 'uninstall_os_apps results', e)
            )
            logger.exception(results)

            self.set_status(results['http_status'])
            self.set_header('Content-Type', 'application/json')
            self.write(dumps(results, indent=4))
