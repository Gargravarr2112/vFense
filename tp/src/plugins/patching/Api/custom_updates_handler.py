import simplejson as json

from vFense.core.api.base import BaseHandler
import logging
import logging.config
from vFense import VFENSE_LOGGING_CONFIG

from vFense.errorz.error_messages import GenericResults, PackageResults

from vFense.core._constants import CommonKeys
from vFense.core.permissions._constants import *
from vFense.core.permissions.decorators import check_permissions

from vFense.core.decorators import convert_json_to_arguments, authenticated_request

from vFense.plugins.patching import *
from vFense.plugins.patching._db import update_app_data_by_app_id
from vFense.plugins.patching.patching import toggle_hidden_status
from vFense.plugins.patching._constants import CommonSeverityKeys

from vFense.plugins.patching._db import delete_app_from_vfense
from vFense.plugins.patching.operations.store_operations import StorePatchingOperation
from vFense.plugins.patching.search.search import RetrieveCustomApps
from vFense.plugins.patching.search.search_by_agentid import RetrieveCustomAppsByAgentId
from vFense.plugins.patching.search.search_by_tagid import RetrieveCustomAppsByTagId
from vFense.plugins.patching.search.search_by_appid import RetrieveCustomAppsByAppId, \
    RetrieveAgentsByCustomAppId

from vFense.plugins.patching.apps.custom_apps.uploaded.uploader import gen_uuid, \
    move_packages, store_package_info_in_db

from vFense.core.user import UserKeys
from vFense.core.user.users import get_user_property

logging.config.fileConfig(VFENSE_LOGGING_CONFIG)
logger = logging.getLogger('rvapi')


class GetThirdPartyUuidHandler(BaseHandler):
    @authenticated_request
    @check_permissions(Permissions.ADMINISTRATOR)
    def get(self):
        username = self.get_current_user()
        customer_name = (
            get_user_property(username, UserKeys.CurrentCustomer)
        )
        uri = self.request.uri
        method = self.request.method
        data = {"uuid": gen_uuid()}
        results = (
            GenericResults(
                username, uri, method
            ).information_retrieved(data, 0)
        )
        self.set_header('Content-Type', 'application/json')
        self.write(json.dumps(results, indent=4))


class ThirdPartyPackageUploadHandler(BaseHandler):
    @authenticated_request
    @check_permissions(Permissions.ADMINISTRATOR)
    def post(self):
        username = self.get_current_user()
        customer_name = (
            get_user_property(username, UserKeys.CurrentCustomer)
        )
        uri = self.request.uri
        method = self.request.method
        name = self.get_argument('pkg.name')
        path = self.get_argument('pkg.path')
        size = self.get_argument('pkg.size')
        md5 = self.get_argument('pkg.md5')
        uuid = self.request.headers.get('Fileuuid')

        if uuid and name and md5 and path and size:
            result = (
                move_packages(
                    username, customer_name, uri, method,
                    name=name, path=path, size=size,
                    md5=md5, uuid=uuid
                )
            )

        self.set_header('Content-Type', 'application/json')
        self.write(json.dumps(result, indent=4))


class ThirdPartyUploadHandler(BaseHandler):
    @authenticated_request
    @convert_json_to_arguments
    @check_permissions(Permissions.ADMINISTRATOR)
    def post(self):
        username = self.get_current_user()
        customer_name = (
            get_user_property(username, UserKeys.CurrentCustomer)
        )
        uri = self.request.uri
        method = self.request.method
        name = self.arguments.get('name', None)
        release_date = self.arguments.get('release_date', None)
        severity = self.arguments.get('severity', 'Optional')
        description = self.arguments.get('description', None)
        kb = self.arguments.get('kb', '')
        support_url = self.arguments.get('support_url', '')
        major_version = self.arguments.get('major_version', None)
        minor_version = self.arguments.get('minor_version', None)
        vendor_name = self.arguments.get('vendor_name', None)
        operating_system = self.arguments.get('operating_system', None)
        size = self.arguments.get('size', None)
        md5 = self.arguments.get('md5_hash', None)
        cli_options = self.arguments.get('cli_options', None)
        arch = self.arguments.get('arch', None)
        uuid = self.arguments.get('id', None)

        result = (
            store_package_info_in_db(
                username, customer_name, uri, method,
                size, md5, operating_system, uuid, name,
                severity, arch, major_version, minor_version,
                release_date, vendor_name, description,
                cli_options, support_url, kb
            )
        )

        self.set_header('Content-Type', 'application/json')
        self.write(json.dumps(result, indent=4))


class AgentIdCustomAppsHandler(BaseHandler):
    @authenticated_request
    def get(self, agent_id):
        username = self.get_current_user().encode('utf-8')
        customer_name = (
            get_user_property(username, UserKeys.CurrentCustomer)
        )
        query = self.get_argument('query', None)
        count = int(self.get_argument('count', 30))
        offset = int(self.get_argument('offset', 0))
        status = self.get_argument('status', 'installed')
        severity = self.get_argument('severity', None)
        sort = self.get_argument('sort', 'asc')
        sort_by = self.get_argument('sort_by', CustomAppsKeys.Name)
        hidden = self.get_argument('hidden', 'false')
        if hidden == 'false':
            hidden = CommonKeys.NO
        else:
            hidden = CommonKeys.YES
        uri = self.request.uri
        method = self.request.method
        patches = (
            RetrieveCustomAppsByAgentId(
                username, customer_name, agent_id,
                uri, method, count, offset,
                sort, sort_by, show_hidden=hidden
            )
        )
        if not query and not severity and status:
            results = patches.filter_by_status(status)

        elif not query and status and severity:
            results = patches.filter_by_status_and_sev(status, severity)

        elif severity and not query and not status:
            results = patches.filter_by_severity(severity)

        elif severity and status and query:
            results = (
                patches.filter_by_status_and_query_by_name_and_sev(
                    query, status, severity
                )
            )

        elif status and query:
            results = (
                patches.filter_by_status_and_query_by_name(
                    query, status
                )
            )

        elif severity and query:
            results = (
                patches.filter_by_sev_and_query_by_name(
                    query, severity
                )
            )

        elif query and not severity and not status:
            results = patches.query_by_name(query)

        else:
            results = (
                GenericResults(
                    username, uri, method
                ).incorrect_arguments()
            )

        self.set_status(results['http_status'])
        self.set_header('Content-Type', 'application/json')
        self.write(json.dumps(results, indent=4))


    @authenticated_request
    @convert_json_to_arguments
    @check_permissions(Permissions.INSTALL)
    def put(self, agent_id):
        username = self.get_current_user().encode('utf-8')
        customer_name = (
            get_user_property(username, UserKeys.CurrentCustomer)
        )
        uri = self.request.uri
        method = self.request.method
        try:
            app_ids = self.arguments.get('app_ids')
            epoch_time = self.arguments.get('time', None)
            label = self.arguments.get('label', None)
            restart = self.arguments.get('restart', 'none')
            cpu_throttle = self.arguments.get('cpu_throttle', 'normal')
            net_throttle = self.arguments.get('net_throttle', 0)
            if not epoch_time and not label and app_ids:
                operation = (
                    StorePatchingOperation(
                        username, customer_name, uri, method
                    )
                )
                results = (
                    operation.install_custom_apps(
                        app_ids, cpu_throttle,
                        net_throttle, restart,
                        agentids=[agent_id]
                    )
                )
                self.set_status(results['http_status'])
                self.set_header('Content-Type', 'application/json')
                self.write(json.dumps(results, indent=4))

            elif epoch_time and label and app_ids:
                date_time = datetime.fromtimestamp(int(epoch_time))
                sched = self.application.scheduler
                job = (
                    {
                        'cpu_throttle': cpu_throttle,
                        'net_throttle': net_throttle,
                        'restart': restart,
                        'pkg_type': 'custom_apps',
                        'app_ids': app_ids
                    }
                )
                add_install_job = (
                    schedule_once(
                        sched, customer_name, username,
                        [agent_id], operation='install',
                        name=label, date=date_time, uri=uri,
                        method=method, job_extra=job
                    )
                )
                result = add_install_job
                self.set_header('Content-Type', 'application/json')
                self.write(json.dumps(result))

        except Exception as e:
            results = (
                GenericResults(
                    username, uri, method
                ).something_broke(agent_id, 'install_custom_apps', e)
            )
            logger.exception(e)
            self.set_status(results['http_status'])
            self.set_header('Content-Type', 'application/json')
            self.write(json.dumps(results, indent=4))

    @authenticated_request
    @convert_json_to_arguments
    @check_permissions(Permissions.UNINSTALL)
    def delete(self, agent_id):
        username = self.get_current_user().encode('utf-8')
        customer_name = (
            get_user_property(username, UserKeys.CurrentCustomer)
        )
        uri = self.request.uri
        method = self.request.method
        try:
            app_ids = self.arguments.get('app_ids')
            epoch_time = self.arguments.get('time', None)
            label = self.arguments.get('label', None)
            restart = self.arguments.get('restart', 'none')
            cpu_throttle = self.arguments.get('cpu_throttle', 'normal')
            net_throttle = self.arguments.get('net_throttle', 0)
            if not epoch_time and not label and app_ids:
                operation = (
                    StorePatchingOperation(
                        username, customer_name, uri, method
                    )
                )
                results = (
                    operation.uninstall_apps(
                        app_ids, cpu_throttle,
                        net_throttle, restart,
                        agentids=[agent_id]
                    )
                )
                self.set_status(results['http_status'])
                self.set_header('Content-Type', 'application/json')
                self.write(json.dumps(results, indent=4))

            elif epoch_time and label and app_ids:
                sched = self.application.scheduler
                date_time = datetime.fromtimestamp(int(epoch_time))
                job = (
                    {
                        'pkg_type': 'custom_apps',
                        'restart': restart,
                        'app_ids': app_ids
                    }
                )
                add_uninstall_job = (
                    schedule_once(
                        sched, customer_name, username,
                        [agent_id], operation='uninstall',
                        name=label, date=date_time, uri=uri,
                        method=method, job_extra=job
                    )
                )
                result = add_uninstall_job
                self.set_header('Content-Type', 'application/json')
                self.write(json.dumps(result))

        except Exception as e:
            results = (
                GenericResults(
                    username, uri, method
                ).something_broke(agent_id, 'install_custom_apps', e)
            )
            logger.exception(e)
            self.set_status(results['http_status'])
            self.set_header('Content-Type', 'application/json')
            self.write(json.dumps(results, indent=4))


class TagIdCustomAppsHandler(BaseHandler):
    @authenticated_request
    def get(self, tag_id):
        username = self.get_current_user().encode('utf-8')
        customer_name = (
            get_user_property(username, UserKeys.CurrentCustomer)
        )
        query = self.get_argument('query', None)
        count = int(self.get_argument('count', 30))
        offset = int(self.get_argument('offset', 0))
        status = self.get_argument('status', 'installed')
        severity = self.get_argument('severity', None)
        sort = self.get_argument('sort', 'asc')
        sort_by = self.get_argument('sort_by', CustomAppsKeys.Name)
        uri = self.request.uri
        method = self.request.method
        patches = (
            RetrieveCustomAppsByTagId(
                username, customer_name, tag_id,
                uri, method, count, offset,
                sort, sort_by
            )
        )
        if not query and not severity and status:
            results = patches.filter_by_status(status)

        elif not query and status and severity:
            results = patches.filter_by_status_and_sev(status, severity)

        elif severity and not query and not status:
            results = patches.filter_by_severity(severity)

        elif severity and status and query:
            results = (
                patches.filter_by_status_and_query_by_name_and_sev(
                    query, status, severity
                )
            )

        elif status and query:
            results = (
                patches.filter_by_status_and_query_by_name(
                    query, status
                )
            )

        elif severity and query:
            results = (
                patches.filter_by_sev_and_query_by_name(
                    query, severity
                )
            )

        elif query and not severity and not status:
            results = patches.query_by_name(query)

        else:
            results = (
                GenericResults(
                    username, uri, method
                ).incorrect_arguments()
            )

        self.set_status(results['http_status'])
        self.set_header('Content-Type', 'application/json')
        self.write(json.dumps(results, indent=4))


    @authenticated_request
    @convert_json_to_arguments
    @check_permissions(Permissions.INSTALL)
    def put(self, tag_id):
        username = self.get_current_user().encode('utf-8')
        customer_name = (
            get_user_property(username, UserKeys.CurrentCustomer)
        )
        uri = self.request.uri
        method = self.request.method
        try:
            app_ids = self.arguments.get('app_ids')
            epoch_time = self.arguments.get('time', None)
            label = self.arguments.get('label', None)
            restart = self.arguments.get('restart', 'none')
            cpu_throttle = self.arguments.get('cpu_throttle', 'normal')
            net_throttle = self.arguments.get('net_throttle', 0)
            if not epoch_time and not label and app_ids:
                operation = (
                    StorePatchingOperation(
                        username, customer_name, uri, method
                    )
                )
                results = (
                    operation.install_custom_apps(
                        app_ids, cpu_throttle,
                        net_throttle, restart,
                        tag_id=tag_id
                    )
                )
                self.set_status(results['http_status'])
                self.set_header('Content-Type', 'application/json')
                self.write(json.dumps(results, indent=4))

            elif epoch_time and label and app_ids:
                date_time = datetime.fromtimestamp(int(epoch_time))
                sched = self.application.scheduler
                job = (
                    {
                        'cpu_throttle': cpu_throttle,
                        'net_throttle': net_throttle,
                        'restart': restart,
                        'pkg_type': 'custom_apps',
                        'app_ids': app_ids
                    }
                )
                add_install_job = (
                    schedule_once(
                        sched, customer_name, username,
                        tag_ids=[tag_id], operation='install',
                        name=label, date=date_time, uri=uri,
                        method=method, job_extra=job
                    )
                )
                result = add_install_job
                self.set_header('Content-Type', 'application/json')
                self.write(json.dumps(result))

        except Exception as e:
            results = (
                GenericResults(
                    username, uri, method
                ).something_broke(tag_id, 'install_custom_apps', e)
            )
            logger.exception(e)
            self.set_status(results['http_status'])
            self.set_header('Content-Type', 'application/json')
            self.write(json.dumps(results, indent=4))

    @authenticated_request
    @convert_json_to_arguments
    @check_permissions(Permissions.UNINSTALL)
    def delete(self, tag_id):
        username = self.get_current_user().encode('utf-8')
        customer_name = (
            get_user_property(username, UserKeys.CurrentCustomer)
        )
        uri = self.request.uri
        method = self.request.method
        try:
            app_ids = self.arguments.get('app_ids')
            epoch_time = self.arguments.get('time', None)
            label = self.arguments.get('label', None)
            restart = self.arguments.get('restart', 'none')
            cpu_throttle = self.arguments.get('cpu_throttle', 'normal')
            net_throttle = self.arguments.get('net_throttle', 0)
            if not epoch_time and not label and app_ids:
                operation = (
                    StorePatchingOperation(
                        username, customer_name, uri, method
                    )
                )
                results = (
                    operation.uninstall_apps(
                        app_ids, cpu_throttle,
                        net_throttle, restart,
                        tag_id=tag_id
                    )
                )
                self.set_status(results['http_status'])
                self.set_header('Content-Type', 'application/json')
                self.write(json.dumps(results, indent=4))

            elif epoch_time and label and app_ids:
                date_time = datetime.fromtimestamp(int(epoch_time))
                sched = self.application.scheduler
                job = (
                    {
                        'restart': restart,
                        'pkg_type': 'custom_apps',
                        'app_ids': app_ids
                    }
                )
                add_uninstall_job = (
                    schedule_once(
                        sched, customer_name, username,
                        tag_ids=[tag_id], operation='uninstall',
                        name=label, date=date_time, uri=uri,
                        method=method, job_extra=job
                    )
                )
                result = add_uninstall_job
                self.set_header('Content-Type', 'application/json')
                self.write(json.dumps(result))

        except Exception as e:
            results = (
                GenericResults(
                    username, uri, method
                ).something_broke(tag_id, 'install_custom_apps', e)
            )
            logger.exception(e)
            self.set_status(results['http_status'])
            self.set_header('Content-Type', 'application/json')
            self.write(json.dumps(results, indent=4))


class AppIdCustomAppsHandler(BaseHandler):
    @authenticated_request
    def get(self, app_id):
        username = self.get_current_user().encode('utf-8')
        customer_name = (
            get_user_property(username, UserKeys.CurrentCustomer)
        )
        uri = self.request.uri
        method = self.request.method
        patches = (
            RetrieveCustomAppsByAppId(
                username, customer_name, app_id,
                uri, method
            )
        )
        results = patches.get_by_app_id(stats=True)
        self.set_status(results['http_status'])
        self.set_header('Content-Type', 'application/json')
        self.write(json.dumps(results, indent=4))

    @authenticated_request
    @convert_json_to_arguments
    @check_permissions(Permissions.ADMINISTRATOR)
    def post(self, app_id):
        username = self.get_current_user().encode('utf-8')
        customer_name = (
            get_user_property(username, UserKeys.CurrentCustomer)
        )
        uri = self.request.uri
        method = self.request.method
        try:
            severity = self.arguments.get('severity', None)
            install_options = self.get_arguments.get('install_options', None)
            if severity:
                if severity in CommonSeverityKeys.ValidRvSeverities:
                    severity = severity.capitalize()
                    sev_data = (
                        {
                            AppsKeys.RvSeverity: severity
                        }
                    )
                    update_app_data_by_app_id(
                        app_id, sev_data, AppCollections.CustomApps
                    )
                    results = (
                        GenericResults(
                            username, uri, method
                        ).object_updated(app_id, 'app severity', [sev_data])
                    )
                    self.set_status(results['http_status'])
                    self.set_header('Content-Type', 'application/json')
                    self.write(json.dumps(results, indent=4))

                else:
                    results = (
                        PackageResults(
                            username, uri, method
                        ).invalid_severity(severity)
                    )
                    self.set_status(results['http_status'])
                    self.set_header('Content-Type', 'application/json')
                    self.write(json.dumps(results, indent=4))

            elif install_options:
                install_options_hash = (
                    {
                        CustomAppsKeys.CliOptions: install_options
                    }
                )

                update_app_data_by_app_id(
                    app_id, sev_data, AppCollections.CustomApps
                )

                results = (
                    GenericResults(
                        username, uri, method
                    ).object_updated(app_id, 'install options updated', [install_options_hash])
                )

                self.set_status(results['http_status'])
                self.set_header('Content-Type', 'application/json')
                self.write(json.dumps(results, indent=4))


        except Exception as e:
            results = (
                GenericResults(
                    username, uri, method
                ).something_broke(app_id, 'update_severity', e)
            )
            logger.exception(e)
            self.set_status(results['http_status'])
            self.set_header('Content-Type', 'application/json')
            self.write(json.dumps(results, indent=4))


    @authenticated_request
    @convert_json_to_arguments
    @check_permissions(Permissions.INSTALL)
    def put(self, app_id):
        username = self.get_current_user().encode('utf-8')
        customer_name = (
            get_user_property(username, UserKeys.CurrentCustomer)
        )
        uri = self.request.uri
        method = self.request.method
        try:
            agent_ids = self.arguments.get('agent_ids')
            epoch_time = self.arguments.get('time', None)
            label = self.arguments.get('label', None)
            restart = self.arguments.get('restart', 'none')
            cpu_throttle = self.arguments.get('cpu_throttle', 'normal')
            net_throttle = self.arguments.get('net_throttle', 0)
            if not epoch_time and not label and agent_ids:
                operation = (
                    StorePatchingOperation(
                        username, customer_name, uri, method
                    )
                )
                results = (
                    operation.install_custom_apps(
                        [app_id], cpu_throttle,
                        net_throttle, restart,
                        agentids=agent_ids
                    )
                )
                self.set_status(results['http_status'])
                self.set_header('Content-Type', 'application/json')
                self.write(json.dumps(results, indent=4))

            elif epoch_time and label and agent_ids:
                date_time = datetime.fromtimestamp(int(epoch_time))
                sched = self.application.scheduler
                job = (
                    {
                        'operation': 'install',
                        'cpu_throttle': cpu_throttle,
                        'net_throttle': net_throttle,
                        'restart': restart,
                        'app_ids': [app_id]
                    }
                )
                add_install_job = (
                    schedule_once(
                        sched, customer_name, username,
                        agent_ids=[agent_ids], operation='install',
                        name=label, date=date_time, uri=uri,
                        method=method, job_extra=job
                    )
                )
                result = add_install_job
                self.set_header('Content-Type', 'application/json')
                self.write(json.dumps(result))

        except Exception as e:
            results = (
                GenericResults(
                    username, uri, method
                ).something_broke(app_id, 'install_custom_apps', e)
            )
            logger.exception(e)
            self.set_status(results['http_status'])
            self.set_header('Content-Type', 'application/json')
            self.write(json.dumps(results, indent=4))


    @authenticated_request
    @convert_json_to_arguments
    @check_permissions(Permissions.UNINSTALL)
    def delete(self, app_id):
        username = self.get_current_user().encode('utf-8')
        customer_name = (
            get_user_property(username, UserKeys.CurrentCustomer)
        )
        uri = self.request.uri
        method = self.request.method
        try:
            agent_ids = self.arguments.get('agent_ids')
            epoch_time = self.arguments.get('time', None)
            label = self.arguments.get('label', None)
            restart = self.arguments.get('restart', 'none')
            cpu_throttle = self.arguments.get('cpu_throttle', 'normal')
            net_throttle = self.arguments.get('net_throttle', 0)
            if not epoch_time and not label and app_id:
                operation = (
                    StorePatchingOperation(
                        username, customer_name, uri, method
                    )
                )
                results = (
                    operation.uninstall_apps(
                        [app_id], cpu_throttle,
                        net_throttle, restart,
                        agentids=agent_ids
                    )
                )
                self.set_status(results['http_status'])
                self.set_header('Content-Type', 'application/json')
                self.write(json.dumps(results, indent=4))

            elif epoch_time and label and agent_ids:
                sched = self.application.scheduler
                date_time = datetime.fromtimestamp(int(epoch_time))
                job = (
                    {
                        'restart': restart,
                        'pkg_type': 'custom_apps',
                        'app_ids': [app_id]
                    }
                )
                add_uninstall_job = (
                    schedule_once(
                        sched, customer_name, username,
                        agent_ids=[agent_ids], operation='uninstall',
                        name=label, date=date_time, uri=uri,
                        method=method, job_extra=job
                    )
                )
                result = add_uninstall_job
                self.set_header('Content-Type', 'application/json')
                self.write(json.dumps(result))

        except Exception as e:
            results = (
                GenericResults(
                    username, uri, method
                ).something_broke(app_id, 'install_custom_apps', e)
            )
            logger.exception(e)
            self.set_status(results['http_status'])
            self.set_header('Content-Type', 'application/json')
            self.write(json.dumps(results, indent=4))


class GetAgentsByCustomAppIdHandler(BaseHandler):
    @authenticated_request
    def get(self, app_id):
        username = self.get_current_user().encode('utf-8')
        customer_name = (
            get_user_property(username, UserKeys.CurrentCustomer)
        )
        query = self.get_argument('query', None)
        count = int(self.get_argument('count', 30))
        offset = int(self.get_argument('offset', 0))
        status = self.get_argument('status', 'installed')
        uri = self.request.uri
        method = self.request.method
        agents = (
            RetrieveAgentsByCustomAppId(
                username, customer_name, app_id,
                uri, method, count, offset
            )
        )

        if status and not query:
            results = (
                agents.filter_by_status(
                    status
                )
            )

        elif status and query:
            results = (
                agents.filter_by_status_and_query_by_name(
                    query, status
                )
            )

        else:
            results = (
                GenericResults(
                    username, uri, method
                ).incorrect_arguments()
            )

        self.set_status(results['http_status'])
        self.set_header('Content-Type', 'application/json')
        self.write(json.dumps(results, indent=4))


    @authenticated_request
    @convert_json_to_arguments
    @check_permissions(Permissions.INSTALL)
    def put(self, app_id):
        username = self.get_current_user().encode('utf-8')
        customer_name = (
            get_user_property(username, UserKeys.CurrentCustomer)
        )
        uri = self.request.uri
        method = self.request.method
        try:
            agent_ids = self.arguments.get('agent_ids')
            epoch_time = self.arguments.get('time', None)
            label = self.arguments.get('label', None)
            restart = self.arguments.get('restart', 'none')
            cpu_throttle = self.arguments.get('cpu_throttle', 'normal')
            net_throttle = self.arguments.get('net_throttle', 0)
            if not epoch_time and not label and app_id:
                operation = (
                    StorePatchingOperation(
                        username, customer_name, uri, method
                    )
                )
                results = (
                    operation.install_custom_apps(
                        [app_id], cpu_throttle,
                        net_throttle, restart,
                        agentids=agent_ids
                    )
                )
                self.set_status(results['http_status'])
                self.set_header('Content-Type', 'application/json')
                self.write(json.dumps(results, indent=4))

            elif epoch_time and label and agent_ids:
                date_time = datetime.fromtimestamp(int(epoch_time))
                sched = self.application.scheduler
                job = (
                    {
                        'cpu_throttle': cpu_throttle,
                        'net_throttle': net_throttle,
                        'pkg_type': 'custom_apps',
                        'restart': restart,
                        'app_ids': [app_id]
                    }
                )
                add_install_job = (
                    schedule_once(
                        sched, customer_name, username,
                        agent_ids=agent_ids, operation='install',
                        name=label, date=date_time, uri=uri,
                        method=method, job_extra=job
                    )
                )
                result = add_install_job
                self.set_header('Content-Type', 'application/json')
                self.write(json.dumps(result))

        except Exception as e:
            results = (
                GenericResults(
                    username, uri, method
                ).something_broke(app_id, 'install_custom_apps', e)
            )
            logger.exception(e)
            self.set_status(results['http_status'])
            self.set_header('Content-Type', 'application/json')
            self.write(json.dumps(results, indent=4))


    @authenticated_request
    @convert_json_to_arguments
    @check_permissions(Permissions.UNINSTALL)
    def delete(self, app_id):
        username = self.get_current_user().encode('utf-8')
        customer_name = (
            get_user_property(username, UserKeys.CurrentCustomer)
        )
        uri = self.request.uri
        method = self.request.method
        try:
            agent_ids = self.arguments.get('agent_ids')
            epoch_time = self.arguments.get('time', None)
            label = self.arguments.get('label', None)
            restart = self.arguments.get('restart', 'none')
            cpu_throttle = self.arguments.get('cpu_throttle', 'normal')
            net_throttle = self.arguments.get('net_throttle', 0)
            if not epoch_time and not label and app_id:
                operation = (
                    StorePatchingOperation(
                        username, customer_name, uri, method
                    )
                )
                results = (
                    operation.uninstall_apps(
                        [app_id], cpu_throttle,
                        net_throttle, restart,
                        agentids=agent_ids
                    )
                )
                self.set_status(results['http_status'])
                self.set_header('Content-Type', 'application/json')
                self.write(json.dumps(results, indent=4))

            elif epoch_time and label and agent_ids:
                date_time = datetime.fromtimestamp(int(epoch_time))
                sched = self.application.scheduler
                job = (
                    {
                        'restart': restart,
                        'pkg_type': 'custom_apps',
                        'app_ids': [app_id]
                    }
                )
                add_uninstall_job = (
                    schedule_once(
                        sched, customer_name, username,
                        agent_ids=agent_ids, operation='uninstall',
                        name=label, date=date_time, uri=uri,
                        method=method, job_extra=job
                    )
                )
                result = add_uninstall_job
                self.set_header('Content-Type', 'application/json')
                self.write(json.dumps(result))

        except Exception as e:
            results = (
                GenericResults(
                    username, uri, method
                ).something_broke(app_id, 'install_custom_apps', e)
            )
            logger.exception(e)
            self.set_status(results['http_status'])
            self.set_header('Content-Type', 'application/json')
            self.write(json.dumps(results, indent=4))


class CustomAppsHandler(BaseHandler):
    @authenticated_request
    def get(self):
        username = self.get_current_user().encode('utf-8')
        customer_name = (
            get_user_property(username, UserKeys.CurrentCustomer)
        )
        query = self.get_argument('query', None)
        count = int(self.get_argument('count', 30))
        offset = int(self.get_argument('offset', 0))
        status = self.get_argument('status', None)
        severity = self.get_argument('severity', None)
        sort = self.get_argument('sort', 'asc')
        sort_by = self.get_argument('sort_by', CustomAppsKeys.Name)
        hidden = self.get_argument('hidden', 'false')
        if hidden == 'false':
            hidden = CommonKeys.NO
        else:
            hidden = CommonKeys.YES
        uri = self.request.uri
        method = self.request.method
        patches = (
            RetrieveCustomApps(
                username, customer_name,
                uri, method, count, offset,
                sort, sort_by, show_hidden=hidden
            )
        )
        if not query and not severity and not status:
            results = patches.get_all_apps()

        elif not query and status and severity:
            results = patches.filter_by_status_and_sev(status, severity)

        elif severity and not query and not status:
            results = patches.filter_by_severity(severity)

        elif severity and status and query:
            results = (
                patches.filter_by_status_and_query_by_name_and_sev(
                    query, status, severity
                )
            )

        elif status and not query and not severity:
            results = (
                patches.filter_by_status(
                    status
                )
            )

        elif status and query:
            results = (
                patches.filter_by_status_and_query_by_name(
                    query, status
                )
            )

        elif severity and query:
            results = (
                patches.filter_by_sev_and_query_by_name(
                    query, severity
                )
            )

        elif query and not severity and not status:
            results = patches.query_by_name(query)

        else:
            results = (
                GenericResults(
                    username, uri, method
                ).incorrect_arguments()
            )

        self.set_status(results['http_status'])
        self.set_header('Content-Type', 'application/json')
        self.write(json.dumps(results, indent=4))

    @authenticated_request
    @convert_json_to_arguments
    @check_permissions(Permissions.ADMINISTRATOR)
    def put(self):
        username = self.get_current_user().encode('utf-8')
        uri = self.request.uri
        method = self.request.method
        try:
            app_ids = self.arguments.get('app_ids')
            toggle = self.arguments.get('hide', 'toggle')
            results = (
                toggle_hidden_status(
                    app_ids, toggle,
                    AppCollections.CustomApps,
                    username, uri, method
                )
            )

            self.set_status(results['http_status'])
            self.set_header('Content-Type', 'application/json')
            self.write(json.dumps(results, indent=4))

        except Exception as e:
            logger.exception(e)
            results = (
                GenericResults(
                    username, uri, method
                ).something_broke(app_ids, 'toggle hidden on custom_apps', e)
            )

            self.set_status(results['http_status'])
            self.set_header('Content-Type', 'application/json')
            self.write(json.dumps(results, indent=4))

    @authenticated_request
    @convert_json_to_arguments
    @check_permissions(Permissions.UNINSTALL)
    def delete(self):
        username = self.get_current_user().encode('utf-8')
        customer_name = (
            get_user_property(username, UserKeys.CurrentCustomer)
        )
        uri = self.request.uri
        method = self.request.method
        try:
            app_ids = self.arguments.get('app_ids') # The UI needs to past the options as the body not as arguments
            appids_deleted = 0
            appids_failed = 0
            for appid in app_ids:
                deleted = (
                    delete_app_from_vfense(
                        appid, AppCollections.CustomApps,
                        AppCollections.CustomAppsPerAgent
                    )
                )
                if deleted:
                    appids_deleted +=1
                else:
                    appids_failed +=1

            results = (
                PackageResults(
                    username, uri, method
                ).packages_deleted(app_ids, appids_deleted, appids_failed)
            )

            self.set_status(results['http_status'])
            self.set_header('Content-Type', 'application/json')
            self.write(json.dumps(results, indent=4))

        except Exception as e:
            logger.exception(e)
            results = (
                GenericResults(
                    username, uri, method
                ).something_broke(app_ids, 'failed to delete custom_apps', e)
            )

            self.set_status(results['http_status'])
            self.set_header('Content-Type', 'application/json')
            self.write(json.dumps(results, indent=4))
