from vFense.db.client import db_create_close, r
from vFense.plugins.patching import *
from vFense.plugins.patching._constants import CommonAppKeys
from vFense.core.agent import *
from vFense.errorz.error_messages import GenericResults, PackageResults

import logging
import logging.config
from vFense import VFENSE_LOGGING_CONFIG

logging.config.fileConfig(VFENSE_LOGGING_CONFIG)
logger = logging.getLogger('rvapi')


@db_create_close
def get_all_stats_by_appid(username, customer_name,
                          uri, method, app_id, conn=None):
    data = []
    try:
        apps = (
            r
            .table(AppCollections.vFenseAppsPerAgent)
            .get_all(
                [app_id, customer_name],
                index=AgentAppsPerAgentIndexes.AppIdAndCustomer
            )
            .group(AgentAppsPerAgentKeys.Status)
            .count()
            .ungroup()
            .run(conn)
        )
        if apps:
            for i in apps:
                new_data = i['reduction']
                new_data = (
                    {
                        AgentAppsPerAgentKeys.Status: i['group'][AgentAppsPerAgentKeys.Status],
                        COUNT: i['reduction'],
                        NAME: i['group'][AgentAppsPerAgentKeys.Status].capitalize()
                    }
                )
                data.append(new_data)

        statuses = map(lambda x: x['status'], data)
        difference = set(ValidPackageStatuses).difference(statuses)
        if len(difference) > 0:
            for status in difference:
                status = {
                    COUNT: 0,
                    STATUS: status,
                    NAME: status.capitalize()
                }
                data.append(status)

        results = (
            GenericResults(
                username, uri, method
            ).information_retrieved(data, len(data))
        )

        logger.info(results)

    except Exception as e:
        results = (
            GenericResults(
                username, uri, method
            ).something_broke('getting_pkg_stats', 'updates', e)
        )

        logger.info(results)

    return(results)


@db_create_close
def get_all_agents_per_appid(username, customer_name,
                            uri, method, app_id, conn=None):
    data = []
    try:
        agents = (
            r
            .table(AppCollections.vFenseAppsPerAgent)
            .get_all(app_id, index=AgentAppsPerAgentKeys.AppId)
            .eq_join(AgentAppsPerAgentKeys.AgentId, r.table(AgentsCollection))
            .zip()
            .group(
                lambda x: x[AgentAppsPerAgentKeys.Status]
            )
            .map(
                lambda x:
                {
                    AGENTS:
                    [
                        {
                            AgentKeys.ComputerName: x[AgentKeys.ComputerName],
                            AgentKeys.DisplayName: x[AgentKeys.DisplayName],
                            AgentAppsPerAgentKeys.AgentId: x[AgentAppsPerAgentKeys.AgentId]
                        }
                    ],
                    COUNT: 1
                }
            )
            .reduce(
                lambda x, y:
                {
                    AGENTS: x[AGENTS] + y[AGENTS],
                    COUNT: x[COUNT] + y[COUNT]
                }
            )
            .ungroup()
            .run(conn)
        )
        if agents:
            for i in agents:
                new_data = i['reduction']
                new_data[AgentAppsPerAgentKeys.Status] = i['group']
                data.append(new_data)

        statuses = map(lambda x: x['status'], data)
        difference = set(ValidPackageStatuses).difference(statuses)
        if len(difference) > 0:
            for status in difference:
                status = {
                    COUNT: 0,
                    AGENTS: [],
                    STATUS: status
                }
                data.append(status)

        results = (
            GenericResults(
                username, uri, method
            ).information_retrieved(data, len(data))
        )

        logger.info(results)

    except Exception as e:
        results = (
            GenericResults(
                username, uri, method
            ).something_broke('getting_pkg_stats', 'updates', e)
        )

        logger.info(results)

    return(results)


@db_create_close
def get_all_stats_by_agentid(username, customer_name,
                              uri, method, agent_id, conn=None):
    data = []
    try:
        apps = (
            r
            .table(AppCollections.vFenseAppsPerAgent)
            .get_all(agent_id, index=AgentAppsPerAgentKeys.AgentId)
            .group(AgentAppsPerAgentKeys.Status)
            .count()
            .ungroup()
            .run(conn)
        )
        if apps:
            for i in apps:
                new_data = i['reduction']
                new_data = (
                    {
                        AgentAppsPerAgentKeys.Status: i['group'][AgentAppsPerAgentKeys.Status],
                        COUNT: i['reduction'],
                        NAME: i['group'][AgentAppsPerAgentKeys.Status].capitalize()
                    }
                )
                data.append(new_data)

        statuses = map(lambda x: x['status'], data)
        difference = set(ValidPackageStatuses).difference(statuses)
        if len(difference) > 0:
            for status in difference:
                status = {
                    COUNT: 0,
                    STATUS: status,
                    NAME: status.capitalize()
                }
                data.append(status)

        results = (
            GenericResults(
                username, uri, method
            ).information_retrieved(data, len(data))
        )

        logger.info(results)

    except Exception as e:
        results = (
            GenericResults(
                username, uri, method
            ).something_broke('getting_pkg_stats', 'updates', e)
        )
        logger.info(results)

    return(results)

@db_create_close
def get_all_stats_by_tagid(username, customer_name,
                           uri, method, tag_id, conn=None):
    data = []
    try:
        apps = (
            r
            .table(AgentAppsPerTagCollection)
            .get_all(tag_id, index=AgentAppsPerTagKeys.TagId)
            .group(AgentAppsPerTagKeys.Status)
            .count()
            .ungroup()
            .run(conn)
        )
        if apps:
            for i in apps:
                new_data = i['reduction']
                new_data = (
                    {
                        AgentAppsPerTagKeys.Status: i['group'][AgentAppsPerTagKeys.Status],
                        COUNT: i['reduction'],
                        NAME: i['group'][AgentAppsPerTagKeys.Status].capitalize()
                    }
                )
                data.append(new_data)

        statuses = map(lambda x: x['status'], data)
        difference = set(ValidPackageStatuses).difference(statuses)
        if len(difference) > 0:
            for status in difference:
                status = {
                    COUNT: 0,
                    STATUS: status,
                    NAME: status.capitalize()
                }
                data.append(status)

        results = (
            GenericResults(
                username, uri, method
            ).information_retrieved(data, len(data))
        )

        logger.info(results)

    except Exception as e:
        results = (
            GenericResults(
                username, uri, method
            ).something_broke('getting_pkg_stats', 'updates', e)
        )
        logger.info(results)

    return(results)

@db_create_close
def insert_into_agent_apps(customer_name, app, conn=None):

    collection=AppCollections.vFenseApps

    exists = []
    try:
        exists = (
            r
            .table(collection)
            .get(app[vFenseAppsKeys.AppId])
            .run(conn)
        )

    except Exception as e:
        msg = (
            'Failed to get unique app_id %s, error: %s' %
            (app[AppsKeys.AppId], e)
        )
        logger.error(e)

    status = app.pop(AppsPerAgentKeys.Status)

    if not exists:

        if (len(app[AppsKeys.FileData]) > 0 and status == CommonAppKeys.AVAILABLE or
                len(app[AppsKeys.FileData]) > 0 and status == CommonAppKeys.INSTALLED):
            app[AppsKeys.FilesDownloadStatus] = PackageCodes.FilePendingDownload

        elif len(app[AppsKeys.FileData]) == 0 and status == CommonAppKeys.AVAILABLE:
            app[AppsKeys.FilesDownloadStatus] = PackageCodes.MissingUri

        elif len(app[AppsKeys.FileData]) == 0 and status == CommonAppKeys.INSTALLED:
            app[AppsKeys.FilesDownloadStatus] = PackageCodes.FileNotRequired

        try:
            (
                r
                .table(AppCollections.UniqueApplications)
                .insert(app)
                .run(conn)
            )

        except Exception as e:
            msg = (
                'Failed to insert %s into unique_applications, error: %s' %
                (app[AppsKeys.AppId], e)
            )
            logger.exception(msg)

    return(app)


@db_create_close
def add_or_update_applications(collection=AppCollections.AppsPerAgent,
        pkg_list=[], delete_afterwards=True, conn=None):

    completed = False
    inserted_count = 0
    updated = None
    replaced_count = 0
    deleted_count = 0
    pkg_count = len(pkg_list)
    last_modified_time = mktime(datetime.now().timetuple())
    if pkg_count > 0:
        for pkg in pkg_list:
            pkg['last_modified_time'] = r.epoch_time(last_modified_time)

            try:
                updated = (
                    r
                    .table(collection)
                    .insert(pkg, conflict="replace")
                    .run(conn)
                )
                logger.info(updated)
                inserted_count += updated['inserted']
                replaced_count += updated['replaced']

            except Exception as e:
                logger.exception(e)

        try:
            if delete_afterwards:
                deleted = (
                    r
                    .table(collection)
                    .get_all(
                        pkg[AppsPerAgentKeys.AgentId],
                        index=AppsPerAgentIndexes.AgentId
                    )
                    .filter(
                        r.row['last_modified_time'] < r.epoch_time(
                            last_modified_time)
                    )
                    .delete()
                    .run(conn)
                )
                deleted_count += deleted['deleted']
        except Exception as e:
            logger.exception(e)

    return(
        {
            'pass': completed,
            'inserted': inserted_count,
            'replaced': replaced_count,
            'deleted': deleted_count,
            'pkg_count': pkg_count,
        }
    )

