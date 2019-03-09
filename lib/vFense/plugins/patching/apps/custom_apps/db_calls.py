from vFense.db.client import db_create_close, r
from vFense.plugins.patching import *
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
            .table(AppCollections.CustomAppsPerAgent)
            .get_all(
                [app_id, customer_name],
                index=CustomAppsPerAgentIndexes.AppIdAndCustomer
            )
            .group(CustomAppsPerAgentKeys.Status)
            .count()
            .ungroup()
            .run(conn)
        )
        if apps:
            for i in apps:
                new_data = i['reduction']
                new_data = (
                    {
                        CustomAppsPerAgentKeys.Status: i['group'][CustomAppsPerAgentKeys.Status],
                        COUNT: i['reduction'],
                        NAME: i['group'][CustomAppsPerAgentKeys.Status].capitalize()
                    }
                )
                data.append(new_data)

        statuses = [x['status'] for x in data]
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
            .table(AppCollections.CustomAppsPerAgent)
            .get_all(app_id, index=CustomAppsPerAgentKeys.AppId)
            .eq_join(CustomAppsPerAgentKeys.AgentId, r.table(AgentsCollection))
            .zip()
            .group(
                lambda x: x[CustomAppsPerAgentKeys.Status]
            )
            .map(
                lambda x:
                {
                    AGENTS:
                    [
                        {
                            AgentKeys.ComputerName: x[AgentKeys.ComputerName],
                            AgentKeys.DisplayName: x[AgentKeys.DisplayName],
                            CustomAppsPerAgentKeys.AgentId: x[CustomAppsPerAgentKeys.AgentId]
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
                new_data[CustomAppsPerAgentKeys.Status] = i['group']
                data.append(new_data)

        statuses = [x['status'] for x in data]
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
            .table(AppCollections.CustomAppsPerAgent)
            .get_all(agent_id, index=CustomAppsPerAgentKeys.AgentId)
            .group(CustomAppsPerAgentKeys.Status)
            .count()
            .ungroup()
            .run(conn)
        )
        if apps:
            for i in apps:
                new_data = i['reduction']
                new_data = (
                    {
                        CustomAppsPerAgentKeys.Status: i['group'][CustomAppsPerAgentKeys.Status],
                        COUNT: i['reduction'],
                        NAME: i['group'][CustomAppsPerAgentKeys.Status].capitalize()
                    }
                )
                data.append(new_data)

        statuses = [x['status'] for x in data]
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
            .table(CustomAppsPerTagCollection)
            .get_all(tag_id, index=CustomAppsPerTagKeys.TagId)
            .group(CustomAppsPerTagKeys.Status)
            .count()
            .ungroup()
            .run(conn)
        )
        if apps:
            for i in apps:
                new_data = i['reduction']
                new_data = (
                    {
                        CustomAppsPerTagKeys.Status: i['group'][CustomAppsPerTagKeys.Status],
                        COUNT: i['reduction'],
                        NAME: i['group'][CustomAppsPerTagKeys.Status].capitalize()
                    }
                )
                data.append(new_data)

        statuses = [x['status'] for x in data]
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
