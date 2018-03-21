from vFense.db.client import db_create_close, r
from vFense.plugins.patching import *
from vFense.plugins.patching._constants import CommonAppKeys
from vFense.core.agent import *
from vFense.errorz.error_messages import GenericResults

import logging
import logging.config
from vFense import VFENSE_LOGGING_CONFIG

logging.config.fileConfig(VFENSE_LOGGING_CONFIG)
logger = logging.getLogger('rvapi')


@db_create_close
def get_all_stats_by_appid(username, customer_name, uri, method, app_id,
        collection=AppCollections.AppsPerAgent, conn=None):

    if collection == AppCollections.AppsPerAgent:
        CurrentAppsPerAgentCollection = AppCollections.AppsPerAgent
        CurrentAppsPerAgentKeys = AppsPerAgentKeys
        CurrentAppsPerAgentIndexes = AppsPerAgentIndexes

    elif collection == AppCollections.SupportedAppsPerAgent:
        CurrentAppsPerAgentCollection = AppCollections.SupportedAppsPerAgent
        CurrentAppsPerAgentKeys = SupportedAppsPerAgentKeys
        CurrentAppsPerAgentIndexes = SupportedAppsPerAgentIndexes

    elif collection == AppCollections.CustomAppsPerAgent:
        CurrentAppsPerAgentCollection = AppCollections.CustomAppsPerAgent
        CurrentAppsPerAgentKeys = CustomAppsPerAgentKeys
        CurrentAppsPerAgentIndexes = CustomAppsPerAgentIndexes

    elif collection == AppCollections.vFenseAppsPerAgent:
        CurrentAppsPerAgentCollection = AppCollections.vFenseAppsPerAgent
        CurrentAppsPerAgentKeys = AgentAppsPerAgentKeys
        CurrentAppsPerAgentIndexes = AgentAppsPerAgentIndexes

    try:
        data = []
        apps = (
            r
            .table(CurrentAppsPerAgentCollection)
            .get_all(
                [app_id, customer_name],
                index=CurrentAppsPerAgentIndexes.AppIdAndCustomer
            )
            .group(CurrentAppsPerAgentKeys.Status)
            .count()
            .ungroup()
            .run(conn)
        )
        if apps:
            for i in apps:
                new_data = i['reduction']
                new_data = (
                    {
                        CurrentAppsPerAgentKeys.Status: i['group'],
                        CommonAppKeys.COUNT: i['reduction'],
                        CommonAppKeys.NAME: i['group'].capitalize()
                    }
                )
                data.append(new_data)

        statuses = map(lambda x: x['status'], data)
        difference = set(CommonAppKeys.ValidPackageStatuses).difference(statuses)
        if len(difference) > 0:
            for status in difference:
                status = {
                    CommonAppKeys.COUNT: 0,
                    CommonAppKeys.STATUS: status,
                    CommonAppKeys.NAME: status.capitalize()
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
def get_all_agents_per_appid(username, customer_name, uri, method, app_id,
    collection=AppCollections.AppsPerAgent, conn=None):

    if collection == AppCollections.AppsPerAgent:
        CurrentAppsPerAgentCollection = AppCollections.AppsPerAgent
        CurrentAppsPerAgentKeys = AppsPerAgentKeys

    elif collection == AppCollections.SupportedAppsPerAgent:
        CurrentAppsPerAgentCollection = AppCollections.SupportedAppsPerAgent
        CurrentAppsPerAgentKeys = SupportedAppsPerAgentKeys

    elif collection == AppCollections.CustomAppsPerAgent:
        CurrentAppsPerAgentCollection = AppCollections.CustomAppsPerAgent
        CurrentAppsPerAgentKeys = CustomAppsPerAgentKeys

    elif collection == AppCollections.vFenseAppsPerAgent:
        CurrentAppsPerAgentCollection = AppCollections.vFenseAppsPerAgent
        CurrentAppsPerAgentKeys = AgentAppsPerAgentKeys

    data = []
    try:
        data = []
        agents = (
            r
            .table(CurrentAppsPerAgentCollection)
            .get_all(app_id, index=CurrentAppsPerAgentKeys.AppId)
            .eq_join(
                CurrentAppsPerAgentKeys.AgentId,
                r.table(CurrentAgentsCollection)
            )
            .zip()
            .group(
                lambda x: x[CurrentAppsPerAgentKeys.Status]
            )
            .map(
                lambda x:
                {
                    AGENTS:
                    [
                        {
                            AgentKeys.ComputerName: x[AgentKeys.ComputerName],
                            AgentKeys.DisplayName: x[AgentKeys.DisplayName],
                            CurrentAppsPerAgentKeys.AgentId: x[CurrentAppsPerAgentKeys.AgentId]
                        }
                    ],
                    CommonAppKeys.COUNT: 1
                }
            )
            .reduce(
                lambda x, y:
                {
                    AGENTS: x[AGENTS] + y[AGENTS],
                    CommonAppKeys.COUNT: x[COUNT] + y[COUNT]
                }
            )
            .ungroup()
            .run(conn)
        )
        if agents:
            for i in agents:
                new_data = i['reduction']
                new_data[CurrentAppsPerAgentKeys.Status] = i['group']
                data.append(new_data)

        statuses = map(lambda x: x['status'], data)
        difference = set(CommonAppKeys.ValidPackageStatuses).difference(statuses)
        if len(difference) > 0:
            for status in difference:
                status = {
                    CommonAppKeys.COUNT: 0,
                    AGENTS: [],
                    CommonAppKeys.STATUS: status
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
                             uri, method, agent_id,
                             collection=AppCollections.AppsPerAgent,
                             conn=None):

    if collection == AppCollections.AppsPerAgent:
        CurrentAppsPerAgentCollection = AppCollections.AppsPerAgent
        CurrentAppsPerAgentKeys = AppsPerAgentKeys

    elif collection == AppCollections.SupportedAppsPerAgent:
        CurrentAppsPerAgentCollection = AppCollections.SupportedAppsPerAgent
        CurrentAppsPerAgentKeys = SupportedAppsPerAgentKeys

    elif collection == AppCollections.CustomAppsPerAgent:
        CurrentAppsPerAgentCollection = AppCollections.CustomAppsPerAgent
        CurrentAppsPerAgentKeys = CustomAppsPerAgentKeys

    elif collection == AppCollections.vFenseAppsPerAgent:
        CurrentAppsPerAgentCollection = AppCollections.vFenseAppsPerAgent
        CurrentAppsPerAgentKeys = AgentAppsPerAgentKeys

    try:
        data = []
        apps = (
            r
            .table(CurrentAppsPerAgentCollection)
            .get_all(agent_id, index=CurrentAppsPerAgentKeys.AgentId)
            .group(CurrentAppsPerAgentKeys.Status)
            .count()
            .ungroup()
            .run(conn)
        )
        if apps:
            for i in apps:
                new_data = i['reduction']
                new_data = (
                    {
                        AppsPerAgentKeys.Status: i['group'][CurrentAppsPerAgentKeys.Status],
                        CommonAppKeys.COUNT: i['reduction'],
                        CommonAppKeys.NAME: i['group'][CurrentAppsPerAgentKeys.Status].capitalize()
                    }
                )
                data.append(new_data)

        statuses = map(lambda x: x['status'], data)
        difference = set(CommonAppKeys.ValidPackageStatuses).difference(statuses)
        if len(difference) > 0:
            for status in difference:
                status = {
                    CommonAppKeys.COUNT: 0,
                    CommonAppKeys.STATUS: status,
                    CommonAppKeys.NAME: status.capitalize()
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
