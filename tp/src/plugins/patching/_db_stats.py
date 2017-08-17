import logging

from vFense import VFENSE_LOGGING_CONFIG
from vFense.db.client import db_create_close, r
from vFense.core.decorators import time_it
from vFense.core._constants import CommonKeys
from vFense.core.tag import (
    TagCollections, TagsPerAgentKey, TagsPerAgentIndexes
)
from vFense.plugins.patching import (
    AppCollections, DbCommonAppPerAgentIndexes,
    DbCommonAppPerAgentKeys, DbCommonAppKeys
)
from vFense.plugins.patching._constants import CommonAppKeys

logging.config.fileConfig(VFENSE_LOGGING_CONFIG)
logger = logging.getLogger('rvapi')

@time_it
@db_create_close
def get_all_app_stats_by_agentid(agent_id, conn=None):
    """Retrieve the application statistics for an agent.
    Args:
        agent_id (str): The agent id of the agent you are retrieving
            application statistics for.

    Basic Usage:
        >>> from vFense.plugins.patching._db_stats import get_all_app_stats_by_agentid
        >>> agent_id = 'default'
        >>> get_all_app_stats_by_agentid(tag_id)

    Returns:
        List of application statistics.
    """
    data = []
    try:
        inventory = (
            r
            .table(AppCollections.AppsPerAgent)
            .get_all(
                [CommonAppKeys.INSTALLED, agent_id],
                index=DbCommonAppPerAgentIndexes.StatusAndAgentId
            )
            .count()
            .run(conn)
        )
        data.append(
            {
                CommonAppKeys.COUNT: inventory,
                CommonAppKeys.STATUS: CommonAppKeys.INSTALLED,
                CommonAppKeys.NAME: CommonAppKeys.SOFTWAREINVENTORY
            }
        )
        os_apps_avail = (
            r
            .table(AppCollections.AppsPerAgent)
            .get_all(
                [CommonAppKeys.AVAILABLE, agent_id],
                index=DbCommonAppPerAgentIndexes.StatusAndAgentId
            )
            .count()
            .run(conn)
        )
        data.append(
            {
                CommonAppKeys.COUNT: os_apps_avail,
                CommonAppKeys.STATUS: CommonAppKeys.AVAILABLE,
                CommonAppKeys.NAME: CommonAppKeys.OS
            }
        )
        custom_apps_avail = (
            r
            .table(AppCollections.CustomAppsPerAgent)
            .get_all(
                [CommonAppKeys.AVAILABLE, agent_id],
                index=DbCommonAppPerAgentIndexes.StatusAndAgentId
            )
            .count()
            .run(conn)
        )
        data.append(
            {
                CommonAppKeys.COUNT: custom_apps_avail,
                CommonAppKeys.STATUS: CommonAppKeys.AVAILABLE,
                CommonAppKeys.NAME: CommonAppKeys.CUSTOM
            }
        )
        #supported_apps_avail = (
        #    r
        #    .table(AppCollections.SupportedAppsPerAgent)
        #    .get_all(
        #        [CommonAppKeys.AVAILABLE, agent_id],
        #        index=DbCommonAppPerAgentIndexes.StatusAndAgentId
        #    )
        #    .count()
        #    .run(conn)
        #)

        #data.append(
        #    {
        #        CommonAppKeys.COUNT: supported_apps_avail,
        #        CommonAppKeys.STATUS: CommonAppKeys.AVAILABLE,
        #        CommonAppKeys.NAME: CommonAppKeys.SUPPORTED
        #    }
        #)

        agent_apps_avail = (
            r
            .table(AppCollections.vFenseAppsPerAgent)
            .get_all(
                [CommonAppKeys.AVAILABLE, agent_id],
                index=DbCommonAppPerAgentIndexes.StatusAndAgentId
            )
            .count()
            .run(conn)
        )

        data.append(
            {
                CommonAppKeys.COUNT: agent_apps_avail,
                CommonAppKeys.STATUS: CommonAppKeys.AVAILABLE,
                CommonAppKeys.NAME: CommonAppKeys.AGENT_UPDATES
            }
        )

    except Exception as e:
        logger.exception(e)

    return data


@db_create_close
def get_all_app_stats_by_tagid(tag_id, conn=None):
    """Retrieve the application statistics for a tag.
    Args:
        tag_id (str): The tag id of the tag you are retrieving
            application statistics for.

    Basic Usage:
        >>> from vFense.plugins.patching._db_stats import get_all_app_stats_by_tagid
        >>> tag_id = 'default'
        >>> get_all_app_stats_by_tagid(tag_id)

    Returns:
        List of application statistics.
    """
    data = []
    try:
        inventory = (
            r
            .table(TagCollections.TagsPerAgent)
            .get_all(tag_id, index=TagsPerAgentIndexes.TagId)
            .pluck(TagsPerAgentKey.AgentId)
            .eq_join(
                lambda x: [
                    CommonAppKeys.INSTALLED,
                    x[DbCommonAppPerAgentKeys.AgentId]
                ],
                r.table(AppCollections.AppsPerAgent),
                index=DbCommonAppPerAgentIndexes.StatusAndAgentId
            )
            .eq_join(lambda x: x['right'][DbCommonAppPerAgentKeys.AppId], r.table(AppCollections.UniqueApplications))
            .filter(
                lambda y: y['right'][DbCommonAppKeys.Hidden] == CommonKeys.NO
            )
            .map(
                {
                    DbCommonAppPerAgentKeys.AppId: r.row['right'][DbCommonAppPerAgentKeys.AppId],
                }
            )
            .pluck(DbCommonAppPerAgentKeys.AppId)
            .distinct()
            .count()
            .run(conn)
        )
        data.append(
            {
                CommonAppKeys.COUNT: inventory,
                CommonAppKeys.STATUS: CommonAppKeys.INSTALLED,
                CommonAppKeys.NAME: CommonAppKeys.SOFTWAREINVENTORY
            }
        )
        os_apps_avail = (
            r
            .table(TagCollections.TagsPerAgent)
            .get_all(tag_id, index=TagsPerAgentIndexes.TagId)
            .pluck(TagsPerAgentKey.AgentId)
            .eq_join(
                lambda x: [
                    CommonAppKeys.AVAILABLE,
                    x[DbCommonAppPerAgentKeys.AgentId]
                ],
                r.table(AppCollections.AppsPerAgent),
                index=DbCommonAppPerAgentIndexes.StatusAndAgentId
            )
            .pluck({'right': DbCommonAppPerAgentKeys.AppId})
            .distinct()
            .count()
            .run(conn)
        )
        data.append(
            {
                CommonAppKeys.COUNT: os_apps_avail,
                CommonAppKeys.STATUS: CommonAppKeys.AVAILABLE,
                CommonAppKeys.NAME: CommonAppKeys.OS
            }
        )
        custom_apps_avail = (
            r
            .table(TagCollections.TagsPerAgent)
            .get_all(tag_id, index=TagsPerAgentIndexes.TagId)
            .pluck(TagsPerAgentKey.AgentId)
            .eq_join(
                lambda x: [
                    CommonAppKeys.AVAILABLE,
                    x[DbCommonAppPerAgentKeys.AgentId]
                ],
                r.table(AppCollections.CustomAppsPerAgent),
                index=DbCommonAppPerAgentIndexes.StatusAndAgentId
            )
            .pluck({'right': DbCommonAppPerAgentKeys.AppId})
            .distinct()
            .count()
            .run(conn)
        )
        data.append(
            {
                CommonAppKeys.COUNT: custom_apps_avail,
                CommonAppKeys.STATUS: CommonAppKeys.AVAILABLE,
                CommonAppKeys.NAME: CommonAppKeys.CUSTOM
            }
        )
        supported_apps_avail = (
            r
            .table(TagCollections.TagsPerAgent)
            .get_all(tag_id, index=TagsPerAgentIndexes.TagId)
            .pluck(TagsPerAgentKey.AgentId)
            .eq_join(
                lambda x: [
                    CommonAppKeys.AVAILABLE,
                    x[DbCommonAppPerAgentKeys.AgentId]
                ],
                r.table(AppCollections.SupportedAppsPerAgent),
                index=DbCommonAppPerAgentIndexes.StatusAndAgentId
            )
            .pluck({'right': DbCommonAppPerAgentKeys.AppId})
            .distinct()
            .count()
            .run(conn)
        )
        data.append(
            {
                CommonAppKeys.COUNT: supported_apps_avail,
                CommonAppKeys.STATUS: CommonAppKeys.AVAILABLE,
                CommonAppKeys.NAME: CommonAppKeys.SUPPORTED
            }
        )
        agent_apps_avail = (
            r
            .table(TagCollections.TagsPerAgent)
            .get_all(tag_id, index=TagsPerAgentIndexes.TagId)
            .pluck(TagsPerAgentKey.AgentId)
            .eq_join(
                lambda x: [
                    CommonAppKeys.AVAILABLE,
                    x[DbCommonAppPerAgentKeys.AgentId]
                ],
                r.table(AppCollections.vFenseAppsPerAgent),
                index=DbCommonAppPerAgentIndexes.StatusAndAgentId
            )
            .pluck({'right': DbCommonAppPerAgentKeys.AppId})
            .distinct()
            .count()
            .run(conn)
        )
        data.append(
            {
                CommonAppKeys.COUNT: agent_apps_avail,
                CommonAppKeys.STATUS: CommonAppKeys.AVAILABLE,
                CommonAppKeys.NAME: CommonAppKeys.AGENT_UPDATES
            }
        )

    except Exception as e:
        logger.exception(e)

    return(data)


@db_create_close
def get_all_avail_stats_by_tagid(tag_id, conn=None):
    """Retrieve the available update statistics for a tag.
    Args:
        tag_id (str): The tag id of the tag you are retrieving
            application statistics for.

    Basic Usage:
        >>> from vFense.plugins.patching._db_stats import get_all_avail_stats_by_tagid
        >>> tag_id = 'default'
        >>> get_all_avail_stats_by_tagid(tag_id)

    Returns:
        List of application statistics.
    """
    data = []
    try:
        os_apps_avail = (
            r
            .table(TagCollections.TagsPerAgent)
            .get_all(tag_id, index=TagsPerAgentIndexes.TagId)
            .pluck(TagsPerAgentKey.AgentId)
            .eq_join(
                lambda x: [
                    CommonAppKeys.AVAILABLE,
                    x[DbCommonAppPerAgentKeys.AgentId]
                ],
                r.table(AppCollections.AppsPerAgent),
                index=DbCommonAppPerAgentIndexes.StatusAndAgentId
            )
            .eq_join(lambda x: x['right'][DbCommonAppPerAgentKeys.AppId], r.table(AppCollections.UniqueApplications))
            .filter(
                lambda y: y['right'][DbCommonAppKeys.Hidden] == CommonKeys.NO
            )
            .map(
                {
                    DbCommonAppPerAgentKeys.AppId: r.row['right'][DbCommonAppPerAgentKeys.AppId],
                }
            )
            .pluck(DbCommonAppPerAgentKeys.AppId)
            .distinct()
            .count()
            .run(conn)
        )
        data.append(
            {
                CommonAppKeys.COUNT: os_apps_avail,
                CommonAppKeys.STATUS: CommonAppKeys.AVAILABLE,
                CommonAppKeys.NAME: CommonAppKeys.OS
            }
        )
        custom_apps_avail = (
            r
            .table(TagCollections.TagsPerAgent)
            .get_all(tag_id, index=TagsPerAgentIndexes.TagId)
            .pluck(TagsPerAgentKey.AgentId)
            .eq_join(
                lambda x: [
                    CommonAppKeys.AVAILABLE,
                    x[DbCommonAppPerAgentIndexes.AgentId]
                ],
                r.table(AppCollections.CustomAppsPerAgent),
                index=DbCommonAppPerAgentIndexes.StatusAndAgentId
            )
            .pluck({'right': DbCommonAppPerAgentKeys.AppId})
            .distinct()
            .count()
            .run(conn)
        )
        data.append(
            {
                CommonAppKeys.COUNT: custom_apps_avail,
                CommonAppKeys.STATUS: CommonAppKeys.AVAILABLE,
                CommonAppKeys.NAME: CommonAppKeys.CUSTOM
            }
        )
        supported_apps_avail = (
            r
            .table(TagCollections.TagsPerAgent)
            .get_all(tag_id, index=TagsPerAgentIndexes.TagId)
            .pluck(TagsPerAgentKey.AgentId)
            .eq_join(
                lambda x: [
                    CommonAppKeys.AVAILABLE,
                    x[DbCommonAppPerAgentKeys.AgentId]
                ],
                r.table(AppCollections.SupportedAppsPerAgent),
                index=DbCommonAppPerAgentIndexes.StatusAndAgentId
            )
            .pluck({'right': DbCommonAppPerAgentKeys.AppId})
            .distinct()
            .count()
            .run(conn)
        )
        data.append(
            {
                CommonAppKeys.COUNT: supported_apps_avail,
                CommonAppKeys.STATUS: CommonAppKeys.AVAILABLE,
                CommonAppKeys.NAME: CommonAppKeys.SUPPORTED
            }
        )
        agent_apps_avail = (
            r
            .table(TagCollections.TagsPerAgent)
            .get_all(tag_id, index=TagsPerAgentIndexes.TagId)
            .pluck(TagsPerAgentKey.AgentId)
            .eq_join(
                lambda x: [
                    CommonAppKeys.AVAILABLE,
                    x[DbCommonAppPerAgentKeys.AgentId]
                ],
                r.table(AppCollections.vFenseAppsPerAgent),
                index=DbCommonAppPerAgentIndexes.StatusAndAgentId
            )
            .pluck({'right': DbCommonAppPerAgentKeys.AppId})
            .distinct()
            .count()
            .run(conn)
        )
        data.append(
            {
                CommonAppKeys.COUNT: agent_apps_avail,
                CommonAppKeys.STATUS: CommonAppKeys.AVAILABLE,
                CommonAppKeys.NAME: CommonAppKeys.AGENT_UPDATES
            }
        )

    except Exception as e:
        logger.exception(e)

    return(data)

@time_it
@db_create_close
def get_all_app_stats_by_customer(customer_name, conn=None):
    """Retrieve the application stats for a customer.
    Args:
        customer_name (str): The name of the customer you are retrieving
            application statistics for.

    Basic Usage:
        >>> from vFense.plugins.patching._db_stats import get_all_app_stats_by_customer
        >>> customer_name = 'default'
        >>> get_all_app_stats_by_customer(customer_name)

    Returns:
        List of application statistics.
    """
    data = []
    try:
        os_apps_avail = (
            r
            .table(AppCollections.AppsPerAgent)
            .get_all(
                [
                    CommonAppKeys.AVAILABLE, customer_name
                ],
                index=DbCommonAppPerAgentIndexes.StatusAndCustomer
            )
            .eq_join(DbCommonAppKeys.AppId, r.table(AppCollections.UniqueApplications))
            .filter(
                lambda x: x['right'][DbCommonAppKeys.Hidden] == CommonKeys.NO
            )
            .map(
                {
                    DbCommonAppPerAgentKeys.AppId: r.row['left'][DbCommonAppPerAgentKeys.AppId],
                }
            )
            .pluck(DbCommonAppPerAgentKeys.AppId)
            .distinct()
            .count()
            .run(conn)
        )
        data.append(
            {
                CommonAppKeys.COUNT: os_apps_avail,
                CommonAppKeys.STATUS: CommonAppKeys.AVAILABLE,
                CommonAppKeys.NAME: CommonAppKeys.OS
            }
        )
        custom_apps_avail = (
            r
            .table(AppCollections.CustomAppsPerAgent)
            .get_all(
                [
                    CommonAppKeys.AVAILABLE, customer_name
                ],
                index=DbCommonAppPerAgentIndexes.StatusAndCustomer
            )
            .pluck(DbCommonAppPerAgentKeys.AppId)
            .distinct()
            .count()
            .run(conn)
        )
        data.append(
            {
                CommonAppKeys.COUNT: custom_apps_avail,
                CommonAppKeys.STATUS: CommonAppKeys.AVAILABLE,
                CommonAppKeys.NAME: CommonAppKeys.CUSTOM
            }
        )
        supported_apps_avail = (
            r
            .table(AppCollections.SupportedAppsPerAgent)
            .get_all(
                [
                    CommonAppKeys.AVAILABLE, customer_name
                ],
                index=DbCommonAppPerAgentIndexes.StatusAndCustomer
            )
            .pluck(DbCommonAppPerAgentKeys.AppId)
            .distinct()
            .count()
            .run(conn)
        )
        data.append(
            {
                CommonAppKeys.COUNT: supported_apps_avail,
                CommonAppKeys.STATUS: CommonAppKeys.AVAILABLE,
                CommonAppKeys.NAME: CommonAppKeys.SUPPORTED
            }
        )
        agent_apps_avail = (
            r
            .table(AppCollections.vFenseAppsPerAgent)
            .get_all(
                [
                    CommonAppKeys.AVAILABLE, customer_name
                ],
                index=DbCommonAppPerAgentIndexes.StatusAndCustomer
            )
            .pluck(DbCommonAppPerAgentKeys.AppId)
            .distinct()
            .count()
            .run(conn)
        )
        data.append(
            {
                CommonAppKeys.COUNT: agent_apps_avail,
                CommonAppKeys.STATUS: CommonAppKeys.AVAILABLE,
                CommonAppKeys.NAME: CommonAppKeys.AGENT_UPDATES
            }
        )

        all_pending_apps = (
            r
            .table(AppCollections.AppsPerAgent)
            .get_all(
                [
                    CommonAppKeys.PENDING, customer_name
                ],
                index=DbCommonAppPerAgentIndexes.StatusAndCustomer
            )
            .pluck((CommonAppKeys.APP_ID))
            .distinct()
            .count()
            .run(conn)
        )

        data.append(
            {
                CommonAppKeys.COUNT: all_pending_apps,
                CommonAppKeys.STATUS: CommonAppKeys.PENDING,
                CommonAppKeys.NAME: CommonAppKeys.PENDING.capitalize()
            }
        )

    except Exception as e:
        logger.exception(e)

    return(data)
