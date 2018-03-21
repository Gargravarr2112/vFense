import logging

from vFense import VFENSE_LOGGING_CONFIG
from vFense.db.client import db_create_close, r
from vFense.core.decorators import time_it
from vFense.core._constants import CommonKeys
from vFense.core.tag import (
    TagCollections, TagsPerAgentKeys, TagsPerAgentIndexes
)
from vFense.plugins.patching import (
    AppCollections, DbCommonAppsPerAgentIndexes,
    DbCommonAppsPerAgentKeys, DbCommonAppsKeys
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
                index=DbCommonAppsPerAgentIndexes.StatusAndAgentId
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
                index=DbCommonAppsPerAgentIndexes.StatusAndAgentId
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
                index=DbCommonAppsPerAgentIndexes.StatusAndAgentId
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
        #        index=DbCommonAppsPerAgentIndexes.StatusAndAgentId
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
                index=DbCommonAppsPerAgentIndexes.StatusAndAgentId
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
            .pluck(TagsPerAgentKeys.AgentId)
            .eq_join(
                lambda x: [
                    CommonAppKeys.INSTALLED,
                    x[DbCommonAppsPerAgentKeys.AgentId]
                ],
                r.table(AppCollections.AppsPerAgent),
                index=DbCommonAppsPerAgentIndexes.StatusAndAgentId
            )
            .eq_join(lambda x: x['right'][DbCommonAppsPerAgentKeys.AppId], r.table(AppCollections.UniqueApplications))
            .filter(
                lambda y: y['right'][DbCommonAppsKeys.Hidden] == CommonKeys.NO
            )
            .map(
                {
                    DbCommonAppsPerAgentKeys.AppId: r.row['right'][DbCommonAppsPerAgentKeys.AppId],
                }
            )
            .pluck(DbCommonAppsPerAgentKeys.AppId)
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
            .pluck(TagsPerAgentKeys.AgentId)
            .eq_join(
                lambda x: [
                    CommonAppKeys.AVAILABLE,
                    x[DbCommonAppsPerAgentKeys.AgentId]
                ],
                r.table(AppCollections.AppsPerAgent),
                index=DbCommonAppsPerAgentIndexes.StatusAndAgentId
            )
            .pluck({'right': DbCommonAppsPerAgentKeys.AppId})
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
            .pluck(TagsPerAgentKeys.AgentId)
            .eq_join(
                lambda x: [
                    CommonAppKeys.AVAILABLE,
                    x[DbCommonAppsPerAgentKeys.AgentId]
                ],
                r.table(AppCollections.CustomAppsPerAgent),
                index=DbCommonAppsPerAgentIndexes.StatusAndAgentId
            )
            .pluck({'right': DbCommonAppsPerAgentKeys.AppId})
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
            .pluck(TagsPerAgentKeys.AgentId)
            .eq_join(
                lambda x: [
                    CommonAppKeys.AVAILABLE,
                    x[DbCommonAppsPerAgentKeys.AgentId]
                ],
                r.table(AppCollections.SupportedAppsPerAgent),
                index=DbCommonAppsPerAgentIndexes.StatusAndAgentId
            )
            .pluck({'right': DbCommonAppsPerAgentKeys.AppId})
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
            .pluck(TagsPerAgentKeys.AgentId)
            .eq_join(
                lambda x: [
                    CommonAppKeys.AVAILABLE,
                    x[DbCommonAppsPerAgentKeys.AgentId]
                ],
                r.table(AppCollections.vFenseAppsPerAgent),
                index=DbCommonAppsPerAgentIndexes.StatusAndAgentId
            )
            .pluck({'right': DbCommonAppsPerAgentKeys.AppId})
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
            .pluck(TagsPerAgentKeys.AgentId)
            .eq_join(
                lambda x: [
                    CommonAppKeys.AVAILABLE,
                    x[DbCommonAppsPerAgentKeys.AgentId]
                ],
                r.table(AppCollections.AppsPerAgent),
                index=DbCommonAppsPerAgentIndexes.StatusAndAgentId
            )
            .eq_join(lambda x: x['right'][DbCommonAppsPerAgentKeys.AppId], r.table(AppCollections.UniqueApplications))
            .filter(
                lambda y: y['right'][DbCommonAppsKeys.Hidden] == CommonKeys.NO
            )
            .map(
                {
                    DbCommonAppsPerAgentKeys.AppId: r.row['right'][DbCommonAppsPerAgentKeys.AppId],
                }
            )
            .pluck(DbCommonAppsPerAgentKeys.AppId)
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
            .pluck(TagsPerAgentKeys.AgentId)
            .eq_join(
                lambda x: [
                    CommonAppKeys.AVAILABLE,
                    x[DbCommonAppsPerAgentIndexes.AgentId]
                ],
                r.table(AppCollections.CustomAppsPerAgent),
                index=DbCommonAppsPerAgentIndexes.StatusAndAgentId
            )
            .pluck({'right': DbCommonAppsPerAgentKeys.AppId})
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
            .pluck(TagsPerAgentKeys.AgentId)
            .eq_join(
                lambda x: [
                    CommonAppKeys.AVAILABLE,
                    x[DbCommonAppsPerAgentKeys.AgentId]
                ],
                r.table(AppCollections.SupportedAppsPerAgent),
                index=DbCommonAppsPerAgentIndexes.StatusAndAgentId
            )
            .pluck({'right': DbCommonAppsPerAgentKeys.AppId})
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
            .pluck(TagsPerAgentKeys.AgentId)
            .eq_join(
                lambda x: [
                    CommonAppKeys.AVAILABLE,
                    x[DbCommonAppsPerAgentKeys.AgentId]
                ],
                r.table(AppCollections.vFenseAppsPerAgent),
                index=DbCommonAppsPerAgentIndexes.StatusAndAgentId
            )
            .pluck({'right': DbCommonAppsPerAgentKeys.AppId})
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
                index=DbCommonAppsPerAgentIndexes.StatusAndCustomer
            )
            .eq_join(DbCommonAppsKeys.AppId, r.table(AppCollections.UniqueApplications))
            .filter(
                lambda x: x['right'][DbCommonAppsKeys.Hidden] == CommonKeys.NO
            )
            .map(
                {
                    DbCommonAppsPerAgentKeys.AppId: r.row['left'][DbCommonAppsPerAgentKeys.AppId],
                }
            )
            .pluck(DbCommonAppsPerAgentKeys.AppId)
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
                index=DbCommonAppsPerAgentIndexes.StatusAndCustomer
            )
            .pluck(DbCommonAppsPerAgentKeys.AppId)
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
                index=DbCommonAppsPerAgentIndexes.StatusAndCustomer
            )
            .pluck(DbCommonAppsPerAgentKeys.AppId)
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
                index=DbCommonAppsPerAgentIndexes.StatusAndCustomer
            )
            .pluck(DbCommonAppsPerAgentKeys.AppId)
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
                index=DbCommonAppsPerAgentIndexes.StatusAndCustomer
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
