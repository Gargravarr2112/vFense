#!/usr/bin/env python
import logging
from time import mktime
from datetime import datetime, timedelta

from vFense import VFENSE_LOGGING_CONFIG
from vFense.db.client import db_create_close, r
from vFense.core.tag import *
from vFense.core.agent import *
from vFense.core._constants import CommonKeys
from vFense.plugins.patching import *
from vFense.plugins.patching._constants import CommonAppKeys, CommonSeverityKeys
from vFense.errorz.error_messages import GenericResults
logging.config.fileConfig(VFENSE_LOGGING_CONFIG)
logger = logging.getLogger('rvapi')


def app_stats_by_os(stats):
    try:
        for i in xrange(len(stats)):
            stats[i] = (
                {
                    'os': stats[i]['group'],
                    'count': stats[i]['reduction']
                }
            )

    except Exception as e:
        logger.exception(e)

    return(stats)

@db_create_close
def customer_stats_by_os(username, customer_name,
                         uri, method, count=3, conn=None):
    try:
        stats = (
            r
            .table(AppCollections.AppsPerAgent)
            .get_all(
                [CommonAppKeys.AVAILABLE, customer_name],
                index=AppsPerAgentIndexes.StatusAndCustomer
            )
            .eq_join(AppsKeys.AppId, r.table(AppCollections.UniqueApplications))
            .filter(
                lambda x: x['right'][AppsKeys.Hidden] == CommonKeys.NO
            )
            .map(
                {
                    AppsPerAgentKeys.AppId: r.row['left'][AppsPerAgentKeys.AppId],
                    AppsPerAgentKeys.AgentId: r.row['left'][AppsPerAgentKeys.AgentId],
                }
            )
            .eq_join(AgentKeys.AgentId, r.table(AgentCollections.Agents))
            .map(
                {
                    AppsKeys.AppId: r.row['left'][AppsKeys.AppId],
                    AgentKeys.OsString: r.row['right'][AgentKeys.OsString]
                }
            )
            .pluck(AppsKeys.AppId, AgentKeys.OsString)
            .distinct()
            .group(AgentKeys.OsString)
            .count()
            .ungroup()
            .map(
                lambda x:
                {
                    'os': x['group'],
                    'count': x['reduction']
                }
            )
            .order_by(r.desc('count'))
            .limit(count)
            .run(conn)
        )
        data = []
        #if stats:
        #    data = app_stats_by_os(stats)

        results = (
            GenericResults(
                username, uri, method
            ).information_retrieved(stats, count)
        )

    except Exception as e:
        results = (
            GenericResults(
                username, uri, method
            ).something_broke('widget stats', 'widget', e)
        )
        logger.exception(results)

    return(results)


@db_create_close
def tag_stats_by_os(username, customer_name,
                    uri, method, tag_id,
                    count=3, conn=None):
    try:
        stats = (
            r
            .table(TagsPerAgentCollection)
            .get_all(tag_id, index=TagsPerAgentIndexes.TagId)
            .pluck(TagsPerAgentKeys.AgentId)
            .eq_join(
                lambda x: [
                    CommonAppKeys.AVAILABLE,
                    x[AppsPerAgentKeys.AgentId]
                ],
                r.table(AppCollections.AppsPerAgent),
                index=AppsPerAgentIndexes.StatusAndAgentId
            )
            .zip()
            .eq_join(AgentKeys.AgentId, r.table(AgentCollections.Agents))
            .zip()
            .eq_join(AppsPerAgentKeys.AppId, r.table(AppCollections.UniqueApplications))
            .filter(
                lambda x: x['right'][AppsKeys.Hidden] == CommonKeys.NO
            )
            .zip()
            .pluck(CommonAppKeys.APP_ID, AgentKeys.OsString)
            .distinct()
            .group(AgentKeys.OsString)
            .count()
            .ungroup()
            .map(
                lambda x:
                {
                    'os': x['group'],
                    'count': x['reduction']
                }
            )
            .order_by(r.desc('count'))
            .limit(count)
            .run(conn)
        )

        #data = []
        #if stats:
        #    data = app_stats_by_os(stats)

        results = (
            GenericResults(
                username, uri, method
            ).information_retrieved(stats, count)
        )

    except Exception as e:
        results = (
            GenericResults(
                username, uri, method
            ).something_broke('tag widget stats', 'widget', e)
        )
        logger.exception(results)

    return(results)

@db_create_close
def bar_chart_for_appid_by_status(app_id=None, customer_name='default',
                                 conn=None):
    statuses = ['installed', 'available'] 
    try:
        status = (
            r
            .table(AppCollections.AppsPerAgent)
            .get_all([app_id, customer_name], index=AppsPerAgentIndexes.AppIdAndCustomer)
            .group('status')
            .count()
            .run(conn)
        )

    except Exception as e:
        msg = (
            'Couldnt get bar chart stats for appid %s for customer %s: %s' %
            (customer_name, e)
        )
        logger.error(msg)

    new_status = {}
    for stat in status:
        new_status[stat['group']['status']] = stat['reduction']
    for s in statuses:
        if not s in new_status:
            new_status[s] = 0.0

    return(
        {
            'pass': True,
            'message': '',
            'data': [new_status]
        }
    )

def app_stats_by_severity(sevs):
    try:
        new_sevs = []
        for i in xrange(len(sevs)):
            sevs[i] = (
                {
                    'severity': sevs[i]['group'],
                    'count': sevs[i]['reduction']
                }
            )
        sevs_in_sevs = map(lambda x: x['severity'], sevs)
        difference = list(set(CommonSeverityKeys.ValidRvSeverities).difference(sevs_in_sevs))

        if difference:
            for sev in difference:
                sevs.append(
                    {
                        'severity': sev,
                        'count': 0
                    }
                )

        for sev in sevs:
            if sev['severity'] == CommonSeverityKeys.CRITICAL:
                crit = sev

            elif sev['severity'] == CommonSeverityKeys.OPTIONAL:
                opt = sev

            elif sev['severity'] == CommonSeverityKeys.RECOMMENDED:
                rec = sev

        new_sevs.append(opt)
        new_sevs.append(crit)
        new_sevs.append(rec)

    except Exception as e:
        logger.exception(e)

    return(new_sevs)

@db_create_close
def get_severity_bar_chart_stats_for_customer(username, customer_name,
                                              uri, method, conn=None):
    try:
        sevs = (
            r
            .table(AppCollections.AppsPerAgent)
            .get_all(
                [CommonAppKeys.AVAILABLE, customer_name],
                index=AppsPerAgentIndexes.StatusAndCustomer
            )
            .pluck(AppsKeys.AppId)
            .distinct()
            .eq_join(AppsKeys.AppId, r.table(AppCollections.UniqueApplications))
            .filter(
                lambda x: x['right'][AppsKeys.Hidden] == CommonKeys.NO
            )
            .map(
                {
                    AppsKeys.AppId: r.row['right'][AppsKeys.AppId],
                    AppsKeys.RvSeverity: r.row['right'][AppsKeys.RvSeverity]
                }
            )
            .group(AppsKeys.RvSeverity)
            .count()
            .ungroup()
            .order_by(r.asc('group'))
            .run(conn)
        )
        data = app_stats_by_severity(sevs)

        results = (
            GenericResults(
                username, uri, method
            ).information_retrieved(data, len(CommonSeverityKeys.ValidRvSeverities))
        )

    except Exception as e:
        results = (
            GenericResults(
                username, uri, method
            ).something_broke('widget severity stats', 'widget', e)
        )
        logger.exception(results)

    return(results)


@db_create_close
def get_severity_bar_chart_stats_for_agent(username, customer_name,
                                           uri, method, agent_id, conn=None):
    try:
        sevs = (
            r
            .table(AppCollections.AppsPerAgent)
            .get_all(
                [CommonAppKeys.AVAILABLE, agent_id],
                index=AppsPerAgentIndexes.StatusAndAgentId
            )
            .eq_join(AppsKeys.AppId, r.table(AppCollections.UniqueApplications))
            .filter(
                lambda x: x['right'][AppsKeys.Hidden] == CommonKeys.NO
            )
            .map(
                {
                    AppsKeys.AppId: r.row['right'][AppsKeys.AppId],
                    AppsKeys.RvSeverity: r.row['right'][AppsKeys.RvSeverity]
                }
            )
            .group(AppsKeys.RvSeverity)
            .count()
            .ungroup()
            .order_by(r.desc('reduction'))
            .run(conn)
        )
        data = app_stats_by_severity(sevs)

        results = (
            GenericResults(
                username, uri, method
            ).information_retrieved(data, len(CommonSeverityKeys.ValidRvSeverities))
        )

    except Exception as e:
        results = (
            GenericResults(
                username, uri, method
            ).something_broke('widget severity stats', 'widget', e)
        )
        logger.exception(results)

    return(results)


@db_create_close
def get_severity_bar_chart_stats_for_tag(username, customer_name,
                                         uri, method, tag_id, conn=None):
    try:
        sevs = (
            r
            .table(TagsPerAgentCollection)
            .get_all(tag_id, index=TagsPerAgentIndexes.TagId)
            .pluck(TagsPerAgentKeys.AgentId)
            .eq_join(
                lambda x: [
                    CommonAppKeys.AVAILABLE,
                    x[AppsPerAgentKeys.AgentId]
                ],
                r.table(AppCollections.AppsPerAgent),
                index=AppsPerAgentIndexes.StatusAndAgentId
            )
            .map(
                {
                    AppsKeys.AppId: r.row['right'][AppsKeys.AppId],
                }
            )
            .eq_join(AppsKeys.AppId, r.table(AppCollections.UniqueApplications))
            .filter(
                lambda x: x['right'][AppsKeys.Hidden] == CommonKeys.NO
            )
            .map(
                {
                    AppsKeys.AppId: r.row['right'][AppsKeys.AppId],
                    AppsKeys.RvSeverity: r.row['right'][AppsKeys.RvSeverity]
                }
            )
            .group(AppsKeys.RvSeverity)
            .count()
            .ungroup()
            .order_by(r.desc('reduction'))
            .run(conn)
        )
        data = app_stats_by_severity(sevs)

        results = (
            GenericResults(
                username, uri, method
            ).information_retrieved(data, len(CommonSeverityKeys.ValidRvSeverities))
        )

    except Exception as e:
        results = (
            GenericResults(
                username, uri, method
            ).something_broke('widget severity stats', 'widget', e)
        )
        logger.exception(results)

    return(results)


@db_create_close
def top_packages_needed(username, customer_name,
                        uri, method, count=5, conn=None):
    
    apps_needed=[]
    
    try:
        data = (
            r
            .table(AppCollections.AppsPerAgent)
            .get_all(
                [CommonAppKeys.AVAILABLE, customer_name],
                index=AppsPerAgentIndexes.StatusAndCustomer
            )
            .eq_join(AppsKeys.AppId, r.table(AppCollections.UniqueApplications))
            .filter(
                lambda x: x['right'][AppsKeys.Hidden] == CommonKeys.NO
            )
            .map(
                lambda x:
                {
                    AppsKeys.Name: x['right'][AppsKeys.Name],
                    AppsKeys.AppId: x['right'][AppsKeys.AppId],
                    AppsKeys.RvSeverity: x['right'][AppsKeys.RvSeverity],
                    AppsKeys.ReleaseDate: x['right'][AppsKeys.ReleaseDate].to_epoch_time(),
                }
            )
            .group(AppsKeys.Name, AppsKeys.AppId, AppsKeys.RvSeverity, AppsKeys.ReleaseDate)
            .count()
            .ungroup()
            .map(
                lambda x:
                {
                    AppsKeys.Name: x['group'][0],
                    AppsKeys.AppId: x['group'][1],
                    AppsKeys.RvSeverity: x['group'][2],
                    AppsKeys.ReleaseDate: x['group'][3],
                    'count': x['reduction'],
                }
            )
            .order_by(r.desc('count'), r.desc(AppsKeys.ReleaseDate))
            .limit(count)
            .run(conn)
        )

        results = (
            GenericResults(
                username, uri, method
            ).information_retrieved(data, count)
        )

    except Exception as e:
        results = (
            GenericResults(
                username, uri, method
            ).something_broke('top os apps needed', 'widget', e)
        )
        logger.exception(results)

    return(results)


@db_create_close
def recently_released_packages(username, customer_name,
                               uri, method, count=5, conn=None):

    data=[]

    try:
        data = list(
            r
            .table(AppCollections.AppsPerAgent)
            .get_all(
                [
                    CommonAppKeys.AVAILABLE, customer_name
                ],
                index=AppsPerAgentIndexes.StatusAndCustomer
            )
            .eq_join(AppsKeys.AppId, r.table(AppCollections.UniqueApplications))
            .map(
                lambda x:
                {
                    AppsKeys.Name: x['right'][AppsKeys.Name],
                    AppsKeys.AppId: x['right'][AppsKeys.AppId],
                    AppsKeys.RvSeverity: x['right'][AppsKeys.RvSeverity],
                    AppsKeys.Hidden: x['right'][AppsKeys.Hidden],
                    AppsKeys.ReleaseDate: x['right'][AppsKeys.ReleaseDate].to_epoch_time(),
                    'count': (
                        r
                        .table(AppCollections.AppsPerAgent)
                        .get_all(
                            [x['right'][AppsKeys.AppId], CommonAppKeys.AVAILABLE],
                            index=AppsPerAgentIndexes.AppIdAndStatus
                        )
                        .eq_join(AppsKeys.AppId, r.table(AppCollections.UniqueApplications))
                        .filter(
                            lambda y: y['right'][AppsKeys.Hidden] == CommonKeys.NO
                        )
                        .count()
                    )
                }
            )
            .pluck(
                AppsKeys.Name, AppsKeys.AppId,AppsKeys.Hidden,
                AppsKeys.RvSeverity, AppsKeys.ReleaseDate, 'count'
            )
            .order_by(r.desc(AppsKeys.ReleaseDate))
            .limit(count)
            .run(conn)
        )

        results = (
            GenericResults(
                username, uri, method
            ).information_retrieved(data, count)
        )

    except Exception as e:
        results = (
            GenericResults(
                username, uri, method
            ).something_broke('recently released os apps', 'widget', e)
        )
        logger.exception(results)

    return(results)


@db_create_close
def get_os_apps_history(username, customer_name, uri, method, status,
                        start_date=None, end_date=None, conn=None):

    try:
        if not start_date and not end_date:
            start_date = mktime((datetime.now() - timedelta(days=1*365)).timetuple())
            end_date = mktime(datetime.now().timetuple())

        elif start_date and not end_date:
            end_date = mktime(datetime.now().timetuple())

        elif not start_date and end_date:
            start_date = 0.0
        data = (
            r
            .table(AppCollections.AppsPerAgent)
            .get_all(
                [CommonAppKeys.AVAILABLE, customer_name],
                index=AppsPerAgentIndexes.StatusAndCustomer
            )
            .eq_join(AppsKeys.AppId, r.table(AppCollections.UniqueApplications))
            .zip()
            .filter(
                r.row[AppsKeys.ReleaseDate].during(
                    r.epoch_time(start_date), r.epoch_time(end_date)
                )
            )
            .pluck(
                AppsKeys.AppId, AppsKeys.Name, AppsKeys.Version,
                AppsKeys.RvSeverity, AppsKeys.ReleaseDate
            )
            .group(
                lambda x: x[AppsKeys.ReleaseDate].to_epoch_time()
            )
            .map(
                lambda x:
                {
                    'details':
                        [
                            {
                                AppsKeys.AppId: x[AppsKeys.AppId],
                                AppsKeys.Name: x[AppsKeys.Name],
                                AppsKeys.Version: x[AppsKeys.Version],
                                AppsKeys.RvSeverity: x[AppsKeys.RvSeverity]
                            }
                        ],
                    CommonAppKeys.COUNT: 1,
                }
            )
            .reduce(
                lambda x, y:
                {
                    "count": x["count"] + y["count"],
                    "details": x["details"] + y["details"],
                }
            )
            .ungroup()
            .map(
                {
                    'timestamp': r.row['group'],
                    'total_count': r.row['reduction']['count'],
                    'details': (
                        r.row['reduction']['details']
                        .group(
                            lambda a: a['rv_severity']
                        )
                        .map(
                            lambda a:
                            {
                                'apps':
                                    [
                                        {
                                            AppsKeys.AppId: a[AppsKeys.AppId],
                                            AppsKeys.Name: a[AppsKeys.Name],
                                            AppsKeys.Version: a[AppsKeys.Version],
                                        }
                                    ],
                                CommonAppKeys.COUNT: 1
                            }
                        )
                        .reduce(
                            lambda a, b:
                            {
                                "count": a["count"] + b["count"],
                                "apps": a["apps"] + b["apps"],
                            }
                        )
                        .ungroup()
                    )
                }
            )
            .run(conn)
        )

        results = (
            GenericResults(
                username, uri, method
            ).information_retrieved(data, len(data))
        )

    except Exception as e:
        results = (
            GenericResults(
                username, uri, method
            ).something_broke('available apps over time graph', 'graph', e)
        )
        logger.exception(results)

    return(results)

@db_create_close
def get_os_apps_history_for_agent(username, customer_name, uri, method,
                                  agent_id, status, start_date=None,
                                  end_date=None, conn=None):

    try:
        if not start_date and not end_date:
            start_date = mktime((datetime.now() - timedelta(days=1*365)).timetuple())
            end_date = mktime(datetime.now().timetuple())

        elif start_date and not end_date:
            end_date = mktime(datetime.now().timetuple())

        elif not start_date and end_date:
            start_date = 0.0
        data = (
            r
            .table(AppCollections.AppsPerAgent)
            .get_all(
                [status, agent_id],
                index=AppsPerAgentIndexes.StatusAndAgentId
            )
            .eq_join(AppsKeys.AppId, r.table(AppCollections.UniqueApplications))
            .zip()
            .filter(
                r.row[AppsKeys.ReleaseDate].during(
                    r.epoch_time(start_date), r.epoch_time(end_date)
                )
            )
            .pluck(
                AppsKeys.AppId, AppsKeys.Name, AppsKeys.Version,
                AppsKeys.RvSeverity, AppsKeys.ReleaseDate
            )
             .group(
                lambda x: x[AppsKeys.ReleaseDate].to_epoch_time()
            )
            .map(
                lambda x:
                {
                    'details':
                        [
                            {
                                AppsKeys.AppId: x[AppsKeys.AppId],
                                AppsKeys.Name: x[AppsKeys.Name],
                                AppsKeys.Version: x[AppsKeys.Version],
                                AppsKeys.RvSeverity: x[AppsKeys.RvSeverity]
                            }
                        ],
                    CommonAppKeys.COUNT: 1,
                }
            )
            .reduce(
                lambda x, y:
                {
                    "count": x["count"] + y["count"],
                    "details": x["details"] + y["details"],
                }
            )
            .ungroup()
            .map(
                {
                    'timestamp': r.row['group'],
                    'total_count': r.row['reduction']['count'],
                    'details': (
                        r.row['reduction']['details']
                        .group(
                            lambda a: a['rv_severity']
                        )
                        .map(
                            lambda a:
                            {
                                'apps':
                                    [
                                        {
                                            AppsKeys.AppId: a[AppsKeys.AppId],
                                            AppsKeys.Name: a[AppsKeys.Name],
                                            AppsKeys.Version: a[AppsKeys.Version],
                                        }
                                    ],
                                CommonAppKeys.COUNT: 1
                            }
                        )
                        .reduce(
                            lambda a, b:
                            {
                                "count": a["count"] + b["count"],
                                "apps": a["apps"] + b["apps"],
                            }
                        )
                        .ungroup()
                    )
                }
            )
            .run(conn)
        )

        results = (
            GenericResults(
                username, uri, method
            ).information_retrieved(data, len(data))
        )

    except Exception as e:
        results = (
            GenericResults(
                username, uri, method
            ).something_broke('available apps over time graph', 'graph', e)
        )
        logger.exception(results)

    return(results)

@db_create_close
def get_os_apps_history_for_tag(username, customer_name, uri, method,
                                tag_id, status, start_date=None,
                                end_date=None, conn=None):

    try:
        if not start_date and not end_date:
            start_date = mktime((datetime.now() - timedelta(days=1*365)).timetuple())
            end_date = mktime(datetime.now().timetuple())

        elif start_date and not end_date:
            end_date = mktime(datetime.now().timetuple())

        elif not start_date and end_date:
            start_date = 0.0
        data = (
            r
            .table(TagsPerAgentCollection)
            .get_all(tag_id, index=TagsPerAgentIndexes.TagId)
            .pluck(TagsPerAgentKeys.AgentId)
            .eq_join(
                lambda x: [
                    status,
                    x[AppsPerAgentKeys.AgentId]
                ],
                r.table(AppCollections.AppsPerAgent),
                index=AppsPerAgentIndexes.StatusAndAgentId
            )
            .zip()
            .eq_join(AppsKeys.AppId, r.table(AppCollections.UniqueApplications))
            .zip()
            .filter(
                r.row[AppsKeys.ReleaseDate].during(
                    r.epoch_time(start_date), r.epoch_time(end_date)
                )
            )
            .pluck(
                AppsKeys.AppId, AppsKeys.Name, AppsKeys.Version,
                AppsKeys.RvSeverity, AppsKeys.ReleaseDate
            )
             .group(
                lambda x: x[AppsKeys.ReleaseDate].to_epoch_time()
            )
            .map(
                lambda x:
                {
                    'details':
                        [
                            {
                                AppsKeys.AppId: x[AppsKeys.AppId],
                                AppsKeys.Name: x[AppsKeys.Name],
                                AppsKeys.Version: x[AppsKeys.Version],
                                AppsKeys.RvSeverity: x[AppsKeys.RvSeverity]
                            }
                        ],
                    CommonAppKeys.COUNT: 1,
                }
            )
            .reduce(
                lambda x, y:
                {
                    "count": x["count"] + y["count"],
                    "details": x["details"] + y["details"],
                }
            )
            .ungroup()
            .map(
                {
                    'timestamp': r.row['group'],
                    'total_count': r.row['reduction']['count'],
                    'details': (
                        r.row['reduction']['details']
                        .group(
                            lambda a: a['rv_severity']
                        )
                        .map(
                            lambda a:
                            {
                                'apps':
                                    [
                                        {
                                            AppsKeys.AppId: a[AppsKeys.AppId],
                                            AppsKeys.Name: a[AppsKeys.Name],
                                            AppsKeys.Version: a[AppsKeys.Version],
                                        }
                                    ],
                                CommonAppKeys.COUNT: 1
                            }
                        )
                        .reduce(
                            lambda a, b:
                            {
                                "count": a["count"] + b["count"],
                                "apps": a["apps"] + b["apps"],
                            }
                        )
                        .ungroup()
                    )
                }
            )
            .run(conn)
        )

        results = (
            GenericResults(
                username, uri, method
            ).information_retrieved(data, len(data))
        )

    except Exception as e:
        results = (
            GenericResults(
                username, uri, method
            ).something_broke('available apps over time graph', 'graph', e)
        )
        logger.exception(results)

    return(results)
