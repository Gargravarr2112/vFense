import logging
import logging.config
from vFense import VFENSE_LOGGING_CONFIG

from vFense.db.client import db_create_close, r
from vFense.plugins.patching import *
from vFense.plugins.patching._constants import CommonAppKeys, CommonSeverityKeys
from vFense.plugins.patching._db_files import fetch_file_data
from vFense.plugins.patching.apps.db_calls import get_all_stats_by_appid
from vFense.core.agent import *
from vFense.errorz.error_messages import GenericResults, PackageResults

logging.config.fileConfig(VFENSE_LOGGING_CONFIG)
logger = logging.getLogger('rvapi')


class RetrieveAppsByAppId(object):
    """
        Main Class for retrieving package information.
    """
    def __init__(self, username, customer_name, app_id,
                 uri=None, method=None, count=30, offset=0):
        """
        """
        self.count = count
        self.offset = offset
        self.customer_name = customer_name
        self.username = username
        self.uri = uri
        self.method = method
        self.app_id = app_id
        self.CurrentAppsCollection = AppCollections.UniqueApplications
        self.CurrentAppsIndexes = AppsIndexes
        self.CurrentAppsPerAgentCollection = AppCollections.AppsPerAgent
        self.CurrentAppsKeys = AppsKeys
        self.CurrentAppsPerAgentKeys = AppsPerAgentKeys
        self.CurrentAppsPerAgentIndexes = AppsPerAgentIndexes

        self.map_hash = (
            {
                self.CurrentAppsKeys.AppId: r.row[self.CurrentAppsKeys.AppId],
                self.CurrentAppsKeys.Version: r.row[self.CurrentAppsKeys.Version],
                self.CurrentAppsKeys.Name: r.row[self.CurrentAppsKeys.Name],
                self.CurrentAppsKeys.Description: r.row[self.CurrentAppsKeys.Description],
                self.CurrentAppsKeys.Kb: r.row[self.CurrentAppsKeys.Kb],
                self.CurrentAppsKeys.ReleaseDate: r.row[self.CurrentAppsKeys.ReleaseDate].to_epoch_time(),
                self.CurrentAppsKeys.RvSeverity: r.row[self.CurrentAppsKeys.RvSeverity],
                self.CurrentAppsKeys.VendorSeverity: r.row[self.CurrentAppsKeys.VendorSeverity],
                self.CurrentAppsKeys.VendorName: r.row[self.CurrentAppsKeys.VendorName],
                self.CurrentAppsKeys.SupportUrl: r.row[self.CurrentAppsKeys.SupportUrl],
                self.CurrentAppsKeys.OsCode: r.row[self.CurrentAppsKeys.OsCode],
                self.CurrentAppsKeys.FilesDownloadStatus: r.row[self.CurrentAppsKeys.FilesDownloadStatus],
                self.CurrentAppsKeys.CveIds: r.row[self.CurrentAppsKeys.CveIds],
                self.CurrentAppsKeys.VulnerabilityId: r.row[self.CurrentAppsKeys.VulnerabilityId],
                self.CurrentAppsKeys.VulnerabilityCategories: r.row[self.CurrentAppsKeys.VulnerabilityCategories],
            }
        )

    @db_create_close
    def get_by_app_id(self, stats=False, conn=None):
        """
        """
        try:
            pkg = list(
                r
                .table(self.CurrentAppsCollection)
                .get_all(self.app_id, index=self.CurrentAppsIndexes.AppId)
                .map(self.map_hash)
                .run(conn)
            )
            if pkg:
                pkg[0][self.CurrentAppsKeys.FileData] = fetch_file_data(self.app_id)

                if stats:
                    pkg[0]['agent_stats'] = (
                        get_all_stats_by_appid(
                            self.username, self.customer_name,
                            self.uri, self.method, self.app_id,
                            collection=self.CurrentAppsPerAgentCollection
                        )['data']
                    )

                status = (
                    GenericResults(
                        self.username, self.uri, self.method
                    ).information_retrieved(pkg[0], 1)
                )

            else:
                status = (
                    GenericResults(
                        self.username, self.uri, self.method
                    ).invalid_id(self.app_id, 'package')
                )

        except Exception as e:
            status = (
                GenericResults(
                    self.username, self.uri, self.method
                ).something_broke(self.app_id, 'package', e)
            )
            logger.exception(e)

        return(status)


class RetrieveAgentsByAppId(object):
    """
        This class is used to get agent data from within the Packages Page
    """
    def __init__(self, username, customer_name,
                 app_id, uri=None, method=None,
                 count=30, offset=0):
        """
        """
        self.count = count
        self.offset = offset
        self.customer_name = customer_name
        self.username = username
        self.uri = uri
        self.method = method
        self.app_id = app_id
        self.CurrentAppsCollection = AppCollections.UniqueApplications
        self.CurrentAppsIndexes = AppsIndexes
        self.CurrentAppsPerAgentCollection = AppCollections.AppsPerAgent
        self.CurrentAppsKeys = AppsKeys
        self.CurrentAppsPerAgentKeys = AppsPerAgentKeys
        self.CurrentAppsPerAgentIndexes = AppsPerAgentIndexes

        self.map_hash = (
            {
                AgentKeys.ComputerName: r.row[AgentKeys.ComputerName],
                AgentKeys.DisplayName: r.row[AgentKeys.DisplayName],
                self.CurrentAppsPerAgentKeys.AgentId: r.row[self.CurrentAppsPerAgentKeys.AgentId]
            }
        )

    @db_create_close
    def filter_by_status(self, pkg_status, conn=None):
        """
        """
        try:
            pkg = (
                r
                .table(self.CurrentAppsCollection)
                .get(self.app_id)
                .run(conn)
            )
            if pkg:
                if pkg_status in CommonAppKeys.ValidPackageStatuses:
                    agents = list(
                        r
                        .table(self.CurrentAppsPerAgentCollection)
                        .get_all([self.app_id, pkg_status],
                                 index=self.CurrentAppsPerAgentIndexes.AppIdAndStatus)
                        .eq_join(
                            self.CurrentAppsPerAgentKeys.AgentId,
                            r.table(AgentsCollection)
                        )
                        .zip()
                        .order_by(r.asc(AgentKeys.ComputerName))
                        .skip(self.offset)
                        .limit(self.count)
                        .map(self.map_hash)
                        .run(conn)
                    )

                    agent_count = (
                        r
                        .table(self.CurrentAppsPerAgentCollection)
                        .get_all([self.app_id, pkg_status],
                                 index=self.CurrentAppsPerAgentIndexes.AppIdAndStatus)
                        .count()
                        .run(conn)
                    )

                    return_status = (
                        GenericResults(
                            self.username, self.uri, self.method
                        ).information_retrieved(agents, agent_count)
                    )

                else:
                    return_status = (
                        PackageResults(
                            self.username, self.uri, self.method
                        ).invalid_status(self.app_id, pkg_status)
                    )

            else:
                return_status = (
                    PackageResults(
                        self.username, self.uri, self.method
                    ).invalid_package_id(self.app_id)
                )

        except Exception as e:
            return_status = (
                GenericResults(
                    self.username, self.uri, self.method
                ).something_broke(
                    "Package Searching went haywire",
                    'os_updates', e
                    )
            )
            logger.exception(e)

        return(return_status)

    @db_create_close
    def query_by_name(self, name, conn=None):
        try:
            pkg = (
                r
                .table(self.CurrentAppsCollection)
                .get(self.app_id)
                .run(conn)
            )
            if pkg:
                agents = list(
                    r
                    .table(self.CurrentAppsPerAgentCollection)
                    .get_all(self.app_id, index=self.CurrentAppsPerAgentIndexes.AppId)
                    .eq_join(
                        self.CurrentAppsPerAgentKeys.AgentId,
                        r.table(AgentsCollection)
                    )
                    .zip()
                    .filter(
                        r.row[AgentKeys.ComputerName].match("(?i)"+name)
                        |
                        r.row[AgentKeys.DisplayName].match("(?i)"+name)
                    )
                    .order_by(r.asc('computer_name'))
                    .skip(self.offset)
                    .limit(self.count)
                    .map(self.map_hash)
                    .run(conn)
                )

                agent_count = (
                    r
                    .table(self.CurrentAppsPerAgentCollection)
                    .get_all(self.app_id, index=self.CurrentAppsPerAgentIndexes.AppId)
                    .eq_join(
                        self.CurrentAppsPerAgentKeys.AgentId,
                        r.table(AgentsCollection)
                    )
                    .zip()
                    .filter(
                        r.row[AgentKeys.ComputerName].match("(?i)"+name)
                        |
                        r.row[AgentKeys.DisplayName].match("(?i)"+name)
                    )
                    .count()
                    .run(conn)
                )

                return_status = (
                    GenericResults(
                        self.username, self.uri, self.method
                    ).information_retrieved(agents, agent_count)
                )

            else:
                return_status = (
                    PackageResults(
                        self.username, self.uri, self.method
                    ).invalid_package_id(self.app_id)
                )

        except Exception as e:
            return_status = (
                GenericResults(
                    self.username, self.uri, self.method
                ).something_broke(
                    "Package Searching went haywire",
                    'os_updates', e
                    )
            )
            logger.exception(e)

        return(return_status)

    @db_create_close
    def filter_by_status_and_query_by_name(self, name, pkg_status, conn=None):
        try:
            pkg = (
                r
                .table(self.CurrentAppsCollection)
                .get(self.app_id)
                .run(conn)
            )
            if pkg:
                if pkg_status in CommonAppKeys.ValidPackageStatuses:
                    agents = list(
                        r
                        .table(self.CurrentAppsPerAgentCollection)
                        .get_all([self.app_id, pkg_status],
                                 index=self.CurrentAppsPerAgentIndexes.AppIdAndStatus)
                        .eq_join(
                            self.CurrentAppsPerAgentKeys.AgentId,
                            r.table(AgentsCollection)
                        )
                        .zip()
                        .filter(
                            r.row[AgentKeys.ComputerName].match("(?i)"+name)
                            |
                            r.row[AgentKeys.DisplayName].match("(?i)"+name)
                        )
                        .order_by(r.asc(AgentKeys.ComputerName))
                        .skip(self.offset)
                        .limit(self.count)
                        .map(self.map_hash)
                        .run(conn)
                    )

                    agent_count = (
                        r
                        .table(self.CurrentAppsPerAgentCollection)
                        .get_all([self.app_id, pkg_status],
                                 index=self.CurrentAppsPerAgentIndexes.AppIdAndStatus)
                        .eq_join(
                            self.CurrentAppsPerAgentKeys.AgentId,
                            r.table(AgentsCollection)
                        )
                        .zip()
                        .filter(
                            r.row[AgentKeys.ComputerName].match("(?i)"+name)
                            |
                            r.row[AgentKeys.DisplayName].match("(?i)"+name)
                        )
                        .count()
                        .run(conn)
                    )

                    return_status = (
                        GenericResults(
                            self.username, self.uri, self.method
                        ).information_retrieved(agents, agent_count)
                    )

                else:
                    return_status = (
                        PackageResults(
                            self.username, self.uri, self.method
                        ).invalid_status(self.app_id, pkg_status)
                    )

            else:
                return_status = (
                    PackageResults(
                        self.username, self.uri, self.method
                    ).invalid_package_id(self.app_id)
                )

        except Exception as e:
            return_status = (
                GenericResults(
                    self.username, self.uri, self.method
                ).something_broke(
                    "Package Searching went haywire",
                    'os_updates', e
                    )
            )
            logger.exception(e)

        return(return_status)

    @db_create_close
    def filter_by_status_and_query_by_name_and_sev(self, name, pkg_status,
                                                   sev, conn=None):

        try:
            pkg = (
                r
                .table(self.CurrentAppsCollection)
                .get(self.app_id)
                .run(conn)
            )
            if agent:
                if pkg_status in CommonAppKeys.ValidPackageStatuses:
                    if sev in CommonSeverityKeys.ValidRvSeverities:
                        agents = list(
                            r
                            .table(self.CurrentAppsPerAgentCollection)
                            .get_all(
                                [self.app_id, pkg_status],
                                index=self.CurrentAppsPerAgentIndexes.AppIdAndStatus
                            )
                            .eq_join(
                                self.CurrentAppsPerAgentKeys.AppId,
                                r.table(self.CurrentAppsCollection)
                            )
                            .zip()
                            .eq_join(
                                self.CurrentAppsPerAgentKeys.AgentId,
                                r.table(AgentsCollection)
                            )
                            .zip()
                            .filter(
                                (r.row[self.CurrentAppsKeys.RvSeverity] == sev)
                                &
                                (r.row[self.CurrentAppsKeys.Name].match("(?i)"+name))
                            )
                            .order_by(r.asc(self.CurrentAppsKeys.Name))
                            .skip(self.offset)
                            .limit(self.count)
                            .map(self.map_hash)
                            .run(conn)
                        )

                        agent_count = (
                            r
                            .table(self.CurrentAppsPerAgentCollection)
                            .get_all(
                                [self.app_id, pkg_status],
                                index=self.CurrentAppsPerAgentIndexes.AppIdAndStatus
                            )
                            .eq_join(self.CurrentAppsPerAgentKeys.AppId,
                                     r.table(self.CurrentAppsCollection))
                            .zip()
                            .filter(
                                (r.row[self.CurrentAppsKeys.RvSeverity] == sev)
                                &
                                (r.row[self.CurrentAppsKeys.Name].match("(?i)"+name))
                                )
                            .count()
                            .run(conn)
                        )

                        return_status = (
                            GenericResults(
                                self.username, self.uri, self.method
                            ).information_retrieved(agents, agent_count)
                        )

                    else:
                        return_status = (
                            PackageResults(
                                self.username, self.uri, self.method
                            ).invalid_severity(sev)
                        )

                else:
                    return_status = (
                        PackageResults(
                            self.username, self.uri, self.method
                        ).invalid_status(self.app_id, pkg_status)
                    )

            else:
                return_status = (
                    GenericResults(
                        self.username, self.uri, self.method
                    ).invalid_id(self.app_id, 'os_apps')
                )

        except Exception as e:
            return_status = (
                GenericResults(
                    self.username, self.uri, self.method
                ).something_broke(
                    "Package Searching went haywire",
                    'os_updates', e
                    )
            )
            logger.exception(e)

        return(return_status)

    @db_create_close
    def filter_by_severity(self, sev, conn=None):
        try:
            pkg = (
                r
                .table(self.CurrentAppsCollection)
                .get(self.app_id)
                .run(conn)
            )
            if pkg:
                if sev in CommonSeverityKeys.ValidRvSeverities:
                    agents = list(
                        r
                        .table(self.CurrentAppsPerAgentCollection)
                        .get_all(
                            self.app_id, index=self.CurrentAppsPerAgentIndexes.AppId
                            )
                        .eq_join(
                            self.CurrentAppsPerAgentKeys.AppId,
                            r.table(self.CurrentAppsCollection)
                        )
                        .zip()
                        .eq_join(
                            self.CurrentAppsPerAgentKeys.AgentId,
                            r.table(AgentsCollection)
                        )
                        .zip()
                        .filter(r.row[self.CurrentAppsKeys.RvSeverity] == sev)
                        .order_by(r.asc(self.CurrentAppsKeys.Name))
                        .skip(self.offset)
                        .limit(self.count)
                        .map(self.map_hash)
                        .run(conn)
                    )

                    agent_count = (
                        r
                        .table(self.CurrentAppsPerAgentCollection)
                        .get_all(self.app_id, index=self.CurrentAppsPerAgentIndexes.AppId)
                        .eq_join(self.CurrentAppsPerAgentKeys.AppId, r.table(self.CurrentAppsCollection))
                        .zip()
                        .filter(r.row[self.CurrentAppsKeys.RvSeverity] == sev)
                        .count()
                        .run(conn)
                    )

                    return_status = (
                        GenericResults(
                            self.username, self.uri, self.method
                        ).information_retrieved(agents, agent_count)
                    )

                else:
                    return_status = (
                        PackageResults(
                            self.username, self.uri, self.method
                        ).invalid_severity(sev)
                    )

            else:
                return_status = (
                    GenericResults(
                        self.username, self.uri, self.method
                    ).invalid_id(self.app_id, 'os_apps')
                )

        except Exception as e:
            return_status = (
                GenericResults(
                    self.username, self.uri, self.method
                ).something_broke(
                    "Package Searching went haywire",
                    'os_updates', e
                    )
            )
            logger.exception(e)

        return(return_status)

    @db_create_close
    def filter_by_sev_and_query_by_name(self, name, sev, conn=None):

        try:
            pkg = (
                r
                .table(self.CurrentAppsCollection)
                .get(self.app_id)
                .run(conn)
            )
            if pkg:
                if sev in CommonSeverityKeys.ValidRvSeverities:
                    agents = list(
                        r
                        .table(self.CurrentAppsPerAgentCollection)
                        .get_all(
                            self.app_id, index=self.CurrentAppsPerAgentIndexes.AppId
                        )
                        .eq_join(
                            self.CurrentAppsPerAgentKeys.AppId,
                            r.table(self.CurrentAppsCollection)
                        )
                        .zip()
                        .eq_join(
                            self.CurrentAppsPerAgentKeys.AgentId,
                            r.table(AgentsCollection)
                        )
                        .zip()
                        .filter(
                            (r.row[self.CurrentAppsKeys.RvSeverity] == sev)
                            &
                            (r.row[self.CurrentAppsKeys.Name].match("(?i)"+name))
                        )
                        .order_by(r.asc(self.CurrentAppsKeys.Name))
                        .skip(self.offset)
                        .limit(self.count)
                        .map(self.map_hash)
                        .run(conn)
                    )

                    agent_count = (
                        r
                        .table(self.CurrentAppsPerAgentCollection)
                        .get_all(
                            self.app_id, index=self.CurrentAppsPerAgentIndexes.AppId
                        )
                        .eq_join(
                            self.CurrentAppsPerAgentKeys.AppId,
                            r.table(self.CurrentAppsCollection)
                        )
                        .zip()
                        .filter(
                            (r.row[self.CurrentAppsKeys.RvSeverity] == sev)
                            &
                            (r.row[self.CurrentAppsKeys.Name].match("(?i)"+name))
                        )
                        .count()
                        .run(conn)
                    )

                    return_status = (
                        GenericResults(
                            self.username, self.uri, self.method
                        ).information_retrieved(agents, agent_count)
                    )

                else:
                    return_status = (
                        PackageResults(
                            self.username, self.uri, self.method
                        ).invalid_severity(sev)
                    )

            else:
                return_status = (
                    GenericResults(
                        self.username, self.uri, self.method
                    ).invalid_id(self.app_id, 'agents')
                )

        except Exception as e:
            return_status = (
                GenericResults(
                    self.username, self.uri, self.method
                ).something_broke(
                    "Package Searching went haywire",
                    'os_updates', e
                    )
            )
            logger.exception(e)

        return(return_status)


    @db_create_close
    def filter_by_status_and_sev(self, pkg_status, sev, conn=None):

        try:
            pkg = (
                r
                .table(self.CurrentAppsCollection)
                .get(self.app_id)
                .run(conn)
            )
            if pkg:
                if pkg_status in CommonAppKeys.ValidPackageStatuses:
                    if sev in CommonSeverityKeys.ValidRvSeverities:
                        agents = list(
                            r
                            .table(self.CurrentAppsPerAgentCollection)
                            .get_all(
                                [self.app_id, pkg_status],
                                index=self.CurrentAppsPerAgentIndexes.AppIdAndStatus
                            )
                            .eq_join(
                                self.CurrentAppsPerAgentKeys.AppId,
                                r.table(self.CurrentAppsCollection)
                            )
                            .zip()
                            .eq_join(
                                self.CurrentAppsPerAgentKeys.AgentId,
                                r.table(AgentsCollection)
                            )
                            .zip()
                            .filter(r.row[self.CurrentAppsKeys.RvSeverity] == sev)
                            .order_by(r.asc(self.CurrentAppsKeys.Name))
                            .skip(self.offset)
                            .limit(self.count)
                            .map(self.map_hash)
                            .run(conn)
                        )

                        agent_count = (
                            r
                            .table(self.CurrentAppsPerAgentCollection)
                            .get_all(
                                [self.app_id, pkg_status],
                                index=self.CurrentAppsPerAgentIndexes.AppIdAndStatus
                            )
                            .eq_join(
                                self.CurrentAppsPerAgentKeys.AppId,
                                r.table(self.CurrentAppsCollection)
                            )
                            .zip()
                            .filter(r.row[self.CurrentAppsKeys.RvSeverity] == sev)
                            .count()
                            .run(conn)
                        )

                        return_status = (
                            GenericResults(
                                self.username, self.uri, self.method
                            ).information_retrieved(agents, agent_count)
                        )

                    else:
                        return_status = (
                            PackageResults(
                                self.username, self.uri, self.method
                            ).invalid_severity(sev)
                        )

                else:
                    return_status = (
                        PackageResults(
                            self.username, self.uri, self.method
                        ).invalid_status(self.app_id, pkg_status)
                    )

            else:
                return_status = (
                    GenericResults(
                        self.username, self.uri, self.method
                    ).invalid_id(self.app_id, 'os_apps')
                )

        except Exception as e:
            return_status = (
                GenericResults(
                    self.username, self.uri, self.method
                ).something_broke(
                    "Package Searching went haywire",
                    'os_updates', e
                    )
            )
            logger.exception(e)

        return(return_status)

class RetrieveCustomAppsByAppId(RetrieveAppsByAppId):
    """
        Main Class for retrieving package information.
    """
    def __init__(self, username, customer_name, app_id,
                 uri=None, method=None, count=30, offset=0):
        """
        """
        self.count = count
        self.offset = offset
        self.customer_name = customer_name
        self.username = username
        self.uri = uri
        self.method = method
        self.app_id = app_id
        self.CurrentAppsCollection = AppCollections.CustomApps
        self.CurrentAppsIndexes = CustomAppsIndexes
        self.CurrentAppsPerAgentCollection = AppCollections.CustomAppsPerAgent
        self.CurrentAppsKeys = CustomAppsKeys
        self.CurrentAppsPerAgentKeys = CustomAppsPerAgentKeys
        self.CurrentAppsPerAgentIndexes = CustomAppsPerAgentIndexes

        self.map_hash = (
            {
                self.CurrentAppsKeys.AppId: r.row[self.CurrentAppsKeys.AppId],
                self.CurrentAppsKeys.Version: r.row[self.CurrentAppsKeys.Version],
                self.CurrentAppsKeys.Name: r.row[self.CurrentAppsKeys.Name],
                self.CurrentAppsPerAgentKeys.Dependencies: r.row[self.CurrentAppsPerAgentKeys.Dependencies],
                self.CurrentAppsKeys.Description: r.row[self.CurrentAppsKeys.Description],
                self.CurrentAppsKeys.Kb: r.row[self.CurrentAppsKeys.Kb],
                self.CurrentAppsKeys.ReleaseDate: r.row[self.CurrentAppsKeys.ReleaseDate].to_epoch_time(),
                self.CurrentAppsKeys.RvSeverity: r.row[self.CurrentAppsKeys.RvSeverity],
                self.CurrentAppsKeys.VendorSeverity: r.row[self.CurrentAppsKeys.VendorSeverity],
                self.CurrentAppsKeys.VendorName: r.row[self.CurrentAppsKeys.VendorName],
                self.CurrentAppsKeys.SupportUrl: r.row[self.CurrentAppsKeys.SupportUrl],
                self.CurrentAppsKeys.OsCode: r.row[self.CurrentAppsKeys.OsCode],
                self.CurrentAppsKeys.FilesDownloadStatus: r.row[self.CurrentAppsKeys.FilesDownloadStatus],
                self.CurrentAppsKeys.CliOptions: r.row[self.CurrentAppsKeys.CliOptions],
            }
        )


class RetrieveSupportedAppsByAppId(RetrieveAppsByAppId):
    """
        Main Class for retrieving package information.
    """
    def __init__(self, username, customer_name, app_id,
                 uri=None, method=None, count=30, offset=0):
        """
        """
        self.count = count
        self.offset = offset
        self.customer_name = customer_name
        self.username = username
        self.uri = uri
        self.method = method
        self.app_id = app_id
        self.CurrentAppsCollection = AppCollections.SupportedApps
        self.CurrentAppsIndexes = SupportedAppsIndexes
        self.CurrentAppsPerAgentCollection = AppCollections.SupportedAppsPerAgent
        self.CurrentAppsKeys = SupportedAppsKeys
        self.CurrentAppsPerAgentKeys = SupportedAppsPerAgentKeys
        self.CurrentAppsPerAgentIndexes = SupportedAppsPerAgentIndexes

        self.map_hash = (
            {
                self.CurrentAppsKeys.AppId: r.row[self.CurrentAppsKeys.AppId],
                self.CurrentAppsKeys.Version: r.row[self.CurrentAppsKeys.Version],
                self.CurrentAppsKeys.Name: r.row[self.CurrentAppsKeys.Name],
                self.CurrentAppsPerAgentKeys.Dependencies: r.row[self.CurrentAppsPerAgentKeys.Dependencies],
                self.CurrentAppsKeys.Description: r.row[self.CurrentAppsKeys.Description],
                self.CurrentAppsKeys.Kb: r.row[self.CurrentAppsKeys.Kb],
                self.CurrentAppsKeys.ReleaseDate: r.row[self.CurrentAppsKeys.ReleaseDate].to_epoch_time(),
                self.CurrentAppsKeys.RvSeverity: r.row[self.CurrentAppsKeys.RvSeverity],
                self.CurrentAppsKeys.VendorSeverity: r.row[self.CurrentAppsKeys.VendorSeverity],
                self.CurrentAppsKeys.VendorName: r.row[self.CurrentAppsKeys.VendorName],
                self.CurrentAppsKeys.SupportUrl: r.row[self.CurrentAppsKeys.SupportUrl],
                self.CurrentAppsKeys.OsCode: r.row[self.CurrentAppsKeys.OsCode],
                self.CurrentAppsKeys.FilesDownloadStatus: r.row[self.CurrentAppsKeys.FilesDownloadStatus],
            }
        )

class RetrieveAgentAppsByAppId(RetrieveAppsByAppId):
    """
        Main Class for retrieving package information.
    """
    def __init__(self, username, customer_name, app_id,
                 uri=None, method=None, count=30, offset=0):
        """
        """
        self.count = count
        self.offset = offset
        self.customer_name = customer_name
        self.username = username
        self.uri = uri
        self.method = method
        self.app_id = app_id
        self.CurrentAppsCollection = AppCollections.vFenseApps
        self.CurrentAppsIndexes = vFenseAppsIndexes
        self.CurrentAppsPerAgentCollection = AppCollections.vFenseAppsPerAgent
        self.CurrentAppsKeys = vFenseAppsKeys
        self.CurrentAppsPerAgentKeys = vFenseAppsPerAgentKeys
        self.CurrentAppsPerAgentIndexes = vFenseAppsPerAgentIndexes

        self.map_hash = (
            {
                self.CurrentAppsKeys.AppId: r.row[self.CurrentAppsKeys.AppId],
                self.CurrentAppsKeys.Version: r.row[self.CurrentAppsKeys.Version],
                self.CurrentAppsKeys.Name: r.row[self.CurrentAppsKeys.Name],
                self.CurrentAppsPerAgentKeys.Dependencies: r.row[self.CurrentAppsPerAgentKeys.Dependencies],
                self.CurrentAppsKeys.Description: r.row[self.CurrentAppsKeys.Description],
                self.CurrentAppsKeys.Kb: r.row[self.CurrentAppsKeys.Kb],
                self.CurrentAppsKeys.ReleaseDate: r.row[self.CurrentAppsKeys.ReleaseDate].to_epoch_time(),
                self.CurrentAppsKeys.RvSeverity: r.row[self.CurrentAppsKeys.RvSeverity],
                self.CurrentAppsKeys.VendorSeverity: r.row[self.CurrentAppsKeys.VendorSeverity],
                self.CurrentAppsKeys.VendorName: r.row[self.CurrentAppsKeys.VendorName],
                self.CurrentAppsKeys.SupportUrl: r.row[self.CurrentAppsKeys.SupportUrl],
                self.CurrentAppsKeys.OsCode: r.row[self.CurrentAppsKeys.OsCode],
                self.CurrentAppsKeys.FilesDownloadStatus: r.row[self.CurrentAppsKeys.FilesDownloadStatus],
            }
        )


class RetrieveAgentsByCustomAppId(RetrieveAgentsByAppId):
    """
        This class is used to get agent data from within the Packages Page
    """
    def __init__(self, username, customer_name,
                 app_id, uri=None, method=None,
                 count=30, offset=0):
        """
        """
        self.count = count
        self.offset = offset
        self.customer_name = customer_name
        self.username = username
        self.uri = uri
        self.method = method
        self.app_id = app_id
        self.CurrentAppsCollection = AppCollections.CustomApps
        self.CurrentAppsIndexes = CustomAppsIndexes
        self.CurrentAppsPerAgentCollection = AppCollections.CustomAppsPerAgent
        self.CurrentAppsKeys = CustomAppsKeys
        self.CurrentAppsPerAgentKeys = CustomAppsPerAgentKeys
        self.CurrentAppsPerAgentIndexes = CustomAppsPerAgentIndexes

        self.map_hash = (
            {
                AgentKeys.ComputerName: r.row[AgentKeys.ComputerName],
                AgentKeys.DisplayName: r.row[AgentKeys.DisplayName],
                self.CurrentAppsPerAgentKeys.AgentId: r.row[self.CurrentAppsPerAgentKeys.AgentId]
            }
        )

class RetrieveAgentsBySupportedAppId(RetrieveAgentsByAppId):
    """
        This class is used to get agent data from within the Packages Page
    """
    def __init__(self, username, customer_name,
                 app_id, uri=None, method=None,
                 count=30, offset=0):
        """
        """
        self.count = count
        self.offset = offset
        self.customer_name = customer_name
        self.username = username
        self.uri = uri
        self.method = method
        self.app_id = app_id
        self.CurrentAppsCollection = AppCollections.SupportedApps
        self.CurrentAppsIndexes = SupportedAppsIndexes
        self.CurrentAppsPerAgentCollection = AppCollections.SupportedAppsPerAgent
        self.CurrentAppsKeys = SupportedAppsKeys
        self.CurrentAppsPerAgentKeys = SupportedAppsPerAgentKeys
        self.CurrentAppsPerAgentIndexes = SupportedAppsPerAgentIndexes

        self.map_hash = (
            {
                AgentKeys.ComputerName: r.row[AgentKeys.ComputerName],
                AgentKeys.DisplayName: r.row[AgentKeys.DisplayName],
                self.CurrentAppsPerAgentKeys.AgentId: r.row[self.CurrentAppsPerAgentKeys.AgentId]
            }
        )

class RetrieveAgentsByAgentAppId(RetrieveAgentsByAppId):
    """
        This class is used to get agent data from within the Packages Page
    """
    def __init__(self, username, customer_name,
                 app_id, uri=None, method=None,
                 count=30, offset=0):
        """
        """
        self.count = count
        self.offset = offset
        self.customer_name = customer_name
        self.username = username
        self.uri = uri
        self.method = method
        self.app_id = app_id
        self.CurrentAppsCollection = AppCollections.vFenseApps
        self.CurrentAppsIndexes = vFenseAppsIndexes
        self.CurrentAppsPerAgentCollection = AppCollections.vFenseAppsPerAgent
        self.CurrentAppsKeys = vFenseAppsKeys
        self.CurrentAppsPerAgentKeys = vFenseAppsPerAgentKeys
        self.CurrentAppsPerAgentIndexes = vFenseAppsPerAgentIndexes

        self.map_hash = (
            {
                AgentKeys.ComputerName: r.row[AgentKeys.ComputerName],
                AgentKeys.DisplayName: r.row[AgentKeys.DisplayName],
                self.CurrentAppsPerAgentKeys.AgentId: r.row[self.CurrentAppsPerAgentKeys.AgentId]
            }
        )

