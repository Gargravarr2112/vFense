import logging
import logging.config
from vFense import VFENSE_LOGGING_CONFIG
from vFense.db.client import db_create_close, r
from vFense.plugins.patching import *
from vFense.core._constants import CommonKeys
from vFense.plugins.patching._constants import CommonSeverityKeys, CommonAppKeys
from vFense.core.agent import *
from vFense.core.agent.agents import get_agent_info
from vFense.errorz.error_messages import GenericResults, PackageResults

logging.config.fileConfig(VFENSE_LOGGING_CONFIG)
logger = logging.getLogger('rvapi')

class RetrieveAppsByAgentId(object):
    """
        This class is used to get agent data from within the Packages Page
    """
    def __init__(self, username, customer_name,
                 agent_id, uri=None, method=None,
                 count=30, offset=0, sort='asc',
                 sort_key=AppsKeys.Name,
                 show_hidden=CommonKeys.NO):
        """
        """
        self.count = count
        self.uri = uri
        self.method = method
        self.offset = offset
        self.count = count
        self.sort = sort
        self.agent_id = agent_id
        self.username = username
        self.customer_name = customer_name
        self.CurrentAppsCollection = AppCollections.UniqueApplications
        self.CurrentAppsIndexes = AppsIndexes
        self.CurrentAppsPerAgentCollection = AppCollections.AppsPerAgent
        self.CurrentAppsKeys = AppsKeys
        self.CurrentAppsPerAgentKeys = AppsPerAgentKeys
        self.CurrentAppsPerAgentIndexes = AppsPerAgentIndexes

        self.pluck_list = (
            [
                self.CurrentAppsKeys.AppId,
                self.CurrentAppsKeys.Version,
                self.CurrentAppsKeys.Name,
                self.CurrentAppsPerAgentKeys.Update,
                self.CurrentAppsKeys.ReleaseDate,
                self.CurrentAppsKeys.Hidden,
                self.CurrentAppsKeys.RebootRequired,
                self.CurrentAppsKeys.RvSeverity,
                self.CurrentAppsKeys.FilesDownloadStatus,
                self.CurrentAppsPerAgentKeys.Dependencies,
                self.CurrentAppsPerAgentKeys.InstallDate,
                self.CurrentAppsPerAgentKeys.Status,
                self.CurrentAppsPerAgentKeys.Update,
                self.CurrentAppsKeys.VulnerabilityId,
            ]
        )

        self.map_hash = (
            {
                self.CurrentAppsKeys.AppId: r.row[self.CurrentAppsKeys.AppId],
                self.CurrentAppsKeys.Version: r.row[self.CurrentAppsKeys.Version],
                self.CurrentAppsKeys.Name: r.row[self.CurrentAppsKeys.Name],
                self.CurrentAppsKeys.Hidden: r.row[self.CurrentAppsKeys.Hidden],
                self.CurrentAppsPerAgentKeys.Update: r.row[self.CurrentAppsPerAgentKeys.Update],
                self.CurrentAppsKeys.ReleaseDate: r.row[self.CurrentAppsKeys.ReleaseDate].to_epoch_time(),
                self.CurrentAppsKeys.RvSeverity: r.row[self.CurrentAppsKeys.RvSeverity],
                self.CurrentAppsKeys.RebootRequired: r.row[self.CurrentAppsKeys.RebootRequired],
                self.CurrentAppsKeys.FilesDownloadStatus: r.row[self.CurrentAppsKeys.FilesDownloadStatus],
                self.CurrentAppsPerAgentKeys.Dependencies: r.row[self.CurrentAppsPerAgentKeys.Dependencies],
                self.CurrentAppsPerAgentKeys.InstallDate: r.row[self.CurrentAppsPerAgentKeys.InstallDate].to_epoch_time(),
                self.CurrentAppsPerAgentKeys.Status: r.row[self.CurrentAppsPerAgentKeys.Status],
                self.CurrentAppsPerAgentKeys.Update: r.row[self.CurrentAppsPerAgentKeys.Update],
                self.CurrentAppsKeys.VulnerabilityId: r.row[self.CurrentAppsKeys.VulnerabilityId],
            }
        )

        if show_hidden in CommonAppKeys.ValidHiddenVals:
            self.show_hidden = show_hidden
        else:
            self.show_hidden = CommonKeys.NO

        if sort_key in self.pluck_list:
            self.sort_key = sort_key
        else:
            self.sort_key = self.CurrentAppsKeys.Name

        if sort == 'asc':
            self.sort = r.asc
        else:
            self.sort = r.desc

    @db_create_close
    def filter_by_status(self, pkg_status, conn=None):
        try:
            agent = get_agent_info(self.agent_id)
            if agent:
                if pkg_status in CommonAppKeys.ValidPackageStatuses:
                    base = (
                        r
                        .table(self.CurrentAppsPerAgentCollection)
                        .get_all(
                            [pkg_status, self.agent_id],
                            index=self.CurrentAppsPerAgentIndexes.StatusAndAgentId)
                        .eq_join(self.CurrentAppsPerAgentKeys.AppId, r.table(self.CurrentAppsCollection))
                        .zip()
                    )
                    if self.show_hidden == CommonKeys.NO:
                        base = base.filter({self.CurrentAppsKeys.Hidden: CommonKeys.NO})

                    packages = list(
                        base
                        .map(self.map_hash)
                        .order_by(self.sort(self.sort_key))
                        .skip(self.offset)
                        .limit(self.count)
                        .run(conn)
                    )

                    pkg_count = (
                        base
                        .count()
                        .run(conn)
                    )

                    return_status = (
                        GenericResults(
                            self.username, self.uri, self.method
                        ).information_retrieved(packages, pkg_count)
                    )

                else:
                    return_status = (
                        PackageResults(
                            self.username, self.uri, self.method
                        ).invalid_status(self.agent_id, pkg_status)
                    )

            else:
                return_status = (
                    GenericResults(
                        self.username, self.uri, self.method
                    ).invalid_id(self.agent_id, 'agents')
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
            agent = get_agent_info(self.agent_id)
            if agent:
                if pkg_status in CommonAppKeys.ValidPackageStatuses:
                    base = (
                        r
                        .table(self.CurrentAppsPerAgentCollection)
                        .get_all(
                            [pkg_status, self.agent_id],
                            index=self.CurrentAppsPerAgentIndexes.StatusAndAgentId
                        )
                        .eq_join(
                            self.CurrentAppsPerAgentKeys.AppId,
                            r.table(self.CurrentAppsCollection)
                        )
                        .zip()
                    )
                    if self.show_hidden == CommonKeys.NO:
                        base = base.filter({self.CurrentAppsKeys.Hidden: CommonKeys.NO})

                    packages = list(
                        base
                        .filter(lambda x: x[self.CurrentAppsKeys.Name].match("(?i)"+name))
                        .map(self.map_hash)
                        .order_by(self.sort(self.sort_key))
                        .skip(self.offset)
                        .limit(self.count)
                        .run(conn)
                    )

                    pkg_count = (
                        base
                        .filter(lambda x: x[self.CurrentAppsKeys.Name].match("(?i)"+name))
                        .count()
                        .run(conn)
                    )

                    return_status = (
                        GenericResults(
                            self.username, self.uri, self.method
                        ).information_retrieved(packages, pkg_count)
                    )

                else:
                    return_status = (
                        PackageResults(
                            self.username, self.uri, self.method
                        ).invalid_status(self.agent_id, pkg_status)
                    )

            else:
                return_status = (
                    GenericResults(
                        self.username, self.uri, self.method
                    ).invalid_id(self.agent_id, 'agents')
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
            agent = get_agent_info(self.agent_id)
            if agent:
                base = (
                    r
                    .table(self.CurrentAppsPerAgentCollection)
                    .get_all(self.agent_id, index=self.CurrentAppsPerAgentIndexes.AgentId)
                    .eq_join(self.CurrentAppsPerAgentKeys.AppId, r.table(self.CurrentAppsCollection))
                    .zip()
                )
                if self.show_hidden == CommonKeys.NO:
                    base = base.filter({self.CurrentAppsKeys.Hidden: CommonKeys.NO})

                packages = list(
                    base
                    .filter(lambda x: x[self.CurrentAppsKeys.Name].match("(?i)"+name))
                    .map(self.map_hash)
                    .order_by(self.sort(self.sort_key))
                    .skip(self.offset)
                    .limit(self.count)
                    .run(conn)
                )

                pkg_count = (
                    base
                    .filter(lambda x: x[self.CurrentAppsKeys.Name].match("(?i)"+name))
                    .count()
                    .run(conn)
                )

                return_status = (
                    GenericResults(
                        self.username, self.uri, self.method
                    ).information_retrieved(packages, pkg_count)
                )

            else:
                return_status = (
                    GenericResults(
                        self.username, self.uri, self.method
                    ).invalid_id(self.agent_id, 'agents')
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
            agent = get_agent_info(self.agent_id)
            if agent:
                if pkg_status in CommonAppKeys.ValidPackageStatuses:
                    if sev in CommonSeverityKeys.ValidRvSeverities:
                        base = (
                            r
                            .table(self.CurrentAppsPerAgentCollection)
                            .get_all(
                                [pkg_status, self.agent_id],
                                index=self.CurrentAppsPerAgentIndexes.StatusAndAgentId
                            )
                            .eq_join(
                                self.CurrentAppsPerAgentKeys.AppId,
                                r.table(self.CurrentAppsCollection)
                            )
                            .zip()
                        )
                        if self.show_hidden == CommonKeys.NO:
                            base = base.filter({self.CurrentAppsKeys.Hidden: CommonKeys.NO})

                        packages = list(
                            base
                            .filter(
                                (r.row[self.CurrentAppsKeys.RvSeverity] == sev)
                                &
                                (r.row[self.CurrentAppsKeys.Name].match("(?i)"+name))
                            )
                            .map(self.map_hash)
                            .order_by(self.sort(self.sort_key))
                            .skip(self.offset)
                            .limit(self.count)
                            .run(conn)
                        )

                        pkg_count = (
                            base
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
                            ).information_retrieved(packages, pkg_count)
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
                        ).invalid_status(self.agent_id, pkg_status)
                    )

            else:
                return_status = (
                    GenericResults(
                        self.username, self.uri, self.method
                    ).invalid_id(self.agent_id, 'agents')
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
            agent = get_agent_info(self.agent_id)
            if agent:
                if sev in CommonSeverityKeys.ValidRvSeverities:
                    base = (
                        r
                        .table(self.CurrentAppsPerAgentCollection)
                        .get_all(
                            self.agent_id, index=self.CurrentAppsPerAgentIndexes.AgentId
                        )
                        .eq_join(
                            self.CurrentAppsPerAgentKeys.AppId,
                            r.table(self.CurrentAppsCollection)
                        )
                        .zip()
                    )
                    if self.show_hidden == CommonKeys.NO:
                        base = base.filter({self.CurrentAppsKeys.Hidden: CommonKeys.NO})

                    packages = list(
                        base
                        .filter(
                            (r.row[self.CurrentAppsKeys.RvSeverity] == sev)
                            &
                            (r.row[self.CurrentAppsKeys.Name].match("(?i)"+name))
                        )
                        .map(self.map_hash)
                        .order_by(self.sort(self.sort_key))
                        .skip(self.offset)
                        .limit(self.count)
                        .run(conn)
                    )

                    pkg_count = (
                        base
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
                        ).information_retrieved(packages, pkg_count)
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
                    ).invalid_id(self.agent_id, 'agents')
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
            agent = get_agent_info(self.agent_id)
            if agent:
                if sev in CommonSeverityKeys.ValidRvSeverities:
                    base = (
                        r
                        .table(self.CurrentAppsPerAgentCollection)
                        .get_all(
                            self.agent_id, index=self.CurrentAppsPerAgentIndexes.AgentId
                        )
                        .eq_join(
                            self.CurrentAppsPerAgentKeys.AppId,
                            r.table(self.CurrentAppsCollection)
                        )
                        .zip()
                    )
                    if self.show_hidden == CommonKeys.NO:
                        base = base.filter({self.CurrentAppsKeys.Hidden: CommonKeys.NO})

                    packages = list(
                        base
                        .filter(r.row[self.CurrentAppsKeys.RvSeverity] == sev)
                        .map(self.map_hash)
                        .order_by(self.sort(self.sort_key))
                        .skip(self.offset)
                        .limit(self.count)
                        .run(conn)
                    )

                    pkg_count = (
                        base
                        .filter(r.row[self.CurrentAppsKeys.RvSeverity] == sev)
                        .count()
                        .run(conn)
                    )

                    return_status = (
                        GenericResults(
                            self.username, self.uri, self.method
                        ).information_retrieved(packages, pkg_count)
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
                    ).invalid_id(self.agent_id, 'agents')
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
            agent = get_agent_info(self.agent_id)
            if agent:
                if pkg_status in CommonAppKeys.ValidPackageStatuses:
                    if sev in CommonSeverityKeys.ValidRvSeverities:
                        base = (
                            r
                            .table(self.CurrentAppsPerAgentCollection)
                            .get_all(
                                [pkg_status, self.agent_id],
                                index=self.CurrentAppsPerAgentIndexes.StatusAndAgentId
                            )
                            .eq_join(
                                self.CurrentAppsPerAgentKeys.AppId,
                                r.table(self.CurrentAppsCollection)
                            )
                            .zip()
                        )
                        if self.show_hidden == CommonKeys.NO:
                            base = base.filter({self.CurrentAppsKeys.Hidden: CommonKeys.NO})

                        packages = list(
                            base
                            .filter(r.row[self.CurrentAppsKeys.RvSeverity] == sev)
                            .map(self.map_hash)
                            .order_by(self.sort(self.sort_key))
                            .skip(self.offset)
                            .limit(self.count)
                            .run(conn)
                        )

                        pkg_count = (
                            base
                            .filter(r.row[self.CurrentAppsKeys.RvSeverity] == sev)
                            .count()
                            .run(conn)
                        )

                        return_status = (
                            GenericResults(
                                self.username, self.uri, self.method
                            ).information_retrieved(packages, pkg_count)
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
                        ).invalid_status(self.agent_id, pkg_status)
                    )

            else:
                return_status = (
                    GenericResults(
                        self.username, self.uri, self.method
                    ).invalid_id(self.agent_id, 'agents')
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

class RetrieveCustomAppsByAgentId(RetrieveAppsByAgentId):
    """
        This class is used to get agent data from within the Packages Page
    """
    def __init__(self, username, customer_name,
                 agent_id, uri=None, method=None,
                 count=30, offset=0, sort='asc',
                 sort_key=CustomAppsKeys.Name,
                 show_hidden=CommonKeys.NO):
        """
        """
        self.count = count
        self.uri = uri
        self.method = method
        self.offset = offset
        self.count = count
        self.sort = sort
        self.agent_id = agent_id
        self.username = username
        self.customer_name = customer_name
        self.CurrentAppsCollection = AppCollections.CustomApps
        self.CurrentAppsIndexes = CustomAppsIndexes
        self.CurrentAppsPerAgentCollection = AppCollections.CustomAppsPerAgent
        self.CurrentAppsKeys = CustomAppsKeys
        self.CurrentAppsPerAgentKeys = CustomAppsPerAgentKeys
        self.CurrentAppsPerAgentIndexes = CustomAppsPerAgentIndexes

        self.pluck_list = (
            [
                self.CurrentAppsKeys.AppId,
                self.CurrentAppsKeys.Version,
                self.CurrentAppsKeys.Name,
                self.CurrentAppsKeys.Hidden,
                self.CurrentAppsPerAgentKeys.Update,
                self.CurrentAppsKeys.ReleaseDate,
                self.CurrentAppsKeys.RebootRequired,
                self.CurrentAppsKeys.RvSeverity,
                self.CurrentAppsKeys.FilesDownloadStatus,
                self.CurrentAppsPerAgentKeys.Dependencies,
                self.CurrentAppsPerAgentKeys.InstallDate,
                self.CurrentAppsPerAgentKeys.Status,
                self.CurrentAppsPerAgentKeys.Update,
            ]
        )

        self.map_hash = (
            {
                self.CurrentAppsKeys.AppId: r.row[self.CurrentAppsKeys.AppId],
                self.CurrentAppsKeys.Version: r.row[self.CurrentAppsKeys.Version],
                self.CurrentAppsKeys.Name: r.row[self.CurrentAppsKeys.Name],
                self.CurrentAppsKeys.Hidden: r.row[self.CurrentAppsKeys.Hidden],
                self.CurrentAppsPerAgentKeys.Update: r.row[self.CurrentAppsPerAgentKeys.Update],
                self.CurrentAppsKeys.ReleaseDate: r.row[self.CurrentAppsKeys.ReleaseDate].to_epoch_time(),
                self.CurrentAppsKeys.RvSeverity: r.row[self.CurrentAppsKeys.RvSeverity],
                self.CurrentAppsKeys.RebootRequired: r.row[self.CurrentAppsKeys.RebootRequired],
                self.CurrentAppsKeys.FilesDownloadStatus: r.row[self.CurrentAppsKeys.FilesDownloadStatus],
                self.CurrentAppsPerAgentKeys.Dependencies: r.row[self.CurrentAppsPerAgentKeys.Dependencies],
                self.CurrentAppsPerAgentKeys.InstallDate: r.row[self.CurrentAppsPerAgentKeys.InstallDate].to_epoch_time(),
                self.CurrentAppsPerAgentKeys.Status: r.row[self.CurrentAppsPerAgentKeys.Status],
                self.CurrentAppsPerAgentKeys.Update: r.row[self.CurrentAppsPerAgentKeys.Update],
            }
        )

        if show_hidden in CommonAppKeys.ValidHiddenVals:
            self.show_hidden = show_hidden
        else:
            self.show_hidden = CommonKeys.NO

        if sort_key in self.pluck_list:
            self.sort_key = sort_key
        else:
            self.sort_key = self.CurrentAppsKeys.Name

        if sort == 'asc':
            self.sort = r.asc
        else:
            self.sort = r.desc


class RetrieveSupportedAppsByAgentId(RetrieveAppsByAgentId):
    """
        This class is used to get agent data from within the Packages Page
    """
    def __init__(self, username, customer_name,
                 agent_id, uri=None, method=None,
                 count=30, offset=0, sort='asc',
                 sort_key=SupportedAppsKeys.Name,
                 show_hidden=CommonKeys.NO):
        """
        """
        self.count = count
        self.uri = uri
        self.method = method
        self.offset = offset
        self.count = count
        self.sort = sort
        self.agent_id = agent_id
        self.username = username
        self.customer_name = customer_name
        self.CurrentAppsCollection = AppCollections.SupportedApps
        self.CurrentAppsIndexes = SupportedAppsIndexes
        self.CurrentAppsPerAgentCollection = AppCollections.SupportedAppsPerAgent
        self.CurrentAppsKeys = SupportedAppsKeys
        self.CurrentAppsPerAgentKeys = SupportedAppsPerAgentKeys
        self.CurrentAppsPerAgentIndexes = SupportedAppsPerAgentIndexes

        self.pluck_list = (
            [
                self.CurrentAppsKeys.AppId,
                self.CurrentAppsKeys.Version,
                self.CurrentAppsKeys.Name,
                self.CurrentAppsKeys.Hidden,
                self.CurrentAppsPerAgentKeys.Update,
                self.CurrentAppsKeys.ReleaseDate,
                self.CurrentAppsKeys.RebootRequired,
                self.CurrentAppsKeys.RvSeverity,
                self.CurrentAppsKeys.FilesDownloadStatus,
                self.CurrentAppsPerAgentKeys.Dependencies,
                self.CurrentAppsPerAgentKeys.InstallDate,
                self.CurrentAppsPerAgentKeys.Status,
                self.CurrentAppsPerAgentKeys.Update,
            ]
        )

        self.map_hash = (
            {
                self.CurrentAppsKeys.AppId: r.row[self.CurrentAppsKeys.AppId],
                self.CurrentAppsKeys.Version: r.row[self.CurrentAppsKeys.Version],
                self.CurrentAppsKeys.Name: r.row[self.CurrentAppsKeys.Name],
                self.CurrentAppsKeys.Hidden: r.row[self.CurrentAppsKeys.Hidden],
                self.CurrentAppsPerAgentKeys.Update: r.row[self.CurrentAppsPerAgentKeys.Update],
                self.CurrentAppsKeys.ReleaseDate: r.row[self.CurrentAppsKeys.ReleaseDate].to_epoch_time(),
                self.CurrentAppsKeys.RvSeverity: r.row[self.CurrentAppsKeys.RvSeverity],
                self.CurrentAppsKeys.RebootRequired: r.row[self.CurrentAppsKeys.RebootRequired],
                self.CurrentAppsKeys.FilesDownloadStatus: r.row[self.CurrentAppsKeys.FilesDownloadStatus],
                self.CurrentAppsPerAgentKeys.Dependencies: r.row[self.CurrentAppsPerAgentKeys.Dependencies],
                self.CurrentAppsPerAgentKeys.InstallDate: r.row[self.CurrentAppsPerAgentKeys.InstallDate].to_epoch_time(),
                self.CurrentAppsPerAgentKeys.Status: r.row[self.CurrentAppsPerAgentKeys.Status],
                self.CurrentAppsPerAgentKeys.Update: r.row[self.CurrentAppsPerAgentKeys.Update],
            }
        )

        if show_hidden in CommonAppKeys.ValidHiddenVals:
            self.show_hidden = show_hidden
        else:
            self.show_hidden = CommonKeys.NO

        if sort_key in self.pluck_list:
            self.sort_key = sort_key
        else:
            self.sort_key = self.CurrentAppsKeys.Name

        if sort == 'asc':
            self.sort = r.asc
        else:
            self.sort = r.desc


class RetrieveAgentAppsByAgentId(RetrieveAppsByAgentId):
    """
        This class is used to get agent data from within the Packages Page
    """
    def __init__(self, username, customer_name,
                 agent_id, uri=None, method=None,
                 count=30, offset=0, sort='asc',
                 sort_key=AgentAppsKeys.Name,
                 show_hidden=CommonKeys.NO):

        self.count = count
        self.uri = uri
        self.method = method
        self.offset = offset
        self.count = count
        self.sort = sort
        self.agent_id = agent_id
        self.username = username
        self.customer_name = customer_name
        self.CurrentAppsCollection = AppCollections.vFenseApps
        self.CurrentAppsIndexes = AgentAppsIndexes
        self.CurrentAppsPerAgentCollection = AppCollections.vFenseAppsPerAgent
        self.CurrentAppsKeys = AgentAppsKeys
        self.CurrentAppsPerAgentKeys = AgentAppsPerAgentKeys
        self.CurrentAppsPerAgentIndexes = AgentAppsPerAgentIndexes

        self.pluck_list = (
            [
                self.CurrentAppsKeys.AppId,
                self.CurrentAppsKeys.Version,
                self.CurrentAppsKeys.Name,
                self.CurrentAppsKeys.Hidden,
                self.CurrentAppsPerAgentKeys.Update,
                self.CurrentAppsKeys.ReleaseDate,
                self.CurrentAppsKeys.RebootRequired,
                self.CurrentAppsKeys.RvSeverity,
                self.CurrentAppsKeys.FilesDownloadStatus,
                self.CurrentAppsPerAgentKeys.Dependencies,
                self.CurrentAppsPerAgentKeys.InstallDate,
                self.CurrentAppsPerAgentKeys.Status,
                self.CurrentAppsPerAgentKeys.Update,
            ]
        )

        self.map_hash = (
            {
                self.CurrentAppsKeys.AppId: r.row[self.CurrentAppsKeys.AppId],
                self.CurrentAppsKeys.Version: r.row[self.CurrentAppsKeys.Version],
                self.CurrentAppsKeys.Name: r.row[self.CurrentAppsKeys.Name],
                self.CurrentAppsKeys.Hidden: r.row[self.CurrentAppsKeys.Hidden],
                self.CurrentAppsKeys.RvSeverity: r.row[self.CurrentAppsKeys.RvSeverity],
                self.CurrentAppsKeys.RebootRequired: r.row[self.CurrentAppsKeys.RebootRequired],
                self.CurrentAppsKeys.FilesDownloadStatus: r.row[self.CurrentAppsKeys.FilesDownloadStatus],
                self.CurrentAppsPerAgentKeys.Update: r.row[self.CurrentAppsPerAgentKeys.Update],
                self.CurrentAppsKeys.ReleaseDate: r.row[self.CurrentAppsKeys.ReleaseDate].to_epoch_time(),
                self.CurrentAppsPerAgentKeys.Dependencies: r.row[self.CurrentAppsPerAgentKeys.Dependencies],
                self.CurrentAppsPerAgentKeys.InstallDate: r.row[self.CurrentAppsPerAgentKeys.InstallDate].to_epoch_time(),
                self.CurrentAppsPerAgentKeys.Status: r.row[self.CurrentAppsPerAgentKeys.Status],
                self.CurrentAppsPerAgentKeys.Update: r.row[self.CurrentAppsPerAgentKeys.Update],
            }
        )

        if show_hidden in CommonAppKeys.ValidHiddenVals:
            self.show_hidden = show_hidden
        else:
            self.show_hidden = CommonKeys.NO

        if sort_key in self.pluck_list:
            self.sort_key = sort_key
        else:
            self.sort_key = self.CurrentAppsKeys.Name

        if sort == 'asc':
            self.sort = r.asc
        else:
            self.sort = r.desc

