import logging
import logging.config
from vFense import VFENSE_LOGGING_CONFIG

from vFense.db.client import db_create_close, r
from vFense.plugins.patching import *
from vFense.core._constants import CommonKeys
from vFense.plugins.patching._constants import CommonAppKeys, CommonSeverityKeys
from vFense.core.agent import *
from vFense.errorz.error_messages import GenericResults, PackageResults

logging.config.fileConfig(VFENSE_LOGGING_CONFIG)
logger = logging.getLogger('rvapi')


class RetrieveApps(object):
    """
        This class is used to get agent data from within the Packages Page
    """
    def __init__(self, username, customer_name,
                 uri=None, method=None, count=30,
                 offset=0, sort='asc', sort_key=AppsKeys.Name,
                 show_hidden=CommonKeys.NO):
        """
        """
        self.count = count
        self.offset = offset
        self.customer_name = customer_name
        self.username = username
        self.uri = uri
        self.method = method

        self.set_global_properties(
            AppCollections.UniqueApplications,
            AppsIndexes, 
            AppCollections.AppsPerAgent, AppsKeys, AppsPerAgentKeys,
            AppsPerAgentIndexes
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

    def set_global_properties(self, apps_collection, apps_indexes,
                              apps_per_agent_collection, apps_key,
                              apps_per_agent_key, apps_per_agent_indexes):
        """ Set the global properties. """

        self.CurrentAppsCollection = apps_collection
        self.CurrentAppsIndexes = apps_indexes
        self.CurrentAppsPerAgentCollection = apps_per_agent_collection
        self.CurrentAppsKeys = apps_key
        self.CurrentAppsPerAgentKeys = apps_per_agent_key
        self.CurrentAppsPerAgentIndexes = apps_per_agent_indexes

        self.joined_map_hash = (
            {                                                                                                                                                      
                self.CurrentAppsKeys.AppId:
                    r.row['right'][self.CurrentAppsKeys.AppId],
                self.CurrentAppsKeys.Version:
                    r.row['right'][self.CurrentAppsKeys.Version],
                self.CurrentAppsKeys.Name:
                    r.row['right'][self.CurrentAppsKeys.Name],
                self.CurrentAppsKeys.ReleaseDate:
                    r.row['right'][self.CurrentAppsKeys.ReleaseDate].to_epoch_time(),
                self.CurrentAppsKeys.RvSeverity:
                    r.row['right'][self.CurrentAppsKeys.RvSeverity],
                self.CurrentAppsKeys.VulnerabilityId:
                    r.row['right'][self.CurrentAppsKeys.VulnerabilityId],
                self.CurrentAppsKeys.Hidden:
                    r.row['right'][self.CurrentAppsKeys.Hidden],
            }
        )

        self.map_hash = (
            {
                self.CurrentAppsKeys.AppId: r.row[self.CurrentAppsKeys.AppId],
                self.CurrentAppsKeys.Version: r.row[self.CurrentAppsKeys.Version],
                self.CurrentAppsKeys.Name: r.row[self.CurrentAppsKeys.Name],
                self.CurrentAppsKeys.ReleaseDate: r.row[self.CurrentAppsKeys.ReleaseDate].to_epoch_time(),
                self.CurrentAppsKeys.RvSeverity: r.row[self.CurrentAppsKeys.RvSeverity],
                self.CurrentAppsKeys.VulnerabilityId: r.row[self.CurrentAppsKeys.VulnerabilityId],
            }
        )
        self.pluck_list = (
            [
                self.CurrentAppsKeys.AppId,
                self.CurrentAppsKeys.Version,
                self.CurrentAppsKeys.Name,
                self.CurrentAppsKeys.ReleaseDate,
                self.CurrentAppsKeys.RvSeverity,
                self.CurrentAppsKeys.VulnerabilityId,
            ]
        )

    @db_create_close
    def filter_by_status(self, pkg_status, conn=None):
        try:
            if pkg_status in CommonAppKeys.ValidPackageStatuses:
                base = (
                    r
                    .table(self.CurrentAppsPerAgentCollection)
                    .get_all(
                        [pkg_status, self.customer_name],
                        index=self.CurrentAppsPerAgentIndexes.StatusAndCustomer)
                    .eq_join(self.CurrentAppsKeys.AppId, r.table(self.CurrentAppsCollection))
                    .map(self.joined_map_hash)
                )

                if self.show_hidden == CommonKeys.NO:
                    base = base.filter(
                        {self.CurrentAppsKeys.Hidden: CommonKeys.NO}
                    )

                packages = list(
                    base
                    .distinct()
                    .order_by(self.sort(self.sort_key))
                    .skip(self.offset)
                    .limit(self.count)
                    .run(conn)
                )

                pkg_count = (
                    base
                    .pluck(self.CurrentAppsKeys.AppId)
                    .distinct()
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
                    ).invalid_global_status(pkg_status)
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
            if sev in CommonSeverityKeys.ValidRvSeverities:
                base = (
                    r
                    .table(self.CurrentAppsCollection)
                    .get_all(self.customer_name, sev, index=self.CurrentAppsIndexes.CustomerAndRvSeverity)
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
                    .pluck(self.pluck_list)
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
            if pkg_status in CommonAppKeys.ValidPackageStatuses:
                if sev in CommonSeverityKeys.ValidRvSeverities:
                    base = (
                        r
                        .table(self.CurrentAppsPerAgentCollection)
                        .get_all(
                            [pkg_status, self.customer_name],
                            index=self.CurrentAppsPerAgentIndexes.StatusAndCustomer
                        )
                        .eq_join(
                            self.CurrentAppsPerAgentKeys.AppId,
                            r.table(self.CurrentAppsCollection)
                        )
                        .map(self.joined_map_hash)
                    )

                    if self.show_hidden == CommonKeys.NO:
                        base = base.filter({self.CurrentAppsKeys.Hidden: CommonKeys.NO})

                    packages = list(
                        base
                        .filter(r.row[self.CurrentAppsKeys.RvSeverity] == sev)
                        .distinct()
                        .order_by(self.sort(self.sort_key))
                        .skip(self.offset)
                        .limit(self.count)
                        .run(conn)
                    )

                    pkg_count = (
                        base
                        .filter(r.row[self.CurrentAppsKeys.RvSeverity] == sev)
                        .pluck(self.pluck_list)
                        .distinct()
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
                    ).invalid_global_status(pkg_status)
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
    def get_all_apps(self, conn=None):
        try:
            base = (
                r
                .table(self.CurrentAppsCollection)
                .get_all(self.customer_name, index=self.CurrentAppsIndexes.Customers)
            )

            if self.show_hidden == CommonKeys.NO:
                base = base.filter({self.CurrentAppsKeys.Hidden: CommonKeys.NO})

            packages = list(
                base
                .order_by(self.sort(self.sort_key))
                .map(self.map_hash)
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
            base = (
                r
                .table(self.CurrentAppsCollection)
                .get_all(self.customer_name, index=self.CurrentAppsIndexes.Customers)
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
                .pluck(self.CurrentAppsKeys.AppId)
                .count()
                .run(conn)
            )

            return_status = (
                GenericResults(
                    self.username, self.uri, self.method
                ).information_retrieved(packages, pkg_count)
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
            if pkg_status in CommonAppKeys.ValidPackageStatuses:
                base = (
                    r
                    .table(self.CurrentAppsPerAgentCollection)
                    .get_all(
                        pkg_status, index=self.CurrentAppsPerAgentIndexes.Status
                    )
                    .eq_join(self.CurrentAppsPerAgentKeys.AppId, r.table(self.CurrentAppsCollection))
                    .map(self.joined_map_hash)
                )

                if self.show_hidden == CommonKeys.NO:
                    base = base.filter({self.CurrentAppsKeys.Hidden: CommonKeys.NO})

                packages = list(
                    base
                    .filter(lambda x: x[self.CurrentAppsKeys.Name].match("(?i)"+name))
                    .distinct()
                    .order_by(self.sort(self.sort_key))
                    .skip(self.offset)
                    .limit(self.count)
                    .run(conn)
                )

                pkg_count = (
                    base
                    .filter(lambda x: x[self.CurrentAppsKeys.Name].match("(?i)"+name))
                    .pluck(self.CurrentAppsKeys.AppId)
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
                    ).invalid_global_status(pkg_status)
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
            if pkg_status in CommonAppKeys.ValidPackageStatuses:
                if sev in CommonSeverityKeys.ValidRvSeverities:
                    base = (
                        r
                        .table(self.CurrentAppsPerAgentCollection)
                        .get_all(
                            [pkg_status, self.customer_name],
                            index=self.CurrentAppsPerAgentIndexes.StatusAndCustomer
                        )
                        .eq_join(
                            self.CurrentAppsPerAgentKeys.AppId,
                            r.table(self.CurrentAppsCollection)
                        )
                        .map(self.joined_map_hash)
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
                        .distinct()
                        .order_by(self.sort(self.sort_key))
                        .skip(self.offset)
                        .limit(self.count)
                        .run(conn)
                    )

                    pkg_count = (
                        base
                        .pluck(self.CurrentAppsKeys.RvSeverity, self.CurrentAppsKeys.Name)
                        .distinct()
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
                    ).invalid_global_status(pkg_status)
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


class RetrieveCustomApps(RetrieveApps):
    """
        This class is used to get agent data from within the Packages Page
    """
    def __init__(self, username, customer_name,
                 uri=None, method=None, count=30,
                 offset=0, sort='asc', sort_key=CustomAppsKeys.Name,
                 show_hidden=CommonKeys.NO):

        self.count = count
        self.offset = offset
        self.customer_name = customer_name
        self.username = username
        self.uri = uri
        self.method = method

        self.set_global_properties(
            AppCollections.CustomApps, CustomAppsIndexes, 
            AppCollections.CustomAppsPerAgent,
            CustomAppsKeys, CustomAppsPerAgentKeys,
            CustomAppsPerAgentIndexes
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

class RetrieveSupportedApps(RetrieveApps):
    """
        This class is used to get agent data from within the Packages Page
    """
    def __init__(self, username, customer_name,
                 uri=None, method=None, count=30,
                 offset=0, sort='asc',
                 sort_key=SupportedAppsKeys.Name,
                 show_hidden=CommonKeys.NO):

        self.count = count
        self.offset = offset
        self.customer_name = customer_name
        self.username = username
        self.uri = uri
        self.method = method

        self.set_global_properties(
            AppCollections.SupportedApps, SupportedAppsIndexes, 
            AppCollections.SupportedAppsPerAgent,
            SupportedAppsKeys, SupportedAppsPerAgentKeys,
            SupportedAppsPerAgentIndexes
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

class RetrieveAgentApps(RetrieveApps):
    """
        This class is used to get agent data from within the Packages Page
    """
    def __init__(self, username, customer_name,
                 uri=None, method=None, count=30,
                 offset=0, sort='asc',
                 sort_key=AgentAppsKeys.Name,
                 show_hidden=CommonKeys.NO):

        self.count = count
        self.offset = offset
        self.customer_name = customer_name
        self.username = username
        self.uri = uri
        self.method = method

        self.set_global_properties(
            AppCollections.vFenseApps, AgentAppsIndexes, 
            AppCollections.vFenseAppsPerAgent, 
            AgentAppsKeys, AgentAppsPerAgentKeys,
            AgentAppsPerAgentIndexes
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

