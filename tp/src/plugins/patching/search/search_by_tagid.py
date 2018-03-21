import logging
import logging.config
from vFense import VFENSE_LOGGING_CONFIG

from vFense.db.client import db_create_close, r
from vFense.plugins.patching import *
from vFense.core._constants import CommonKeys
from vFense.plugins.patching._constants import CommonAppKeys, CommonSeverityKeys
from vFense.core.agent import *
from vFense.core.tag import *
from vFense.core.tag.tagManager import tag_exists
from vFense.errorz.error_messages import GenericResults, PackageResults

logging.config.fileConfig(VFENSE_LOGGING_CONFIG)
logger = logging.getLogger('rvapi')

class RetrieveAppsByTagId(object):
    """
        This class is used to get tag data from within the Packages Page
    """
    def __init__(self, username, customer_name,
                 tag_id, uri=None, method=None,
                 count=30, offset=0, sort='asc',
                 sort_key=AppsKeys.Name,
                 show_hidden=CommonKeys.NO):
        """
        """
        self.count = count
        self.offset = offset
        self.customer_name = customer_name
        self.username = username
        self.uri = uri
        self.method = method
        self.tag_id = tag_id
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
                self.CurrentAppsKeys.Hidden,
                self.CurrentAppsPerAgentKeys.Update,
                self.CurrentAppsPerAgentKeys.Dependencies,
                self.CurrentAppsKeys.ReleaseDate,
                self.CurrentAppsKeys.RebootRequired,
                self.CurrentAppsPerAgentKeys.InstallDate,
                self.CurrentAppsPerAgentKeys.Status,
                self.CurrentAppsKeys.RvSeverity,
                self.CurrentAppsKeys.FilesDownloadStatus,
            ]
        )

        self.map_hash = (
            {
                self.CurrentAppsKeys.AppId: r.row['right'][self.CurrentAppsKeys.AppId],
                self.CurrentAppsKeys.Version: r.row['right'][self.CurrentAppsKeys.Version],
                self.CurrentAppsKeys.Name: r.row['right'][self.CurrentAppsKeys.Name],
                self.CurrentAppsKeys.Hidden: r.row['right'][self.CurrentAppsKeys.Hidden],
                self.CurrentAppsPerAgentKeys.Update: r.row['left']['right'][self.CurrentAppsPerAgentKeys.Update],
                self.CurrentAppsKeys.ReleaseDate: r.row['right'][self.CurrentAppsKeys.ReleaseDate].to_epoch_time(),
                self.CurrentAppsPerAgentKeys.InstallDate: r.row['left']['right'][self.CurrentAppsPerAgentKeys.InstallDate].to_epoch_time(),
                self.CurrentAppsPerAgentKeys.Status: r.row['left']['right'][self.CurrentAppsPerAgentKeys.Status],
                self.CurrentAppsPerAgentKeys.Dependencies: r.row['left']['right'][self.CurrentAppsPerAgentKeys.Dependencies],
                self.CurrentAppsKeys.RvSeverity: r.row['right'][self.CurrentAppsKeys.RvSeverity],
                self.CurrentAppsKeys.RebootRequired: r.row['right'][self.CurrentAppsKeys.RebootRequired],
                self.CurrentAppsKeys.FilesDownloadStatus: r.row['right'][self.CurrentAppsKeys.FilesDownloadStatus],
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
            tag = tag_exists(self.tag_id)
            if tag:
                if pkg_status in CommonAppKeys.ValidPackageStatuses:
                    base = (
                        r
                        .table(TagsPerAgentCollection)
                        .get_all(self.tag_id, index=TagsPerAgentIndexes.TagId)
                        .pluck(TagsPerAgentKeys.AgentId)
                        .eq_join(
                            lambda x: [
                                pkg_status,
                                x[self.CurrentAppsPerAgentKeys.AgentId]
                            ],
                            r.table(self.CurrentAppsPerAgentCollection),
                            index=self.CurrentAppsPerAgentIndexes.StatusAndAgentId
                        )
                        .eq_join(
                            lambda y:
                            y['right'][self.CurrentAppsKeys.AppId],
                            r.table(self.CurrentAppsCollection)
                        )
                        .map(self.map_hash)
                    )
                    if self.show_hidden == CommonKeys.NO:
                        base = base.filter({self.CurrentAppsKeys.Hidden: CommonKeys.NO})

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
                        ).invalid_status(self.tag_id, pkg_status)
                    )

            else:
                return_status = (
                    GenericResults(
                        self.username, self.uri, self.method
                    ).invalid_id(self.tag_id, 'tags')
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
            tag = tag_exists(self.tag_id)
            if tag:
                if pkg_status in CommonAppKeys.ValidPackageStatuses:
                    base = (
                        r
                        .table(TagsPerAgentCollection)
                        .get_all(self.tag_id, index=TagsPerAgentIndexes.TagId)
                        .pluck(TagsPerAgentKeys.AgentId)
                        .eq_join(
                            lambda x: [
                                pkg_status,
                                x[self.CurrentAppsPerAgentKeys.AgentId]
                            ],
                            r.table(self.CurrentAppsPerAgentCollection),
                            index=self.CurrentAppsPerAgentIndexes.StatusAndAgentId
                        )
                        .eq_join(lambda y: y['right'][self.CurrentAppsKeys.AppId], r.table(self.CurrentAppsCollection))
                        .map(self.map_hash)
                    )
                    if self.show_hidden == CommonKeys.NO:
                        base = base.filter({self.CurrentAppsKeys.Hidden: CommonKeys.NO})

                    packages = list(
                        base
                        .filter(lambda z: z[self.CurrentAppsKeys.Name].match("(?i)"+name))
                        .distinct()
                        .order_by(self.sort(self.sort_key))
                        .skip(self.offset)
                        .limit(self.count)
                        .run(conn)
                    )

                    pkg_count = (
                        base
                        .filter(lambda x: x[self.CurrentAppsKeys.Name].match("(?i)"+name))
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
                        ).invalid_status(self.tag_id, pkg_status)
                    )

            else:
                return_status = (
                    GenericResults(
                        self.username, self.uri, self.method
                    ).invalid_id(self.tag_id, 'tags')
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
            tag = tag_exists(self.tag_id)
            if tag:
                base = (
                    r
                    .table(TagsPerAgentCollection)
                    .get_all(self.tag_id, index=TagsPerAgentIndexes.TagId)
                    .pluck(TagsPerAgentKeys.AgentId)
                    .eq_join(
                        self.CurrentAppsPerAgentIndexes.AgentId,
                        r.table(self.CurrentAppsPerAgentCollection),
                        index=self.CurrentAppsPerAgentIndexes.AgentId
                    )
                    .eq_join(lambda y: y['right'][self.CurrentAppsKeys.AppId], r.table(self.CurrentAppsCollection))
                    .map(self.map_hash)
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
                    GenericResults(
                        self.username, self.uri, self.method
                    ).invalid_id(self.tag_id, 'tags')
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
            tag = tag_exists(self.tag_id)
            if tag:
                if pkg_status in CommonAppKeys.ValidPackageStatuses:
                    if sev in CommonSeverityKeys.ValidRvSeverities:
                        base = (
                            r
                            .table(TagsPerAgentCollection)
                            .get_all(self.tag_id, index=TagsPerAgentIndexes.TagId)
                            .pluck(TagsPerAgentKeys.AgentId)
                            .eq_join(
                                lambda x: [
                                    pkg_status,
                                    x[self.CurrentAppsPerAgentKeys.AgentId]
                                ],
                                r.table(self.CurrentAppsPerAgentCollection),
                                index=self.CurrentAppsPerAgentIndexes.StatusAndAgentId
                            )
                            .eq_join(lambda y: y['right'][self.CurrentAppsKeys.AppId], r.table(self.CurrentAppsCollection))
                            .map(self.map_hash)
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
                            .filter(
                                (r.row[self.CurrentAppsKeys.RvSeverity] == sev)
                                &
                                (r.row[self.CurrentAppsKeys.Name].match("(?i)"+name))
                            )
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
                        ).invalid_status(self.tag_id, pkg_status)
                    )

            else:
                return_status = (
                    GenericResults(
                        self.username, self.uri, self.method
                    ).invalid_id(self.tag_id, 'tags')
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
            tag = tag_exists(self.tag_id)
            if tag:
                if sev in CommonSeverityKeys.ValidRvSeverities:
                    base = (
                        r
                        .table(TagsPerAgentCollection)
                        .get_all(self.tag_id, index=TagsPerAgentIndexes.TagId)
                        .pluck(TagsPerAgentKeys.AgentId)
                        .eq_join(
                            self.CurrentAppsPerAgentIndexes.AgentId,
                            r.table(self.CurrentAppsPerAgentCollection),
                            index=self.CurrentAppsPerAgentIndexes.AgentId
                        )
                        .eq_join(lambda y: y['right'][self.CurrentAppsKeys.AppId], r.table(self.CurrentAppsCollection))
                        .map(self.map_hash)
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
                    GenericResults(
                        self.username, self.uri, self.method
                    ).invalid_id(self.tag_id, 'tags')
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
            tag = tag_exists(self.tag_id)
            if tag:
                if sev in CommonSeverityKeys.ValidRvSeverities:
                    base = (
                        r
                        .table(TagsPerAgentCollection)
                        .get_all(self.tag_id, index=TagsPerAgentIndexes.TagId)
                        .pluck(TagsPerAgentKeys.AgentId)
                        .eq_join(
                            self.CurrentAppsPerAgentIndexes.AgentId,
                            r.table(self.CurrentAppsPerAgentCollection),
                            index=self.CurrentAppsPerAgentIndexes.AgentId
                        )
                        .eq_join(lambda y: y['right'][self.CurrentAppsKeys.AppId], r.table(self.CurrentAppsCollection))
                        .map(self.map_hash)
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
                        .filter(
                            (r.row[self.CurrentAppsKeys.RvSeverity] == sev)
                            &
                            (r.row[self.CurrentAppsKeys.Name].match("(?i)"+name))
                        )
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
                    GenericResults(
                        self.username, self.uri, self.method
                    ).invalid_id(self.tag_id, 'agents')
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
            tag = tag_exists(self.tag_id)
            if tag:
                if pkg_status in CommonAppKeys.ValidPackageStatuses:
                    if sev in CommonSeverityKeys.ValidRvSeverities:
                        base = (
                            r
                            .table(TagsPerAgentCollection)
                            .get_all(self.tag_id, index=TagsPerAgentIndexes.TagId)
                            .pluck(TagsPerAgentKeys.AgentId)
                            .eq_join(
                                lambda x: [
                                    pkg_status,
                                    x[self.CurrentAppsPerAgentKeys.AgentId]
                                ],
                                r.table(self.CurrentAppsPerAgentCollection),
                                index=self.CurrentAppsPerAgentIndexes.StatusAndAgentId
                            )
                            .eq_join(lambda y: y['right'][self.CurrentAppsKeys.AppId], r.table(self.CurrentAppsCollection))
                            .map(self.map_hash)
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
                        ).invalid_status(self.tag_id, pkg_status)
                    )

            else:
                return_status = (
                    GenericResults(
                        self.username, self.uri, self.method
                    ).invalid_id(self.tag_id, 'tags')
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


class RetrieveCustomAppsByTagId(RetrieveAppsByTagId):
    """
        This class is used to get tag data from within the Packages Page
    """
    def __init__(self, username, customer_name,
                 tag_id, uri=None, method=None,
                 count=30, offset=0, sort='asc',
                 sort_key=CustomAppsKeys.Name,
                 show_hidden=CommonKeys.NO):
        """
        """
        self.count = count
        self.offset = offset
        self.customer_name = customer_name
        self.username = username
        self.uri = uri
        self.method = method
        self.tag_id = tag_id
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
                self.CurrentAppsPerAgentKeys.Dependencies,
                self.CurrentAppsKeys.ReleaseDate,
                self.CurrentAppsKeys.RebootRequired,
                self.CurrentAppsPerAgentKeys.InstallDate,
                self.CurrentAppsPerAgentKeys.Status,
                self.CurrentAppsKeys.RvSeverity,
                self.CurrentAppsKeys.FilesDownloadStatus,
            ]
        )

        self.map_hash = (
            {
                self.CurrentAppsKeys.AppId: r.row['right'][self.CurrentAppsKeys.AppId],
                self.CurrentAppsKeys.Version: r.row['right'][self.CurrentAppsKeys.Version],
                self.CurrentAppsKeys.Name: r.row['right'][self.CurrentAppsKeys.Name],
                self.CurrentAppsKeys.Hidden: r.row['right'][self.CurrentAppsKeys.Hidden],
                self.CurrentAppsPerAgentKeys.Update: r.row['left']['right'][self.CurrentAppsPerAgentKeys.Update],
                self.CurrentAppsPerAgentKeys.Dependencies: r.row['left']['right'][self.CurrentAppsPerAgentKeys.Dependencies],
                self.CurrentAppsKeys.ReleaseDate: r.row['right'][self.CurrentAppsKeys.ReleaseDate].to_epoch_time(),
                self.CurrentAppsPerAgentKeys.InstallDate: r.row['left']['right'][self.CurrentAppsPerAgentKeys.InstallDate].to_epoch_time(),
                self.CurrentAppsPerAgentKeys.Status: r.row['left']['right'][self.CurrentAppsPerAgentKeys.Status],
                self.CurrentAppsKeys.RvSeverity: r.row['right'][self.CurrentAppsKeys.RvSeverity],
                self.CurrentAppsKeys.RebootRequired: r.row['right'][self.CurrentAppsKeys.RebootRequired],
                self.CurrentAppsKeys.FilesDownloadStatus: r.row['right'][self.CurrentAppsKeys.FilesDownloadStatus],
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


class RetrieveSupportedAppsByTagId(RetrieveAppsByTagId):
    """
        This class is used to get tag data from within the Packages Page
    """
    def __init__(self, username, customer_name,
                 tag_id, uri=None, method=None,
                 count=30, offset=0, sort='asc',
                 sort_key=SupportedAppsKeys.Name,
                 show_hidden=CommonKeys.NO):
        """
        """
        self.count = count
        self.offset = offset
        self.customer_name = customer_name
        self.username = username
        self.uri = uri
        self.method = method
        self.tag_id = tag_id
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
                self.CurrentAppsPerAgentKeys.Dependencies,
                self.CurrentAppsKeys.ReleaseDate,
                self.CurrentAppsKeys.RebootRequired,
                self.CurrentAppsPerAgentKeys.InstallDate,
                self.CurrentAppsPerAgentKeys.Status,
                self.CurrentAppsKeys.RvSeverity,
                self.CurrentAppsKeys.FilesDownloadStatus,
            ]
        )

        self.map_hash = (
            {
                self.CurrentAppsKeys.AppId: r.row['right'][self.CurrentAppsKeys.AppId],
                self.CurrentAppsKeys.Version: r.row['right'][self.CurrentAppsKeys.Version],
                self.CurrentAppsKeys.Name: r.row['right'][self.CurrentAppsKeys.Name],
                self.CurrentAppsKeys.Hidden: r.row['right'][self.CurrentAppsKeys.Hidden],
                self.CurrentAppsPerAgentKeys.Update: r.row['left']['right'][self.CurrentAppsPerAgentKeys.Update],
                self.CurrentAppsPerAgentKeys.Dependencies: r.row['left']['right'][self.CurrentAppsPerAgentKeys.Dependencies],
                self.CurrentAppsKeys.ReleaseDate: r.row['right'][self.CurrentAppsKeys.ReleaseDate].to_epoch_time(),
                self.CurrentAppsPerAgentKeys.InstallDate: r.row['left']['right'][self.CurrentAppsPerAgentKeys.InstallDate].to_epoch_time(),
                self.CurrentAppsPerAgentKeys.Status: r.row['left']['right'][self.CurrentAppsPerAgentKeys.Status],
                self.CurrentAppsKeys.RvSeverity: r.row['right'][self.CurrentAppsKeys.RvSeverity],
                self.CurrentAppsKeys.RebootRequired: r.row['right'][self.CurrentAppsKeys.RebootRequired],
                self.CurrentAppsKeys.FilesDownloadStatus: r.row['right'][self.CurrentAppsKeys.FilesDownloadStatus],
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


class RetrieveAgentAppsByTagId(RetrieveAppsByTagId):
    """
        This class is used to get tag data from within the Packages Page
    """
    def __init__(self, username, customer_name,
                 tag_id, uri=None, method=None,
                 count=30, offset=0, sort='asc',
                 sort_key=AgentAppsKeys.Name,
                 show_hidden=CommonKeys.NO):
        """
        """
        self.count = count
        self.offset = offset
        self.customer_name = customer_name
        self.username = username
        self.uri = uri
        self.method = method
        self.tag_id = tag_id
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
                self.CurrentAppsPerAgentKeys.Dependencies,
                self.CurrentAppsKeys.ReleaseDate,
                self.CurrentAppsKeys.RebootRequired,
                self.CurrentAppsPerAgentKeys.InstallDate,
                self.CurrentAppsPerAgentKeys.Status,
                self.CurrentAppsKeys.RvSeverity,
                self.CurrentAppsKeys.FilesDownloadStatus,
            ]
        )

        self.map_hash = (
            {
                self.CurrentAppsKeys.AppId: r.row['right'][self.CurrentAppsKeys.AppId],
                self.CurrentAppsKeys.Version: r.row['right'][self.CurrentAppsKeys.Version],
                self.CurrentAppsKeys.Name: r.row['right'][self.CurrentAppsKeys.Name],
                self.CurrentAppsKeys.Hidden: r.row['right'][self.CurrentAppsKeys.Hidden],
                self.CurrentAppsPerAgentKeys.Update: r.row['left']['right'][self.CurrentAppsPerAgentKeys.Update],
                self.CurrentAppsPerAgentKeys.Dependencies: r.row['left']['right'][self.CurrentAppsPerAgentKeys.Dependencies],
                self.CurrentAppsKeys.ReleaseDate: r.row['right'][self.CurrentAppsKeys.ReleaseDate].to_epoch_time(),
                self.CurrentAppsPerAgentKeys.InstallDate: r.row['left']['right'][self.CurrentAppsPerAgentKeys.InstallDate].to_epoch_time(),
                self.CurrentAppsPerAgentKeys.Status: r.row['left']['right'][self.CurrentAppsPerAgentKeys.Status],
                self.CurrentAppsKeys.RvSeverity: r.row['right'][self.CurrentAppsKeys.RvSeverity],
                self.CurrentAppsKeys.RebootRequired: r.row['right'][self.CurrentAppsKeys.RebootRequired],
                self.CurrentAppsKeys.FilesDownloadStatus: r.row['right'][self.CurrentAppsKeys.FilesDownloadStatus],
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

