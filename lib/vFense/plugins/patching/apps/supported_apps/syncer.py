import os
import logging
import requests

from time import mktime
from datetime import datetime

from vFense import VFENSE_LOGGING_CONFIG
from vFense.core._db import delete_all_in_table
from vFense.core.agent import *
from vFense.core.agent.agents import get_agents_info, get_agent_info 

from vFense.errorz.status_codes import PackageCodes

from vFense.plugins.patching import *
from vFense.plugins.patching._constants import CommonAppKeys
from vFense.plugins.patching._db import fetch_apps_data_by_os_code, \
    insert_app_data
from vFense.plugins.patching.utils import build_agent_app_id
from vFense.plugins.patching.file_data import add_file_data
from vFense.plugins.patching.downloader.downloader import \
    download_all_files_in_app

from vFense.db.client import db_connect, r, db_create_close
from vFense.server.hierarchy import Collection, CustomerKeys

import redis
from rq import Queue

RQ_HOST = 'localhost'
RQ_PORT = 6379
RQ_DB = 0
RQ_PKG_POOL = redis.StrictRedis(host=RQ_HOST, port=RQ_PORT, db=RQ_DB)

BASE_URL = 'http://updater2.toppatch.com'
#GET_AGENT_UPDATES = 'api/new_updater/rvpkglist'
GET_SUPPORTED_UPDATES = 'api/new_updater/pkglist'

logging.config.fileConfig(VFENSE_LOGGING_CONFIG)
logger = logging.getLogger('rvapi')


class IncomingSupportedApps(object):

    def __init__(self):
        last_modified_time = mktime(datetime.now().timetuple())
        self.last_modified_time = r.epoch_time(last_modified_time)

        # Search caching
        self.previous_os_code_search = None
        self.previous_agent_list = None

    def sync_supported_updates_to_all_agents(self, apps):
        try:
            conn = db_connect()
            deleted_count = 0
            (
                r
                .table(AppCollections.SupportedAppsPerAgent)
                .delete()
                .run(conn)
            )
            conn.close()
            self.update_agents_with_supported(apps)

        except Exception as e:
            logger.exception(e)

    def _delete_old_supported_apps_from_agent(self, agent_id, conn):
        (
            r
            .table(AppCollections.SupportedAppsPerAgent)
            .get_all(
                agent_id,
                index=SupportedAppsPerAgentIndexes.AgentId
            )
            .delete()
            .run(conn)
       )

    def _get_list_of_agents_by_os_code(self, os_code):
        if not self.previous_os_code_search == os_code:
            self.previous_os_code_search = os_code
            self.previous_agent_list = get_agents_info(agent_os=os_code)

        return self.previous_agent_list

    def update_agents_with_supported(self, apps, agents=None):
        if agents is None:
            agents = []

        try:
            conn = db_connect()
            for agent in agents:
                self._delete_old_supported_apps_from_agent(
                    agent[SupportedAppsPerAgentKeys.AgentId], conn
                )

            for app in apps:
                if not agents:
                    agents = self._get_list_of_agents_by_os_code(
                        app[AgentKeys.OsCode]
                    )

                app_id = app.get(SupportedAppsKeys.AppId)
                file_data = app.get(SupportedAppsKeys.FileData)

                for agent in agents:
                    if agent[AgentKeys.OsCode] == app[SupportedAppsKeys.OsCode]:
                        agent_id = agent[SupportedAppsPerAgentKeys.AgentId]

                        add_file_data(app_id, file_data, agent_id)

                        app_per_agent_props = \
                            self._set_app_per_agent_properties(agent, app_id)

                        agent_has_app = self.check_if_agent_has_app(
                            agent_id, app_id
                        )

                        if not agent_has_app:
                            self.insert_app(app_per_agent_props)

                        elif agent_has_app:
                            app_per_agent_props[
                                SupportedAppsPerAgentKeys.Status
                            ] = CommonAppKeys.INSTALLED

                            self.insert_app(app_per_agent_props)

            conn.close()

        except Exception as e:
            logger.exception(e)

    @db_create_close
    def insert_app(self, app, conn=None):
        try:
            (
                r
                .table(AppCollections.SupportedAppsPerAgent)
                .insert(app)
                .run(conn)
            )

        except Exception as e:
            logger.exception(e)

    @db_create_close
    def insert_app_and_delete_old(self, app, lower_apps, conn=None):
        try:
            (
                r
                .table(AppCollections.SupportedAppsPerAgent)
                .insert(app)
                .run(conn)
            )
            for lower_app in lower_apps:
                (
                    r
                    .table(AppCollections.AppsPerAgent)
                    .get(lower_app[AppsPerAgentKeys.Id])
                    .delete()
                    .run(conn)
                )
        except Exception as e:
            logger.exception(e)

    def _set_app_per_agent_properties(self, agent, app_id):
        return {
            SupportedAppsPerAgentKeys.AgentId:
                agent[AgentKeys.AgentId],
            SupportedAppsPerAgentKeys.CustomerName:
                agent[AgentKeys.CustomerName],
            SupportedAppsPerAgentKeys.Status:
                CommonAppKeys.AVAILABLE,
            SupportedAppsPerAgentKeys.LastModifiedTime:
                self.last_modified_time,
            SupportedAppsPerAgentKeys.Update:
                PackageCodes.ThisIsAnUpdate,
            SupportedAppsPerAgentKeys.InstallDate:
                r.epoch_time(0.0),
            SupportedAppsPerAgentKeys.AppId:
                app_id,
            SupportedAppsPerAgentKeys.Id:
                build_agent_app_id(
                    agent[SupportedAppsPerAgentKeys.AgentId],
                    app_id
                )
        }

    @db_create_close
    def app_name_exist(self, app_info,conn=None):
        try:
            app_name_exists= list(
                r
                .table(AppCollections.UniqueApplications)
                .get_all(
                    app_info[AppsKeys.Name],
                    index=AppsIndexes.Name
                )
                .run(conn)
                .pluck(
                    SupportedAppsKeys.AppId,
                    SupportedAppsKeys.Name,
                    SupportedAppsKeys.Version,
                    SupportedAppsPerAgentKeys.AgentId
                )
                .run(conn)
            )
        except Exception as e:
            logger.exception(e)
            app_name_exists = None

        return(app_name_exists)

    @db_create_close
    def lower_version_exists_of_app(self, app, app_info,
                                    status=CommonAppKeys.AVAILABLE, conn=None):
        try:
            lower_version_exists = list(
                r
                .table(AppCollections.UniqueApplications)
                .get_all(
                    app_info[AppsKeys.Name],
                    index=AppsIndexes.Name
                )
                .filter(
                    lambda x: x[AppsKeys.Version] < app_info[AppsKeys.Version]
                )
                .eq_join(
                    lambda y:
                    [
                        app[AgentKeys.AgentId],
                        app[AppsPerAgentKeys.AppId],
                    ],
                    r.table(AppCollections.AppsPerAgent),
                    index=AppsPerAgentIndexes.AgentId
                )
                .zip()
                .filter(
                    {
                        AppsPerAgentKeys.Status: status
                    }
                )
                .pluck(
                    AppsKeys.AppId,
                    AppsPerAgentKeys.Id,
                    AppsKeys.Name,
                    AppsPerAgentKeys.AgentId
                )
                .run(conn)
            )

        except Exception as e:
            logger.exception(e)

        return(lower_version_exists)

    @db_create_close
    def check_if_agent_has_app(self, agent_id, app_id, conn=None):
        try:
            agent_has_app = list(
                r
                .table(AppCollections.AppsPerAgent)
                .get_all(
                    [
                        agent_id,
                        app_id
                    ],
                    index=AppsPerAgentIndexes.AgentIdAndAppId
                )
                .run(conn)
            )

        except Exception as e:
            logger.exception(e)

        return(agent_has_app)


def update_supported_apps(json_data):

    try:
        rv_q = Queue('downloader', connection=RQ_PKG_POOL)
        conn = db_connect()

        inserted_count = 0
        all_customers = list(
            r
            .table(Collection.Customers)
            .map(lambda x: x[CustomerKeys.CustomerName])
            .run(conn)
        )

        for i in range(len(json_data)):
            json_data[i][SupportedAppsKeys.Customers] = all_customers
            json_data[i][SupportedAppsKeys.ReleaseDate] = \
                r.epoch_time(json_data[i][SupportedAppsKeys.ReleaseDate])
            json_data[i][SupportedAppsKeys.FilesDownloadStatus] = \
                PackageCodes.FilePendingDownload
            json_data[i][SupportedAppsKeys.Hidden] = 'no'
            json_data[i][SupportedAppsKeys.VulnerabilityId] = ''

            insert_app_data(
                json_data[i], DownloadCollections.LatestDownloadedSupported
            )
            file_data = json_data[i].get(SupportedAppsKeys.FileData)
            add_file_data(json_data[i][SupportedAppsKeys.AppId], file_data)
            data_to_update = {
                SupportedAppsKeys.Customers: all_customers
            }
            exists = (
                r
                .table(AppCollections.SupportedApps)
                .get(json_data[i][SupportedAppsKeys.AppId])
                .run(conn)
            )

            if exists:
                updated = (
                    r
                    .table(AppCollections.SupportedApps)
                    .get(json_data[i][SupportedAppsKeys.AppId])
                    .update(data_to_update)
                    .run(conn)
                )

            else:
                updated = (
                    r
                    .table(AppCollections.SupportedApps)
                    .insert(json_data[i])
                    .run(conn)
                )

            rv_q.enqueue_call(
                func=download_all_files_in_app,
                args=(
                    json_data[i][SupportedAppsKeys.AppId],
                    json_data[i][SupportedAppsKeys.OsCode],
                    None,
                    file_data,
                    0,
                    AppCollections.SupportedApps
                ),
                timeout=86400
            )

            inserted_count += updated['inserted']

        conn.close()

        update_apps = IncomingSupportedApps()
        update_apps.sync_supported_updates_to_all_agents(json_data)

    except Exception as e:
        logger.exception(e)


def get_supported_apps():
    delete_all_in_table(
        collection=DownloadCollections.LatestDownloadedSupported
    )
    get_updater_data = requests.get(
        os.path.join(BASE_URL, GET_SUPPORTED_UPDATES)
    )

    if get_updater_data.status_code == 200:
        json_data = get_updater_data.json()
        update_supported_apps(json_data)

    else:
        logger.error(
            'Failed to connect and download packages from TopPatch Updater server'
        )


def get_all_supported_apps_for_agent(agent_id):
    agent = get_agent_info(agent_id)
    apps = fetch_apps_data_by_os_code(
        agent[AgentKeys.OsCode],
        collection=DownloadCollections.LatestDownloadedSupported
    )

    if apps:
        try:
            update_apps = IncomingSupportedApps()
            update_apps.update_agents_with_supported(apps, [agent])
        except Exception as e:
            logger.exception(e)
