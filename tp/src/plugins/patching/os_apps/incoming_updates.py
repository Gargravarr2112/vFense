import logging
import logging.config
from hashlib import sha256

from vFense.db.client import r
from vFense.errorz.status_codes import PackageCodes
from vFense.plugins.patching import AppsKey, AppsPerAgentKey
from vFense.core._db_constants import DbTime
from vFense.plugins.patching.patching import add_or_update_apps_per_agent, \
    unique_application_updater

from vFense.plugins.patching.downloader.downloader import download_all_files_in_app
import re

import redis
from rq import Connection, Queue

rq_host = 'localhost'
rq_port = 6379
rq_db = 0

logging.config.fileConfig('/opt/TopPatch/conf/logging.config')
logger = logging.getLogger('rvapi')

rq_pkg_pool = redis.StrictRedis(host=rq_host, port=rq_port, db=rq_db)


class IncomingApplicationsFromAgent():

    def __init__(self, username, agent_id, customer_name,
                 os_code, os_string):
        self.username = username
        self.agent_id = agent_id
        self.customer_name = customer_name
        self.os_code = os_code
        self.os_string = os_string
        self.inserted_count = 0
        self.updated_count = 0
        self.modified_time = DbTime.time_now()

    def add_or_update_packages(self, app_list, delete_afterwards=True):
        rv_q = Queue('downloader', connection=rq_pkg_pool)
        index_with_no_name = list()
        good_app_list = list()
        #start_time = datetime.now()
        #print start_time, 'add all apps to app_table'
        for i in range(len(app_list)):
            if not app_list[i][AppsKey.Name]:
                index_with_no_name.append(i)
                continue

            if len(app_list[i][AppsKey.Name]) < 1:
                index_with_no_name.append(i)
                continue

            app_list[i] = self.set_app_per_node_parameters(app_list[i])
            app_list[i][AppsKey.AppId] = self.build_app_id(app_list[i])
            agent_app = self.set_specific_keys_for_app_agent(app_list[i])
            file_data = app_list[i].get(AppsKey.FileData)
            counts = (
                unique_application_updater(
                    self.customer_name, app_list[i], self.os_string
                )
            )
            self.inserted_count += counts[0]
            self.updated_count += counts[1]

            if agent_app[AppsPerAgentKey.Status] == 'available':
                rv_q.enqueue_call(
                    func=download_all_files_in_app,
                    args=(
                        app_list[i][AppsKey.AppId],
                        self.os_code, self.os_string,
                        file_data,
                    ),
                    timeout=86400
                )
            good_app_list.append(agent_app)

        inserted, updated, deleted = (
            add_or_update_apps_per_agent(
                self.agent_id, good_app_list,
                self.modified_time, delete_afterwards
            )
        )
        #end_time = datetime.now()
        #print end_time, 'finished adding  all apps to app_table'
        #print 'total time took %s' % (str(end_time - start_time))
        print (("Added or updated apps per agent: "
               "inserted: {0}, updated: {1}, deleted: {2}")
               .format(inserted, updated, deleted))

        #logger.info(msg)

    def set_specific_keys_for_app_agent(self, app):
        only_these_keys_are_needed = (
            {
                AppsPerAgentKey.AppId: app[AppsPerAgentKey.AppId],
                AppsPerAgentKey.AgentId: app[AppsPerAgentKey.AgentId],
                AppsPerAgentKey.InstallDate: app.pop(AppsPerAgentKey.InstallDate),
                AppsPerAgentKey.AgentId: self.agent_id,
                AppsPerAgentKey.CustomerName: self.customer_name,
                AppsPerAgentKey.Status: app[AppsPerAgentKey.Status],
                AppsPerAgentKey.Dependencies: app.pop(AppsPerAgentKey.Dependencies),
                AppsPerAgentKey.Update: PackageCodes.ThisIsAnUpdate,
                AppsPerAgentKey.LastModifiedTime: self.modified_time,
                AppsPerAgentKey.Id: self.build_agent_app_id(
                    app[AppsPerAgentKey.AppId])
            }
        )

        return(only_these_keys_are_needed)

    def set_app_per_node_parameters(self, app):
        app[AppsPerAgentKey.AgentId] = self.agent_id
        app[AppsKey.OsCode] = self.os_code
        app[AppsKey.RvSeverity] = (
            self.sev_generator(
                app[AppsKey.VendorSeverity]
            )
        )

        app[AppsKey.ReleaseDate] = (
            r.epoch_time(app[AppsKey.ReleaseDate])
        )

        app[AppsPerAgentKey.InstallDate] = (
            r.epoch_time(app[AppsPerAgentKey.InstallDate])
        )

        return(app)

    def build_app_id(self, app):
        app_id = '%s%s' % \
            (app['name'], app['version'])
        app_id = app_id.encode('utf-8')

        return (sha256(app_id).hexdigest())

    def build_agent_app_id(self, appid):
        agent_app_id = self.agent_id.encode('utf8') + appid.encode('utf8')

        return (sha256(agent_app_id).hexdigest())

    def sev_generator(self, sev):

        tp_sev = ''
        if re.search(r'Critical|Important|Security', sev, re.IGNORECASE):
            tp_sev = 'Critical'

        elif re.search(r'Recommended|Moderate|Low|Bugfix', sev, re.IGNORECASE):
            tp_sev = 'Recommended'

        else:
            tp_sev = 'Optional'

        return (tp_sev)


def incoming_packages_from_agent(username, agent_id, customer_name,
                                 os_code, os_string, apps,
                                 delete_afterwards=True):

        app = (
            IncomingApplicationsFromAgent(
                username, agent_id, customer_name, os_code, os_string
            )
        )
        app.add_or_update_packages(apps, delete_afterwards)
