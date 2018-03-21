import logging

import redis
from rq import Connection, Queue

from vFense import VFENSE_LOGGING_CONFIG
from vFense.core.agent import AgentKeys
from vFense.core.agent.agents import get_agent_info
from vFense.plugins.patching import AppCollections
from vFense.plugins.patching.apps.incoming_apps import \
   incoming_applications_from_agent 
from vFense.plugins.patching.apps.custom_apps.custom_apps import \
    add_custom_app_to_agents
from vFense.plugins.patching.apps.supported_apps.syncer import \
    get_all_supported_apps_for_agent


RQ_HOST = 'localhost'
RQ_PORT = 6379
RQ_DB = 0
RQ_POOL = redis.StrictRedis(host=RQ_HOST, port=RQ_PORT, db=RQ_DB)

logging.config.fileConfig(VFENSE_LOGGING_CONFIG)
logger = logging.getLogger('rvapi')


class RvHandOff():

    def __init__(self, username, customer_name, uri, method,
            delete_afterwards=True):

        self.username = username
        self.customer_name = customer_name
        self.uri = uri
        self.method = method
        self.delete_afterwards = delete_afterwards

    def _get_agent_data(self, agent_id):
        #if self.agent_data:
        #    if self.agent_data.get(AgentKeys.AgentId) == agent_id:
        #        return self.agent_data
        #    else:
        #        logger.info(
        #            "Agent id: {0} did not match agent id of set agent data: {0}"
        #            .format(agent_id, self.agent_data)
        #        )

        return get_agent_info(agent_id)

    def _add_custom_apps(self, username, customer_name, uri, method, agent_id):
        rv_q = Queue('incoming_updates', connection=RQ_POOL)
        rv_q.enqueue_call(
            func=add_custom_app_to_agents,
            args=(
                username,
                customer_name,
                uri,
                method,
                None,
                agent_id
            ),
            timeout=3600
        )

    def _add_supported_apps(self, agent_id):
        rv_q = Queue('incoming_updates', connection=RQ_POOL)
        rv_q.enqueue_call(
            func=get_all_supported_apps_for_agent,
            args=(
                agent_id,
            ),
            timeout=3600
        )

    def _add_applications_from_agent(self, username, customer_name, agent_data,
            apps, delete_afterwards, app_collection, apps_per_agent_collection):

        rv_q = Queue('incoming_updates', connection=RQ_POOL)
        rv_q.enqueue_call(
            func=incoming_applications_from_agent,
            args=(
                username,
                customer_name,
                agent_data[AgentKeys.AgentId],
                agent_data[AgentKeys.OsCode],
                agent_data[AgentKeys.OsString],
                apps,
                delete_afterwards,
                app_collection,
                apps_per_agent_collection
            ),
            timeout=3600
        )

    def new_agent_operation(self, agent_id, apps_data, agent_data=None):

        if not agent_data:
            agent_data = self._get_agent_data(agent_id)

        self._add_applications_from_agent(
            self.username,
            self.customer_name,
            agent_data,
            apps_data,
            self.delete_afterwards,
            AppCollections.UniqueApplications,
            AppCollections.AppsPerAgent
        )
        self._add_custom_apps(
            self.username,
            self.customer_name,
            self.uri,
            self.method,
            agent_id
        )

        self._add_supported_apps(agent_id)

    def startup_operation(self, agent_id, apps_data, agent_data=None):

        if not agent_data:
            agent_data = self._get_agent_data(agent_id)

        self.refresh_apps_operation(agent_id, apps_data, agent_data)

    def refresh_apps_operation(self, agent_id, apps_data, agent_data=None):

        if not agent_data:
            agent_data = self._get_agent_data(agent_id)

        self._add_applications_from_agent(
            self.username,
            self.customer_name,
            agent_data,
            apps_data,
            self.delete_afterwards,
            AppCollections.UniqueApplications,
            AppCollections.AppsPerAgent
        )
        self._add_supported_apps(agent_id)

    def available_agent_update_operation(self, agent_id, app_data):
        agent_data = self._get_agent_data(agent_id)

        apps_data = [app_data]
        self._add_applications_from_agent(
            self.username,
            self.customer_name,
            agent_data,
            apps_data,
            self.delete_afterwards,
            AppCollections.vFenseApps,
            AppCollections.vFenseAppsPerAgent
        )
