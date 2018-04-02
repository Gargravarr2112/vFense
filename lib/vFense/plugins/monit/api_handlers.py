import json
import logging

from vFense import VFENSE_LOGGING_CONFIG

from vFense.core.api.base import BaseHandler
from vFense.core.decorators import authenticated_request
from vFense.errorz.error_messages import GenericResults
from vFense.core.decorators import agent_authenticated_request, \
    convert_json_to_arguments

from vFense.plugins.monit import api
from vFense.plugins.monit.utils import update_agent_monit_stats

logging.config.fileConfig(VFENSE_LOGGING_CONFIG)
list_log = logging.getLogger('rvlistener')
web_log = logging.getLogger('rvlistener')


class UpdateMonitoringStatsV1(BaseHandler):

    @agent_authenticated_request
    @convert_json_to_arguments
    def post(self, agent_id):
        username = self.get_current_user()
        uri = self.request.uri
        method = self.request.method

        try:
            data = self.arguments.get('data')
            mem = data['memory']
            cpu = data['cpu']
            file_system = data['file_system']

            update_agent_monit_stats(
                agent=agent_id,
                memory=mem,
                cpu=cpu,
                file_system=file_system
            )
            results = (
                GenericResults(
                    username, uri, method
                ).object_updated(agent_id, 'monitoring data')
            )
            self.set_status(results['http_status'])
            self.set_header('Content-Type', 'application/json')
            self.write(json.dumps(results, indent=4))

        except Exception as e:
            results = (
                GenericResults(
                    username, uri, method
                ).something_broke(agent_id, 'monitoring data', e)
            )
            list_log.exception(results)

            self.set_status(results['http_status'])
            self.set_header('Content-Type', 'application/json')
            self.write(json.dumps(results, indent=4))


class GetMemoryStats(BaseHandler):

    @authenticated_request
    def get(self):
        self.set_header('Content-Type', 'application/json')

        agent_id = self.get_argument('agent_id', None)
        result = api.get_agent_memory_latest(agent_id)

        self.write(json.dumps(result, indent=4))


class GetFileSystemStats(BaseHandler):

    @authenticated_request
    def get(self):
        self.set_header('Content-Type', 'application/json')

        agent_id = self.get_argument('agent_id', None)
        result = api.get_agent_file_system_latest(agent_id)

        self.write(json.dumps(result, indent=4))


class GetCpuStats(BaseHandler):

    @authenticated_request
    def get(self):
        self.set_header('Content-Type', 'application/json')

        agent_id = self.get_argument('agent_id', None)
        result = api.get_agent_cpu_latest(agent_id)

        self.write(json.dumps(result, indent=4))


class GetAllStats(BaseHandler):

    @authenticated_request
    def get(self):
        self.set_header('Content-Type', 'application/json')

        agent_id = self.get_argument('agent_id', None)
        result = api.get_agent_latest(agent_id)

        self.write(json.dumps(result, indent=4))
