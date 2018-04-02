import json
import logging
import logging.config
from vFense import VFENSE_LOGGING_CONFIG

from vFense.core.api.base import BaseHandler
from vFense.core.decorators import authenticated_request

from vFense.plugins.monit import api

logging.config.fileConfig(VFENSE_LOGGING_CONFIG)
logger = logging.getLogger('rvapi')

ROOT_USER = 'root'


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
