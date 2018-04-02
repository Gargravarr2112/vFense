import os
import sys
import importlib
import inspect
import traceback

from vFense.receiver.api.core.newagent import NewAgentV1
from vFense.receiver.api.core.checkin import CheckInV1
from vFense.receiver.api.core.startup import StartUpV1
from vFense.receiver.api.core.result_uris import ResultURIs
from vFense.receiver.api.core.results import RebootResultsV1, ShutdownResultsV1

from vFense.core.api.base import RootHandler, RvlLoginHandler, RvlLogoutHandler
from vFense.core.api.user import UserHandler, UsersHandler
from vFense.core.api.group import GroupHandler, GroupsHandler
from vFense.core.api.customer import CustomerHandler, CustomersHandler
from vFense.core.api.agent import AgentHandler, AgentResultURIs, \
    AgentsHandler, FetchSupportedOperatingSystems, FetchValidProductionLevels
from vFense.core.api.base import RootHandler, LoginHandler, LogoutHandler, \
    WebSocketHandler, AdminHandler

from vFense.server.api.tag_api import TagsAgentHandler, TagHandler, TagsHandler
from vFense.server.api.email_api import CreateEmailConfigHandler, \
    GetEmailConfigHandler
from vFense.server.api.log_api import LoggingModifyerHandler, \
    LoggingListerHandler
from vFense.server.api.reports_api import (AgentsOsDetailsHandler,
    AgentsHardwareDetailsHandler, AgentsCPUDetailsHandler,
    AgentsMemoryDetailsHandler, AgentsDiskDetailsHandler,
    AgentsNetworkDetailsHandler)
from vFense.server.api.scheduler_api import (ScheduleListerHandler,
    ScheduleAppDetailHandler, SchedulerDateBasedJobHandler,
    SchedulerDailyRecurrentJobHandler, SchedulerMonthlyRecurrentJobHandler,
    SchedulerYearlyRecurrentJobHandler, SchedulerWeeklyRecurrentJobHandler,
    SchedulerCustomRecurrentJobHandler)

from vFense.plugins.patching.Api.os_updates_handler import \
    AgentIdOsAppsHandler, TagIdOsAppsHandler
from vFense.plugins.patching.Api.agent_updates_handler import \
    AgentIdAgentAppsHandler, TagIdAgentAppsHandler
from vFense.plugins.patching.Api.supported_updates_handler import \
    AgentIdSupportedAppsHandler, TagIdSupportedAppsHandler
from vFense.plugins.patching.Api.custom_updates_handler import \
    AgentIdCustomAppsHandler, TagIdCustomAppsHandler
from vFense.plugins.patching.Api.stats_api import (AgentSeverityHandler,
    AgentOsAppsOverTimeHandler, TagSeverityHandler, TagOsAppsOverTimeHandler,
    TagStatsByOsHandler)

from vFense.operations.api.agent_operations import (GetTransactionsHandler,
    AgentOperationsHandler, TagOperationsHandler, OperationHandler,
    TagOperationsHandler)


class CoreLoader():

    def get_core_listener_api_handlers(self):
        handlers = [

            #Login and Logout Operations
            (r"/rvl/?", RootHandler),
            (r"/rvl/login/?", RvlLoginHandler),
            (r"/rvl/logout/?", RvlLogoutHandler),

            #Operations for the New Core Plugin
            (r"/rvl/v1/core/newagent/?", NewAgentV1),
            (r"/rvl/v1/([a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[a-f0-9]{4}-[a-f0-9]{12})/core/startup/?",
                StartUpV1),
            (r"/rvl/v1/([a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[a-f0-9]{4}-[a-f0-9]{12})/core/uris/response/?",
                ResultURIs),
            (r"/rvl/v1/([a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[a-f0-9]{4}-[a-f0-9]{12})/core/checkin/?",
                CheckInV1),
            (r"/rvl/v1/([a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[a-f0-9]{4}-[a-f0-9]{12})/core/results/reboot/?",
                RebootResultsV1),
            (r"/rvl/v1/([a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[a-f0-9]{4}-[a-f0-9]{12})/core/results/shutdown/?",
                ShutdownResultsV1)
        ]

        return handlers

    def get_core_web_api_handlers(self):
        handlers = [

            (r"/?", RootHandler),
            (r"/login/?", LoginHandler),
            (r"/logout/?", LogoutHandler),
            (r"/ws/?", WebSocketHandler),
            (r"/adminForm", AdminHandler),

            ##### New User API
            (r"/api/v1/user/([a-zA-Z0-9_ ]+)?", UserHandler),
            (r"/api/v1/users?", UsersHandler),

            ##### New Group API
            (r"/api/v1/group/([a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[a-f0-9]{4}-[a-f0-9]{12})?", GroupHandler),
            (r"/api/v1/groups?", GroupsHandler),

            ##### New Customer API
            (r'/api/v1/customer/((?:\w(?!%20+")|%20(?!%20*")){1,36})?', CustomerHandler),
            (r"/api/v1/customers?", CustomersHandler),

            ##### Email API Handlers
            (r"/api/email/config/create?", CreateEmailConfigHandler),
            (r"/api/email/config/list?", GetEmailConfigHandler),

            ##### Logger API Handlers
            (r"/api/logger/modifyLogging?", LoggingModifyerHandler),
            (r"/api/logger/getParams?", LoggingListerHandler),

            ##### Reports Api
            (r"/api/v1/reports/osdetails?", AgentsOsDetailsHandler),
            (r"/api/v1/reports/hardwaredetails?",AgentsHardwareDetailsHandler),
            (r"/api/v1/reports/cpudetails?",AgentsCPUDetailsHandler),
            (r"/api/v1/reports/memorydetails?",AgentsMemoryDetailsHandler),
            (r"/api/v1/reports/diskdetails?",AgentsDiskDetailsHandler),
            (r"/api/v1/reports/networkdetails?",AgentsNetworkDetailsHandler),

            ##### Scheduler API Handlers
            (r"/api/v1/schedules?", ScheduleListerHandler),
            (r"/api/v1/schedule/([A-Za-z0-9_ ]+.*)?", ScheduleAppDetailHandler),
            (r"/api/v1/schedules/recurrent/none?", SchedulerDateBasedJobHandler),
            (r"/api/v1/schedules/recurrent/daily?", SchedulerDailyRecurrentJobHandler),
            (r"/api/v1/schedules/recurrent/monthly?", SchedulerMonthlyRecurrentJobHandler),
            (r"/api/v1/schedules/recurrent/yearly?", SchedulerYearlyRecurrentJobHandler),
            (r"/api/v1/schedules/recurrent/weekly?", SchedulerWeeklyRecurrentJobHandler),
            (r"/api/v1/schedules/recurrent/custom?", SchedulerCustomRecurrentJobHandler),

            ##### Agent API Handlers
            (r"/api/v1/agent/([a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[a-f0-9]{4}-[a-f0-9]{12})?", AgentHandler),
            (r"/api/v1/agent/([a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[a-f0-9]{4}-[a-f0-9]{12})/graphs/bar/severity?",AgentSeverityHandler),
            (r"/api/v1/agent/([a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[a-f0-9]{4}-[a-f0-9]{12})/graphs/column/range/apps/os?", AgentOsAppsOverTimeHandler),
            (r"/api/v1/agent/([a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[a-f0-9]{4}-[a-f0-9]{12})/tag?", TagsAgentHandler),
            (r"/api/v1/agent/([a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[a-f0-9]{4}-[a-f0-9]{12})/apps/os?", AgentIdOsAppsHandler),
            (r"/api/v1/agent/([a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[a-f0-9]{4}-[a-f0-9]{12})/apps/agentupdates?", AgentIdAgentAppsHandler),
            (r"/api/v1/agent/([a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[a-f0-9]{4}-[a-f0-9]{12})/apps/custom?", AgentIdCustomAppsHandler),
            (r"/api/v1/agent/([a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[a-f0-9]{4}-[a-f0-9]{12})/apps/supported?", AgentIdSupportedAppsHandler),
            (r"/api/v1/agent/([a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[a-f0-9]{4}-[a-f0-9]{12})/operations?", AgentOperationsHandler),
            (r"/api/v1/agent/([a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[a-f0-9]{4}-[a-f0-9]{12})/uris/response?", AgentResultURIs),

            ##### Agents API Handlers
            (r"/api/v1/agents", AgentsHandler),

            ##### Tag API Handlers
            (r"/api/v1/tag/([a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[a-f0-9]{4}-[a-f0-9]{12})?", TagHandler),
            (r"/api/v1/tag/([a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[a-f0-9]{4}-[a-f0-9]{12})/graphs/bar/severity?",TagSeverityHandler),
            (r"/api/v1/tag/([a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[a-f0-9]{4}-[a-f0-9]{12})/graphs/column/range/apps/os?", TagOsAppsOverTimeHandler),
            #(r"/api/v1/tag/([a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[a-f0-9]{4}-[a-f0-9]{12})/graphs/linear/severity?",TagPackageSeverityOverTimeHandler),
            (r"/api/v1/tag/([a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[a-f0-9]{4}-[a-f0-9]{12})/apps/os?", TagIdOsAppsHandler),
            (r"/api/v1/tag/([a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[a-f0-9]{4}-[a-f0-9]{12})/apps/agentupdates?", TagIdAgentAppsHandler),
            (r"/api/v1/tag/([a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[a-f0-9]{4}-[a-f0-9]{12})/apps/supported?", TagIdSupportedAppsHandler),
            (r"/api/v1/tag/([a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[a-f0-9]{4}-[a-f0-9]{12})/apps/custom?", TagIdCustomAppsHandler),
            (r"/api/v1/tag/([a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[a-f0-9]{4}-[a-f0-9]{12})/operations?", TagOperationsHandler),
            (r"/api/v1/tag/([a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[a-f0-9]{4}-[a-f0-9]{12})/stats_by_os?", TagStatsByOsHandler),

            ##### Tags API Handlers
            (r"/api/v1/tags", TagsHandler),

            ##### Generic API Handlers
            (r"/api/v1/supported/operating_systems?", FetchSupportedOperatingSystems),
            (r"/api/v1/supported/production_levels?", FetchValidProductionLevels),
            #(r"/api/package/getDependecies?", GetDependenciesHandler),

        ]

        return handlers


class PluginsLoader():
    """Used to retrieve the listener and web api's from every plugin."""

    def __init__(self):
        """Append the plugins directory to sys path."""
        self.curr_dir = os.path.dirname(os.path.realpath(__file__)) 
        self.plugins_dir = 'plugins'
        self.plugins_path = os.path.join(self.curr_dir, self.plugins_dir)

        sys.path.append(self.plugins_path)

    def _get_all_plugins(self):
        """Search through the plugins directory and find all directories
        with an __init__.py file. These directories will be considered
        plugins.
        
        Basic usage:
            >>> from vFense_module_loader import PluginsLoader
            >>> loader = PluginsLoader()
            >>> plugins = loader._get_all_plugins()
            >>> print plugins
            >>> ['plugins.patching', 'plugins.monit', ...]

        Returns:
            (list str) - A list of modules as strings corresponding to found
                plugins.

                Ex: ['plugins.patching', 'plugins.monit', ...]
        """
        plugins = []

        for entry in os.listdir(self.plugins_path):
            entry_path = os.path.join(self.plugins_path, entry)
            init_path = os.path.join(entry_path, '__init__.py')

            if os.path.isdir(entry_path) and os.path.exists(init_path):
                module = os.path.join(
                    self.plugins_dir, entry
                ).replace('/', '.')

                plugins.append(module)

        return plugins

    def _import_all_plugins(self, plugins):
        """Imports the modules given.

        Args:
            plugins (list): A list of modules as strings corresponding to
                plugins.

                Ex: ['plugins.patching', 'plugins.monit', ...]

        Basic usage:
            >>> from vFense_module_loader import PluginsLoader
            >>> loader = PluginsLoader()
            >>> imported = loader._import_all_plugins(plugins)
            >>> print imported
            >>> [<module 'plugins.monit' from 'plugins/monit/__init__.pyc'>]

        Returns:
            (list): A list of loaded modules.

            Ex: [<module 'plugins.monit' from 'plugins/monit/__init__.pyc'>]
        """
        imported_plugins = []

        for module in plugins:
            try:
                imported_plugins.append(importlib.import_module(module))
            except Exception as e:
                print "Failed to import {0} because of: {1}".format(
                    module, e
                )

                continue

        return imported_plugins

    def get_plugins_listener_api_handlers(self):
        """Retrieves the listener handlers from every plugin by calling the
        get_listener_api_handlers function of every plugin found.
        
        Basic usage:
            >>> from vFense_module_loader import PluginsLoader
            >>> loader = PluginsLoader()
            >>> loader.get_plugins_listener_api_handlers()

        Returns:
            (list) - Returns a list of tuples where the first element is
                the regex to be handled and the second element is
                the class that will be used to handle that regex.

            Ex:
                [('/rvl/v1/([a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[a-f0-9]{4}-[a-f0-9]{12})/monitoring/monitordata/?',
                <class 'vFense.plugins.monit.api_handlers.UpdateMonitoringStatsV1'>)]

        """

        plugins = self._get_all_plugins()
        imported_plugins = self._import_all_plugins(plugins)

        handlers = []
        for plugin in imported_plugins:
            try:
                if 'get_listener_api_handlers' in plugin.__dict__.keys():
                    handlers.extend(plugin.get_listener_api_handlers())

            except Exception as e:
                print "Failed to get listener handlers: {0}".format(e)
                print traceback.format_exc()

        return handlers

    def get_plugins_web_api_handlers(self):
        """Retrieves the listener handlers from every plugin by calling the
        get_plugins_web_api_handlers function of every plugin found.
        
        Basic usage:
            >>> from vFense_module_loader import PluginsLoader
            >>> loader = PluginsLoader()
            >>> loader.get_plugins_web_api_handlers()

        Returns:
            (list) - Returns a list of tuples where the first element is
                the regex to be handled and the second element is
                the class that will be used to handle that regex.

            Ex:
                [('/api/monitor/memory/?', <class 'vFense.plugins.monit.api_handlers.GetMemoryStats'>),
                ('/api/monitor/filesystem/?', <class 'vFense.plugins.monit.api_handlers.GetFileSystemStats'>)]

        """
        plugins = self._get_all_plugins()
        imported_plugins = self._import_all_plugins(plugins)

        handlers = []
        for plugin in imported_plugins:
            try:
                if 'get_web_api_handlers' in plugin.__dict__.keys():
                    handlers.extend(plugin.get_web_api_handlers())

            except Exception as e:
                print "Failed to get web handlers: {0}".format(e)
                print traceback.format_exc()

        return handlers
