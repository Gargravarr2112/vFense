"""
Main launching point of the Top Patch Server
"""
import base64
import uuid
import os
import logging
import logging.config
from vFense import (
    VFENSE_LOGGING_CONFIG, VFENSE_TEMPLATE_PATH, VFENSE_SSL_PATH,
    VFENSE_APP_PATH, VFENSE_WWW_PATH
)

import tornado.httpserver
import tornado.ioloop
import tornado.web
import tornado.options

from . import vFense_module_loader

from redis import StrictRedis

from vFense.server.api.reports_api import *

from vFense.db.client import *
from vFense.scheduler.jobManager import start_scheduler
##from server.api.auth_api import LoginHandler, LogoutHandler
from vFense.core.api.agent import *
from vFense.plugins.patching.Api.stats_api import *
from vFense.plugins.patching.Api.notification_handler import *
from vFense.plugins.patching.Api.os_updates_handler import *
from vFense.plugins.patching.Api.agent_updates_handler import *
from vFense.plugins.patching.Api.custom_updates_handler import *
from vFense.plugins.patching.Api.supported_updates_handler import *
from vFense.plugins.mightymouse.api.relay_servers import *
##Vulnerability APIs
from vFense.plugins.vuln.api.vulnerability import *
from vFense.plugins.vuln.api.cve import *

from vFense.plugins.ra.api.status import RDStatusQueue
from vFense.plugins.ra.api.rdsession import RDSession
from vFense.plugins.ra.api.settings import SetPassword
from vFense.server.hierarchy import db as hierarchy_db
from vFense.server.api.tag_api import *
from vFense.server.api.monit_api import *
from vFense.core.api.permission import RetrieveValidPermissionsHandler
from vFense.operations.api.agent_operations import GetTransactionsHandler, \
    AgentOperationsHandler, TagOperationsHandler, OperationHandler

from vFense.scripts.create_indexes import initialize_indexes_and_create_tables

from tornado.options import define, options

define("port", default=9000, help="run on port", type=int)
define("debug", default=True, help="enable debugging features", type=bool)

rq_host = 'localhost'
rq_port = 6379
rq_db = 0

rq_pool = StrictRedis(host=rq_host, port=rq_port, db=rq_db)


class HeaderModule(tornado.web.UIModule):
    def render(self):
        return self.render_string(
            os.path.join(VFENSE_TEMPLATE_PATH, "header.html")
        )


class Application(tornado.web.Application):
    def __init__(self, debug):
        handlers = [

            ##### Notification API
            (r"/api/v1/notifications?", NotificationsHandler),
            (r"/api/v1/notification/([a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[a-f0-9]{4}-[a-f0-9]{12})?", NotificationHandler),
            (r"/api/v1/notifications/get_valid_fields/?",
                GetAllValidFieldsForNotifications),
            (r"/api/v1/permissions?", RetrieveValidPermissionsHandler),

            ##### RA Api
            (r"/api/ra/rd/password/?", SetPassword),
            (r"/api/ra/rd/([^/]+)/?", RDSession),
            (r"/ws/ra/status/?", RDStatusQueue),

            ##### MightyMouse API Handlers
            (r'/api/v1/relay/([A-Za-z0-9:,"_ ]+.*)?', RelayServerHandler),
            (r"/api/v1/relay", RelayServersHandler),

            ##### Os Apps API Handlers
            (r"/api/v1/app/os/([0-9A-Za-z]{64})?", AppIdOsAppsHandler),
            (r"/api/v1/app/os/([0-9A-Za-z]{64})/agents?", GetAgentsByAppIdHandler),
            (r"/api/v1/apps/os", OsAppsHandler),

            ##### Custom Apps API Handlers
            (r"/api/v1/app/custom/([a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[a-f0-9]{4}-[a-f0-9]{12})?", AppIdCustomAppsHandler),
            (r"/api/v1/app/custom/([a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[a-f0-9]{4}-[a-f0-9]{12})/agents?", GetAgentsByCustomAppIdHandler),
            (r"/api/v1/apps/custom?", CustomAppsHandler),

            (r"/api/v1/apps/custom/upload/finalize?", ThirdPartyPackageUploadHandler),
            (r"/api/v1/apps/custom/upload/data?",ThirdPartyUploadHandler),
            (r"/upload/package?",ThirdPartyPackageUploadHandler),
            (r"/api/v1/apps/custom/upload/uuid?", GetThirdPartyUuidHandler),

            ##### Supported Apps API Handlers
            (r"/api/v1/app/supported/([0-9A-Za-z]{64})?", AppIdSupportedAppsHandler),
            (r"/api/v1/app/supported/([0-9A-Za-z]{64})/agents?", GetAgentsBySupportedAppIdHandler),
            (r"/api/v1/apps/supported?", SupportedAppsHandler),

            ##### Agent Apps API Handlers
            (r"/api/v1/app/remediationvault/([0-9A-Za-z]{64})?", AppIdAgentAppsHandler),
            (r"/api/v1/app/remediationvault/([0-9A-Za-z]{64})/agents?", GetAgentsByAgentAppIdHandler),
            (r"/api/v1/apps/remediationvault?", AgentAppsHandler),

            ##### Dashboard API Handlers
            (r"/api/v1/dashboard/graphs/bar/severity?",CustomerSeverityHandler),
            #(r"/api/v1/dashboard/graphs/linear/severity?",PackageSeverityOverTimeHandler),
            (r"/api/v1/dashboard/graphs/bar/stats_by_os?", CustomerStatsByOsHandler),
            (r"/api/v1/dashboard/graphs/column/range/apps/os?", OsAppsOverTimeHandler),
            (r"/api/v1/dashboard/widgets/unique_count?", WidgetHandler),
            (r"/api/v1/dashboard/widgets/top_needed?", TopAppsNeededHandler),
            (r"/api/v1/dashboard/widgets/recently_released?", RecentlyReleasedHandler),

            ##### Operations API Handlers
            (r"/api/v1/operations?", GetTransactionsHandler),
            (r"/api/v1/operation/([a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[a-f0-9]{4}-[a-f0-9]{12})?", OperationHandler),

            ##### Vulnerability API Handlers
            (r'/api/v1/vulnerability/os/([A-Za-z0-9_-]+)?', VulnIdHandler),
            (r'/api/v1/vulnerability/cve/(CVE-[0-9]+-[0-9]+)?', CveIdHandler),

            ##### File system access whitelist
            (r"/css/(.*?)", tornado.web.StaticFileHandler,
                {"path": os.path.join(VFENSE_WWW_PATH, "css")}),
            (r"/font/(.*?)", tornado.web.StaticFileHandler,
                {"path": os.path.join(VFENSE_WWW_PATH, "font")}),
            (r"/img/(.*?)", tornado.web.StaticFileHandler,
                {"path": os.path.join(VFENSE_WWW_PATH, "img")}),
            (r"/js/(.*?)", tornado.web.StaticFileHandler,
                {"path": os.path.join(VFENSE_WWW_PATH, "js")}),
            (r"/packages/*/(.*?)", tornado.web.StaticFileHandler,
                {"path": VFENSE_APP_PATH})
        ]

        core_loader = vFense_module_loader.CoreLoader()
        plugin_loader = vFense_module_loader.PluginsLoader()

        # TODO: check for colliding regex's from plugins
        handlers.extend(core_loader.get_core_web_api_handlers())
        handlers.extend(plugin_loader.get_plugins_web_api_handlers())

        settings = {
            "cookie_secret": base64.b64encode(uuid.uuid4().bytes +
                                              uuid.uuid4().bytes),
            "login_url": "/login",
        }
        self.scheduler = start_scheduler()
        initialize_indexes_and_create_tables()
        hierarchy_db.init()

        tornado.web.Application.__init__(self, handlers,
                                         template_path=VFENSE_TEMPLATE_PATH,
                                         debug=debug, **settings)

    def log_request(self, handler):
        logging.config.fileConfig(VFENSE_LOGGING_CONFIG)
        log = logging.getLogger('rvweb')
        log_method = log.debug
        if handler.get_status() <= 299:
            log_method = log.info
        elif handler.get_status() <= 399 and \
                handler.get_status() >= 300:
            log_method = log.warn
        elif handler.get_status() <= 499 and \
                handler.get_status() >= 400:
            log_method = log.error
        elif handler.get_status() <= 599 and \
                handler.get_status() >= 500:
            log_method = log.error
        request_time = 1000.0 * handler.request.request_time()
        real_ip = handler.request.headers.get('X-Real-Ip', None)
        #remote_ip = handler.request.remote_ip
        #uri = handler.request.remote_ip
        forwarded_ip = handler.request.headers.get('X-Forwarded-For', None)
        user_agent = handler.request.headers.get('User-Agent')
        log_message = '%d %s %s, %.2fms' % (handler.get_status(), handler._request_summary(), user_agent, request_time)
        if real_ip:
            log_message = '%d %s %s %s %s, %.2fms' % (handler.get_status(), handler._request_summary(), real_ip, forwarded_ip, user_agent, request_time)
        log_method(log_message)

if __name__ == '__main__':
    tornado.options.parse_command_line()
    https_server = tornado.httpserver.HTTPServer(
        Application(options.debug),
        ssl_options={
            "certfile": os.path.join(VFENSE_SSL_PATH, "server.crt"),
            "keyfile": os.path.join(VFENSE_SSL_PATH, "server.key")
        }
    )
    https_server.listen(options.port)
    tornado.ioloop.IOLoop.instance().start()

