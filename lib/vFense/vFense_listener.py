"""
Main launching point of the Top Patch Server
"""
import base64
import uuid
import os
import logging
import logging.config
from vFense import (
    VFENSE_LOGGING_CONFIG, VFENSE_SSL_PATH, VFENSE_TEMPLATE_PATH
)

import tornado.httpserver
import tornado.ioloop
import tornado.web
import tornado.options

import vFense_module_loader

from vFense.core.api.base import WebSocketHandler, AdminHandler
from vFense.receiver.api.rv.results import InstallOsAppsResults, \
    InstallCustomAppsResults, InstallSupportedAppsResults, \
    InstallAgentAppsResults, UninstallAppsResults
from vFense.receiver.api.rv.updateapplications import UpdateApplicationsV1
from vFense.receiver.api.rv.agent_update import AgentUpdateHandler
from vFense.receiver.api.ra.results import RemoteDesktopResults

from tornado.options import define, options

define("port", default=9001, help="run on port", type=int)
define("debug", default=True, help="enable debugging features", type=bool)


class Application(tornado.web.Application):
    def __init__(self, debug):
        handlers = [

            #RA plugin
            (r"/rvl/ra/rd/results/?", RemoteDesktopResults),

            #Operations for the New Core Plugin
            (r"/rvl/v1/([a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[a-f0-9]{4}-[a-f0-9]{12})/rv/updatesapplications/?", UpdateApplicationsV1),
            (r"/rvl/v1/([a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[a-f0-9]{4}-[a-f0-9]{12})/rv/available_agent_update/?", AgentUpdateHandler),

            #New Operations for the New RV Plugin
            (r"/rvl/v1/([a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[a-f0-9]{4}-[a-f0-9]{12})/rv/results/install/apps/os?",
                InstallOsAppsResults),
            (r"/rvl/v1/([a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[a-f0-9]{4}-[a-f0-9]{12})/rv/results/install/apps/custom?",
                InstallCustomAppsResults),
            (r"/rvl/v1/([a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[a-f0-9]{4}-[a-f0-9]{12})/rv/results/install/apps/supported?",
                InstallSupportedAppsResults),
            (r"/rvl/v1/([a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[a-f0-9]{4}-[a-f0-9]{12})/rv/results/install/apps/agent?",
                InstallAgentAppsResults),
            (r"/rvl/v1/([a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[a-f0-9]{4}-[a-f0-9]{12})/rv/results/uninstall?",
                UninstallAppsResults),

        ]

        core_loader = vFense_module_loader.CoreLoader()
        plugin_loader = vFense_module_loader.PluginsLoader()

        # TODO: check for colliding regex's from plugins
        handlers.extend(core_loader.get_core_listener_api_handlers())
        handlers.extend(plugin_loader.get_plugins_listener_api_handlers())

        template_path = VFENSE_TEMPLATE_PATH
        settings = {
            "cookie_secret": "patching-0.7",
            "login_url": "/rvl/login",
        }
        tornado.web.Application.__init__(
            self, handlers, template_path=template_path, debug=True, **settings
        )

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
            log_message = (
                '%d %s %s %s %s, %.2fms' %
                (
                    handler.get_status(), handler._request_summary(),
                    real_ip, forwarded_ip, user_agent, request_time
                )
            )
        log_method(log_message)

if __name__ == '__main__':
    tornado.options.parse_command_line()
    https_server = tornado.httpserver.HTTPServer(
        Application(options.debug),
        ssl_options={
            "certfile": os.path.join(
                VFENSE_SSL_PATH,
                "server.crt"),
            "keyfile": os.path.join(
                VFENSE_SSL_PATH, 
                "server.key"),
        }
    )
    https_server.listen(options.port)
    tornado.ioloop.IOLoop.instance().start()
