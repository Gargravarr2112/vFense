import datetime
import time
import json

from _db import monit_initialization
from vFense.plugins.monit.api_handlers import UpdateMonitoringStatsV1, \
    GetMemoryStats, GetFileSystemStats, GetCpuStats, GetAllStats


def get_listener_api_handlers():
    handlers = [
        (r"/rvl/v1/([a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[a-f0-9]{4}-[a-f0-9]{12})/monitoring/monitordata/?",
         UpdateMonitoringStatsV1)
    ]

    return handlers


def get_web_api_handlers():
    handlers = [
        (r"/api/monitor/memory/?", GetMemoryStats),
        (r"/api/monitor/filesystem/?", GetFileSystemStats),
        (r"/api/monitor/cpu/?", GetCpuStats),
        (r"/api/monitor/?", GetAllStats),
    ]

    return handlers
