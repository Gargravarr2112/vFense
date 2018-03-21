import re
import logging
import logging.config
from vFense import VFENSE_LOGGING_CONFIG
from time import mktime
from datetime import datetime

from vFense.plugins.patching import *
from vFense.operations import *
from vFense.operations._constants import AgentOperations
from vFense.operations.agent_operations import AgentOperation
from vFense.plugins.patching.patching import (
    update_app_status_by_agentid_and_appid
)

from vFense.core.queue._db import get_all_expired_jobs, delete_all_expired_jobs

logging.config.fileConfig(VFENSE_LOGGING_CONFIG)
logger = logging.getLogger('admin_scheduler')

def remove_expired_jobs_and_update_operations():
    epoch_time_now = mktime(datetime.now().timetuple())
    expired_jobs = get_all_expired_jobs(epoch_time_now)
    status_code, count, error, generated_ids = (
        delete_all_expired_jobs(epoch_time_now)
    )
    jobs_deleted = count
    msg = 'number of jobs expired: %s' % (str(jobs_deleted))
    logger.info(msg)
    for job in expired_jobs:
        operation = (
            AgentOperation('admin', job[OperationKeys.CustomerName], None, None)
        )

        operation.update_operation_expire_time(
            job[OperationKeys.OperationId],
            job[OperationPerAgentKeys.AgentId],
            job[OperationKeys.Operation]
        )

        if job[OperationKeys.Plugin] == RV_PLUGIN:
            collection = AppCollections.UniqueApplications

            if re.search('^install', job['operation']):
                app_status = {STATUS:  AVAILABLE}
                if job['operation'] == AgentOperations.INSTALL_CUSTOM_APPS:
                    collection = AppCollections.CustomApps

                if job['operation'] == AgentOperations.INSTALL_SUPPORTED_APPS:
                    collection = AppCollections.SupportedApps

                if job['operation'] == AgentOperations.INSTALL_AGENT_UPDATE:
                    collection = AppCollections.vFenseApps

            elif re.search('^uninstall', job['operation']):
                app_status = {STATUS:  INSTALLED}
            for app in job[AppsKeys.FileData]:
                update_app_status_by_agentid_and_appid(
                    job[OperationPerAgentKeys.AgentId],
                    collection,
                    app[AppsKeys.AppId],
                    app_status
                )
