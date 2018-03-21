import logging

from time import mktime
from datetime import datetime
from vFense import VFENSE_LOGGING_CONFIG
from vFense.core.agent import *
from vFense.db.client import r, db_connect

logging.config.fileConfig(VFENSE_LOGGING_CONFIG)
logger = logging.getLogger('agentstatus')

def all_agent_status():
    seconds = mktime(datetime.now().timetuple()) - 600
    try:
        conn = db_connect()
        (
            r
            .table(AgentsCollection)
            .filter(
                lambda x:
                x[AgentKeys.LastAgentUpdate].to_epoch_time() < seconds
            )
            .update({AgentKeys.AgentStatus: 'down'})
            .run(conn)
        )
        logger.info('agent uptime verifier completed')
        conn.close()

    except Exception as e:
        logger.exception(e)
