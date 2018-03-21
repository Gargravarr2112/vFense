import logging
import logging.config
from vFense import VFENSE_LOGGING_CONFIG

from vFense.core.decorators import return_status_tuple, time_it
from vFense.db.client import r, db_create_close
from vFense.core.queue import *

logging.config.fileConfig(VFENSE_LOGGING_CONFIG)
logger = logging.getLogger('rvapi')


@time_it
@db_create_close
@return_status_tuple
def insert_into_agent_queue(operation, conn=None):
    """Insert data into the agent_queue
        DO NOT CALL DIRECTLY
    Args:
        operation (list|dict): operation data

    Basic Usage:
        >>> from vFense.queue._db import insert_into_agent_queue
        >>> operation = [{'operation': 'data'}]
        >>> insert_into_agent_queue(operation)

    Returns:
        Tuple (status_code, count, error, generated ids)
        >>> (2001, 1, None, [])
    """
    data = {}
    try:
        operation[AgentQueueKeys.CreatedTime] = (
            r.epoch_time(operation[AgentQueueKeys.CreatedTime])
        )
        operation[AgentQueueKeys.ServerQueueTTL] = (
            r.epoch_time(operation[AgentQueueKeys.ServerQueueTTL])
        )
        operation[AgentQueueKeys.AgentQueueTTL] = (
            r.epoch_time(operation[AgentQueueKeys.AgentQueueTTL])
        )

        data = (
            r
            .table(QueueCollections.Agent)
            .insert(operation)
            .run(conn)
        )

    except Exception as e:
        logger.exception(e)

    return(data)

@db_create_close
def get_next_avail_order_id_in_agent_queue(agent_id, conn=None):
    """Get the latest order id and return it.
    Args:
        agent_id (str): 36 character agent UUID.

    Basic Usage:
        >>> from vFense.queue._db import get_next_avail_order_id_in_agent_queue
        >>> agent_id = 'd4119b36-fe3c-4973-84c7-e8e3d72a3e02'
        >>> get_next_avail_order_id_in_agent_queue(agent_id)
        >>> 0

    Returns:
        Integer
    """
    last_num_in_queue = 0
    try:
        last_num_in_queue = (
            r
            .table(QueueCollections.Agent)
            .get_all(agent_id, index=AgentQueueIndexes.AgentId)
            .count()
            .run(conn)
        )

    except Exception as e:
        logger.exception(e)

    return(last_num_in_queue)


@db_create_close
def get_agent_queue(agent_id, conn=None):
    """Retrieve the queue for an agent
    Args:
        agent_id (str): The 36 character agent UUID.

    Basic Usage:
        >>> from vFense.queue._db import get_agent_queue
        >>> agent_id = 'd4119b36-fe3c-4973-84c7-e8e3d72a3e0'
        >>> get_agent_queue(agent_id)

    Returns:
        List of dictionairies
        [
            {
                "agent_queue_ttl": 1396778416, 
                "plugin": "rv", 
                "order_id": 1, 
                "server_queue_ttl": 1396777816, 
                "agent_id": "d4119b36-fe3c-4973-84c7-e8e3d72a3e02", 
                "created_time": 1396777216, 
                "operation_id": "b95837d9-5df7-4ab0-9449-a7be196a2b12", 
                "operation": "updatesapplications", 
                "id": "f9817e07-6877-4857-aef3-e80f57022ac8", 
                "expire_minutes": 10, 
                "customer_name": "default"
            }
        ]
    """
    agent_queue = []
    try:
        agent_queue = list(
            r
            .table(QueueCollections.Agent)
            .get_all(agent_id, index=AgentQueueIndexes.AgentId)
            .merge(
                {
                    AgentQueueKeys.CreatedTime: (
                        r.row[AgentQueueKeys.CreatedTime].to_epoch_time()
                    ),
                    AgentQueueKeys.ServerQueueTTL: (
                        r.row[AgentQueueKeys.ServerQueueTTL].to_epoch_time()
                    ),
                    AgentQueueKeys.AgentQueueTTL: (
                        r.row[AgentQueueKeys.AgentQueueTTL].to_epoch_time()
                    ),
                }
            )
            .order_by(AgentQueueKeys.OrderId)
            .run(conn)
        )

    except Exception as e:
        logger.exception(e)

    return(agent_queue)


@time_it
@db_create_close
@return_status_tuple
def delete_job_in_queue(job_id, conn=None):
    """Delete a job in the queue
        DO NOT CALL DIRECTLY
    Args:
        job_id (str): The 36 character job UUID.

    Basic Usage:
        >>> from vFense.queue._db import delete_job_in_queue
        >>> job_id = 'd4119b36-fe3c-4973-84c7-e8e3d72a3e02'
        >>> delete_job_in_queue(operation)

    Returns:
        Tuple (status_code, count, error, generated ids)
        >>> (2001, 1, None, [])
    """
    data = {}
    try:
        data = (
            r
            .table(QueueCollections.Agent)
            .get(job_id)
            .delete()
            .run(conn)
        )

    except Exception as e:
        logger.exception(e)

    return(data)


@db_create_close
def get_all_expired_jobs(now=None, conn=None):
    """Retrieve all expired jobs
    Kwargs:
        now (float): The epoch time to compare against,
            during the retrieval process.
            Default: (Is to use the epoch time of right now)

    Basic Usage:
        >>> from vFense.queue._db import get_all_expired_jobs
        >>> now = 1396780822.0
        >>> get_all_expired_jobs(now)

    Returns:
        List of dictionairies
        [
            {
                "agent_queue_ttl": 1396778416, 
                "plugin": "rv", 
                "order_id": 1, 
                "server_queue_ttl": 1396777816, 
                "agent_id": "d4119b36-fe3c-4973-84c7-e8e3d72a3e02", 
                "created_time": 1396777216, 
                "operation_id": "b95837d9-5df7-4ab0-9449-a7be196a2b12", 
                "operation": "updatesapplications", 
                "id": "f9817e07-6877-4857-aef3-e80f57022ac8", 
                "expire_minutes": 10, 
                "customer_name": "default"
            }
        ]
    """
    expired_jobs = []
    try:
        if not now:
            expired_jobs = list(
                r
                .table(QueueCollections.Agent)
                .filter(
                    lambda x: x[AgentQueueKeys.ServerQueueTTL] <= r.now()
                )
                .run(conn)
            )

        else:
            expired_jobs = list(
                r
                .table(QueueCollections.Agent)
                .filter(
                    lambda x:
                        x[AgentQueueKeys.ServerQueueTTL].to_epoch_time() <= now
                )
                .run(conn)
            )

    except Exception as e:
        logger.exception(e)

    return(expired_jobs)


@time_it
@db_create_close
@return_status_tuple
def delete_all_expired_jobs(now=None, conn=None):
    """Delete all expired jobs in the queue
        DO NOT CALL DIRECTLY
    Kwargs:
        now (float): The epoch time to compare against,
            during the deletion process.
            Default: (Is to use the epoch time of right now)

    Basic Usage:
        >>> from vFense.queue._db import delete_all_expired_jobs
        >>> now = 1396780822.0
        >>> delete_all_expired_jobs(now)

    Returns:
        Tuple (status_code, count, error, generated ids)
        >>> (2001, 1, None, [])
    """
    try:
        if not now:
            data = (
                r
                .table(QueueCollections.Agent)
                .filter(
                    lambda x: x[AgentQueueKeys.ServerQueueTTL] <= r.now()
                )
                .delete()
                .run(conn)
            )

        else:
            data = (
                r
                .table(QueueCollections.Agent)
                .filter(
                    lambda x:
                        x[AgentQueueKeys.ServerQueueTTL].to_epoch_time() <= now
                )
                .delete()
                .run(conn)
            )

    except Exception as e:
        logger.exception(e)

    return(data)

@db_create_close
def delete_multiple_jobs(job_ids, conn=None):
    """Delete all multiple jobs in the queue by job ids.
        DO NOT CALL DIRECTLY
    Args:
        job_ids (list): List of job ids to delete ['id1', 'id2']

    Basic Usage:
        >>> from vFense.queue._db import delete_multiple_jobs
        >>> job_ids = ['id1', 'id2']
        >>> delete_multiple_jobs(job_ids)

    Returns:
        Tuple (status_code, count, error, generated ids)
        >>> (2001, 1, None, [])
    """
    jobs_deleted = 0
    try:
        if isinstance(job_ids, list):
            jobs = (
                r
                .table(QueueCollections.Agent)
                .get_all(*job_ids)
                .delete()
                .run(conn)
            )
            jobs_deleted = jobs.get('deleted')

        else:
            jobs = (
                r
                .table(QueueCollections.Agent)
                .get(job_ids)
                .delete()
                .run(conn)
            )
            jobs_deleted = jobs.get('deleted')

    except Exception as e:
        logger.exception(e)

    return(jobs_deleted)
