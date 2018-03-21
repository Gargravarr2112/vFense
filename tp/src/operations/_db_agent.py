#!/usr/bin/env python

import logging
import logging.config
from vFense import VFENSE_LOGGING_CONFIG
from vFense.db.client import db_create_close, r

from vFense.core._constants import CommonKeys
from vFense.operations import OperationCollections, \
    OperationPerAgentIndexes, OperationPerAppIndexes, \
    AgentOperationKeys, OperationPerAppKeys

from vFense.operations._db_sub_queries import OperationPerAgentMerge

from vFense.core.decorators import return_status_tuple, time_it
from vFense.errorz.status_codes import AgentOperationCodes

logging.config.fileConfig(VFENSE_LOGGING_CONFIG)
logger = logging.getLogger('rvapi')

@time_it
@db_create_close
def fetch_agent_operation(operation_id, conn=None):
    """Fetch an operation by id and all of it's information
    Args:
        operation_id (str): 36 character UUID

    Basic Usage:
        >>> from vFense.operations._db import fetch_agent_operation
        >>> operation_id = '8fed3dc7-33d4-4278-9bd4-398a68bf7f22'
        >>> fetch_agent_operation(operation_id)

    Returns:
        Dictionary
        {
            "agents_expired_count": 0,
            "cpu_throttle": "normal",
            "agents_total_count": 1,
            "plugin": "rv",
            "tag_id": null,
            "agents_completed_with_errors_count": 0,
            "created_by": "admin",
            "agents_pending_pickup_count": 0,
            "completed_time": 1397246851,
            "operation_status": 6006,
            "agents_completed_count": 1,
            "operation_id": "8fed3dc7-33d4-4278-9bd4-398a68bf7f22",
            "created_time": 1397246674,
            "agents_pending_results_count": 0,
            "operation": "install_os_apps",
            "updated_time": 1397246851,
            "net_throttle": 0,
            "agents_failed_count": 0,
            "restart": "none",
            "customer_name": "default"
        }
    """
    data = {}
    try:
        data = (
            r
            .table(OperationCollections.Agent)
            .get(operation_id)
            .run(conn)
        )

    except Exception as e:
        logger.exception(e)

    return data

@time_it
@db_create_close
def operation_exist(operation_id, conn=None):
    """Verify if the operation exists by operation id.
    Args:
        operation_id (str): 36 character UUID

    Basic Usage:
        >>> from vFense.operations._db import operation_exist
        >>> operation_id = '8fed3dc7-33d4-4278-9bd4-398a68bf7f22'
        >>> operation_exist(operation_id)

    Returns:
        Boolean True or False
    """
    exists = False
    try:
        is_empty = (
            r
            .table(OperationCollections.Agent)
            .get_all(operation_id)
            .is_empty()
            .run(conn)
        )
        if not is_empty:
            exists = True

    except Exception as e:
        logger.exception(e)

    return exists

@time_it
@db_create_close
def operation_with_agentid_exists(operation_id, agent_id, conn=None):
    """Verify if the operation exists by operation id and agent id.
    Args:
        operation_id (str): 36 character UUID
        agent_id (str): 36 character UUID

    Basic Usage:
        >>> from vFense.operations._db import operation_with_agentid_exists
        >>> operation_id = '8fed3dc7-33d4-4278-9bd4-398a68bf7f22'
        >>> agent_id = 'db6bf07-c5da-4494-93bb-109db205ca64'
        >>> operation_with_agentid_exists(operation_id, agent_id)

    Returns:
        Boolean True or False
    """
    exists = False
    try:
        is_empty = (
            r
            .table(OperationCollections.OperationPerAgent)
            .get_all(
                [operation_id, agent_id],
                index=OperationPerAgentIndexes.OperationIdAndAgentId
            )
            .is_empty()
            .run(conn)
        )
        if not is_empty:
            exists = True

    except Exception as e:
        logger.exception(e)

    return exists

@time_it
@db_create_close
def fetch_operation_with_agentid(operation_id, agent_id, conn=None):
    """Fetch the operation by operation id and agent id.
    Args:
        operation_id (str): 36 character UUID
        agent_id (str): 36 character UUID

    Basic Usage:
        >>> from vFense.operations._db import fetch_operation_with_agentid
        >>> operation_id = '8fed3dc7-33d4-4278-9bd4-398a68bf7f22'
        >>> agent_id = 'db6bf07-c5da-4494-93bb-109db205ca64'
        >>> fetch_operation_with_agentid(operation_id, agent_id)

    Returns:
        Dictionary
        {
            "status": "picked_up",
            "picked_up_time": 1397246704,
            "errors": null,
            "expired_time": 0,
            "apps_failed_count": 0,
            "apps_completed_count": 1,
            "completed_time": 1397246851,
            "apps_pending_count": 0,
            "agent_id": "4db6bf07-c5da-4494-93bb-109db205ca64",
            "apps_total_count": 1,
            "operation_id": "8fed3dc7-33d4-4278-9bd4-398a68bf7f22",
            "id": "2f678e9e-a537-4cfb-8613-6aa37696a8a9",
            "customer_name": "default"
        }
    """
    data = {}
    try:
        data = list(
            r
            .table(OperationCollections.OperationPerAgent)
            .get_all(
                [operation_id, agent_id],
                index=OperationPerAgentIndexes.OperationIdAndAgentId
            )
            .merge(OperationPerAgentMerge.TIMES)
            .run(conn)
        )
        if data:
            data = data[0]

    except Exception as e:
        logger.exception(e)

    return data

@time_it
@db_create_close
def operation_with_agentid_and_appid_exists(
        operation_id, agent_id,
        app_id, conn=None
    ):
    """Verify if the operation exists by operation id, agent id and app id.
    Args:
        operation_id (str): 36 character UUID
        agent_id (str): 36 character UUID
        app_id (str): 36 character UUID

    Basic Usage:
        >>> from vFense.operations._db import operation_with_agentid_and_appid_exists
        >>> operation_id = '8fed3dc7-33d4-4278-9bd4-398a68bf7f22'
        >>> agent_id = 'db6bf07-c5da-4494-93bb-109db205ca64'
        >>> app_id = '70d462913faad1ecaa85eda4c448a607164fe39414c8be44405e7ab4f7f8467c'
        >>> operation_with_agentid_and_appid_exists(operation_id, agent_id, app_id)

    Returns:
        Boolean True or False
    """
    exists = False
    try:
        is_empty = (
            r
            .table(OperationCollections.OperationPerApp)
            .get_all(
                [operation_id, agent_id, app_id],
                index=OperationPerAppIndexes.OperationIdAndAgentIdAndAppId
            )
            .is_empty()
            .run(conn)
        )
        if not is_empty:
            exists = True

    except Exception as e:
        logger.exception(e)

    return exists

@time_it
@db_create_close
def group_operations_per_app_by_results(
        operation_id, agent_id, conn=None
    ):
    """Return the grouped results, grouped by status_count
    Args:
        operation_id (str): 36 character UUID
        agent_id (str): 36 character UUID

    Basic Usage:
        >>> from vFense.operations._db import group_operations_per_app_by_results
        >>> operation_id = '8fed3dc7-33d4-4278-9bd4-398a68bf7f22'
        >>> agent_id = 'db6bf07-c5da-4494-93bb-109db205ca64'
        >>> group_operations_per_app_by_results(operation_id, agent_id)

    Returns:
        Tuple (pending_count, completed_count, failed_count)
    """
    pending_count = 0
    completed_count = 0
    failed_count = 0
    data = (pending_count, completed_count, failed_count)
    try:
        app_stats_count = (
            r
            .table(OperationCollections.OperationPerApp)
            .get_all(
                [operation_id, agent_id],
                index=OperationPerAppIndexes.OperationIdAndAgentId
            )
            .group(OperationPerAppKeys.Results)
            .count()
            .ungroup()
            .run(conn)
        )
        for i in app_stats_count:
            if i[CommonKeys.GROUP] == AgentOperationCodes.ResultsPending:
                pending_count = i[CommonKeys.REDUCTION]

            elif i[CommonKeys.GROUP] == AgentOperationCodes.ResultsReceived:
                completed_count = i[CommonKeys.REDUCTION]

            elif (
                    i[CommonKeys.GROUP] ==
                    AgentOperationCodes.ResultsReceivedWithErrors
                ):
                failed_count = i[CommonKeys.REDUCTION]

        data = (pending_count, completed_count, failed_count)

    except Exception as e:
        logger.exception(e)

    return data

@time_it
@db_create_close
@return_status_tuple
def insert_into_agent_operations(operation_data, conn=None):
    """Insert into agent_operations
        DO NOT CALL DIRECTLY
    Args:
        operation_data (list|dict): Insert a list of operations or an operation.

    Basic Usage:
        >>> from vFense.operations._db import insert_into_agent_operations
        >>> operation_data = {'opertion_id': 'id_goes_here'}
        >>> insert_into_agent_operations(operation_data)

    Returns:
        Tuple (status_code, count, error, generated ids)
        >>> (2001, 1, None, [])
    """
    data = {}
    try:
        data = (
            r
            .table(OperationCollections.Agent)
            .insert(operation_data)
            .run(conn)
        )

    except Exception as e:
        logger.exception(e)

    return data

@time_it
@db_create_close
@return_status_tuple
def insert_agent_into_agent_operations(operation_data, conn=None):
    """Insert an operation per agent
        DO NOT CALL DIRECTLY
    Args:
        operation_data (list|dict): Insert a list of operations or an operation.

    Basic Usage:
        >>> from vFense.operations._db import insert_agent_into_agent_operations
        >>> operation_data = {'opertion_id': 'id_goes_here'}
        >>> insert_agent_into_agent_operations(operation_data)

    Returns:
        Tuple (status_code, count, error, generated ids)
        >>> (2001, 1, None, [])
    """
    data = {}
    try:
        data = (
            r
            .table(OperationCollections.OperationPerAgent)
            .insert(operation_data)
            .run(conn)
        )

    except Exception as e:
        logger.exception(e)

    return data

@time_it
@db_create_close
@return_status_tuple
def insert_app_into_agent_operations(operation_data, conn=None):
    """Insert an operation per agent
        DO NOT CALL DIRECTLY
    Args:
        operation_data (list|dict): Insert a list of operations or an operation.

    Basic Usage:
        >>> from vFense.operations._db import insert_app_into_agent_operations
        >>> operation_data = {'opertion_id': 'id_goes_here'}
        >>> insert_app_into_agent_operations(operation_data)

    Returns:
        Tuple (status_code, count, error, generated ids)
        >>> (2001, 1, None, [])
    """
    data = {}
    try:
        data = (
            r
            .table(OperationCollections.OperationPerApp)
            .insert(operation_data)
            .run(conn)
        )

    except Exception as e:
        logger.exception(e)

    return data

@time_it
@db_create_close
@return_status_tuple
def update_agent_operation(operation_id, operation_data, conn=None):
    """Update an agent_operation.
        DO NOT CALL DIRECTLY
    Args:
        operation_id (str): the id of the operation.
        operation_data (list|dict): Insert a list of operations or an operation.

    Basic Usage:
        >>> from vFense.operations._db import update_agent_operation
        >>> operation_id = '5dc03727-de89-460d-b2a7-7f766c83d2f1'
        >>> operation_data = {'opertion_id': 'id_goes_here'}
        >>> update_agent_operation(operation_id, operation_data)

    Returns:
        Tuple (status_code, count, error, generated ids)
        >>> (2001, 1, None, [])
    """
    data = {}
    try:
        data = (
            r
            .table(OperationCollections.Agent)
            .get(operation_id)
            .update(operation_data)
            .run(conn)
        )

    except Exception as e:
        logger.exception(e)

    return data

@time_it
@db_create_close
@return_status_tuple
def update_operation_per_agent(
        operation_id, agent_id,
        operation_data, conn=None
    ):
    """Update an operation per agent.
        DO NOT CALL DIRECTLY
    Args:
        operation_id (str): the id of the operation.
        agent_id (str): the id of the agent.
        operation_data (list|dict): Insert a list of operations or an operation.

    Basic Usage:
        >>> from vFense.operations._db import update_operation_per_agent
        >>> operation_id = '5dc03727-de89-460d-b2a7-7f766c83d2f1'
        >>> agent_id = '38c1c67e-436f-4652-8cae-f1a2ac2dd4a2'
        >>> operation_data = {'opertion_id': 'id_goes_here'}
        >>> update_operation_per_agent(operation_id, agent_id, operation_data)

    Returns:
        Tuple (status_code, count, error, generated ids)
        >>> (2001, 1, None, [])
    """
    data = {}
    try:
        data = (
            r
            .table(OperationCollections.OperationPerAgent)
            .get_all(
                [operation_id, agent_id],
                index=OperationPerAgentIndexes.OperationIdAndAgentId
            )
            .update(operation_data)
            .run(conn)
        )

    except Exception as e:
        logger.exception(e)

    return data

@time_it
@db_create_close
@return_status_tuple
def update_operation_per_app(
        operation_id, agent_id, app_id,
        operation_data, conn=None
    ):
    """Update an operation per agent.
        DO NOT CALL DIRECTLY
    Args:
        operation_id (str): The id of the operation.
        agent_id (str): The id of the agent.
        app_id (str): The id of the app.
        operation_data (list|dict): Insert a list of operations or an operation.

    Basic Usage:
        >>> from vFense.operations._db import update_operation_per_app
        >>> operation_id = '5dc03727-de89-460d-b2a7-7f766c83d2f1'
        >>> agent_id = '38c1c67e-436f-4652-8cae-f1a2ac2dd4a2'
        >>> operation_data = {'opertion_id': 'id_goes_here'}
        >>> app_id = '70d462913faad1ecaa85eda4c448a607164fe39414c8be44405e7ab4f7f8467c'
        >>> update_operation_per_app(operation_id, agent_id, app_id, operation_data)

    Returns:
        Tuple (status_code, count, error, generated ids)
        >>> (2001, 1, None, [])
    """
    data = {}
    try:
        data = (
            r
            .table(OperationCollections.OperationPerApp)
            .get_all(
                [operation_id, agent_id, app_id],
                index=OperationPerAppIndexes.OperationIdAndAgentIdAndAppId
            )
            .update(operation_data)
            .run(conn)
        )

    except Exception as e:
        logger.exception(e)

    return data

@time_it
@db_create_close
@return_status_tuple
def update_agent_operation_expire_time(
        operation_id, db_time, conn=None
    ):
    """Update an operation per agent.
        DO NOT CALL DIRECTLY
    Args:
        operation_id (str): the id of the operation.
        db_time (rql date object): r.epoch_time

    Basic Usage:
        >>> from vFense.operations._db import update_agent_operation_expire_time
        >>> operation_id = '5dc03727-de89-460d-b2a7-7f766c83d2f1'
        >>> db_time = r.epoch_time(time.time())
        >>> update_agent_operation_expire_time(operation_id, db_time)

    Returns:
        Tuple (status_code, count, error, generated ids)
        >>> (2001, 1, None, [])
    """
    data = {}
    try:
        data = (
            r
            .table(OperationCollections.Agent)
            .get(operation_id)
            .update(
                {
                    AgentOperationKeys.AgentsPendingPickUpCount: (
                        r.branch(
                            r.row[AgentOperationKeys.AgentsPendingPickUpCount] > 0,
                            r.row[AgentOperationKeys.AgentsPendingPickUpCount] - 1,
                            r.row[AgentOperationKeys.AgentsPendingPickUpCount],
                        )
                    ),
                    AgentOperationKeys.AgentsExpiredCount: (
                        r.branch(
                            r.row[AgentOperationKeys.AgentsExpiredCount] < r.row[AgentOperationKeys.AgentsTotalCount],
                            r.row[AgentOperationKeys.AgentsExpiredCount] + 1,
                            r.row[AgentOperationKeys.AgentsExpiredCount]
                        )
                    ),
                    AgentOperationKeys.UpdatedTime: db_time
                }
            )
            .run(conn)
        )

    except Exception as e:
        logger.exception(e)

    return data

@time_it
@db_create_close
@return_status_tuple
def update_agent_operation_pickup_time(
        operation_id, db_time, conn=None
    ):
    """Update an operation per agent.
        DO NOT CALL DIRECTLY
    Args:
        operation_id (str): the id of the operation.
        db_time (rql date object): r.epoch_time

    Basic Usage:
        >>> from vFense.operations._db import update_agent_operation_pickup_time
        >>> operation_id = '5dc03727-de89-460d-b2a7-7f766c83d2f1'
        >>> db_time = r.epoch_time(time.time())
        >>> update_agent_operation_pickup_time(operation_id, db_time)

    Returns:
        Tuple (status_code, count, error, generated ids)
        >>> (2001, 1, None, [])
    """
    data = {}
    try:
        data = (
            r
            .table(OperationCollections.Agent)
            .get(operation_id)
            .update(
                {
                    AgentOperationKeys.AgentsPendingPickUpCount: (
                        r.branch(
                            r.row[AgentOperationKeys.AgentsPendingPickUpCount] > 0,
                            r.row[AgentOperationKeys.AgentsPendingPickUpCount] - 1,
                            r.row[AgentOperationKeys.AgentsPendingPickUpCount],
                        )
                    ),
                    AgentOperationKeys.AgentsPendingResultsCount: (
                        r.branch(
                            r.row[AgentOperationKeys.AgentsPendingResultsCount] < (
                                r.row[AgentOperationKeys.AgentsTotalCount]
                            ),
                            r.row[AgentOperationKeys.AgentsPendingResultsCount] + 1,
                            r.row[AgentOperationKeys.AgentsPendingResultsCount]
                        )
                    ),
                    AgentOperationKeys.UpdatedTime: db_time
                }
            )
            .run(conn)
        )

    except Exception as e:
        logger.exception(e)

    return data

@time_it
@db_create_close
@return_status_tuple
def update_completed_and_pending_count(
        operation_id, db_time, conn=None
    ):
    """Update completed and pending count.
        DO NOT CALL DIRECTLY
    Args:
        operation_id (str): the id of the operation.
        db_time (rql date object): r.epoch_time

    Basic Usage:
        >>> from vFense.operations._db import update_completed_and_pending_count
        >>> operation_id = '5dc03727-de89-460d-b2a7-7f766c83d2f1'
        >>> db_time = r.epoch_time(time.time())
        >>> update_completed_and_pending_count(operation_id, db_time)

    Returns:
        Tuple (status_code, count, error, generated ids)
        >>> (2001, 1, None, [])
    """
    data = {}
    try:
        data = (
            r
            .table(OperationCollections.Agent)
            .get(operation_id)
            .update(
                {
                    AgentOperationKeys.AgentsCompletedCount: r.branch(
                        r.row[AgentOperationKeys.AgentsCompletedCount] < (
                            r.row[AgentOperationKeys.AgentsTotalCount]
                        ),
                        r.row[AgentOperationKeys.AgentsCompletedCount] + 1,
                        r.row[AgentOperationKeys.AgentsCompletedCount]
                    ),
                    AgentOperationKeys.AgentsPendingResultsCount: r.branch(
                        r.row[AgentOperationKeys.AgentsPendingResultsCount] > 0,
                        r.row[AgentOperationKeys.AgentsPendingResultsCount] - 1,
                        r.row[AgentOperationKeys.AgentsPendingResultsCount]
                    ),
                    AgentOperationKeys.UpdatedTime: db_time,
                    AgentOperationKeys.CompletedTime: db_time
                }
            )
            .run(conn)
        )

    except Exception as e:
        logger.exception(e)

    return data

@time_it
@db_create_close
@return_status_tuple
def update_failed_and_pending_count(
        operation_id, db_time, conn=None
    ):
    """Update failed and pending count.
        DO NOT CALL DIRECTLY
    Args:
        operation_id (str): the id of the operation.
        db_time (rql date object): r.epoch_time

    Basic Usage:
        >>> from vFense.operations._db import update_failed_and_pending_count
        >>> operation_id = '5dc03727-de89-460d-b2a7-7f766c83d2f1'
        >>> db_time = r.epoch_time(time.time())
        >>> update_completed_and_failed_count(operation_id, db_time)

    Returns:
        Tuple (status_code, count, error, generated ids)
        >>> (2001, 1, None, [])
    """
    data = {}
    try:
        data = (
            r
            .table(OperationCollections.Agent)
            .get(operation_id)
            .update(
                {
                    AgentOperationKeys.AgentsFailedCount: r.branch(
                        r.row[AgentOperationKeys.AgentsFailedCount] < (
                            r.row[AgentOperationKeys.AgentsTotalCount]
                        ),
                        r.row[AgentOperationKeys.AgentsFailedCount] + 1,
                        r.row[AgentOperationKeys.AgentsFailedCount]
                    ),
                    AgentOperationKeys.AgentsPendingResultsCount: r.branch(
                        r.row[AgentOperationKeys.AgentsPendingResultsCount] > 0,
                        r.row[AgentOperationKeys.AgentsPendingResultsCount] - 1,
                        r.row[AgentOperationKeys.AgentsPendingResultsCount]
                    ),
                    AgentOperationKeys.UpdatedTime: db_time,
                    AgentOperationKeys.CompletedTime: db_time
                }
            )
            .run(conn)
        )

    except Exception as e:
        logger.exception(e)

    return data

@time_it
@db_create_close
@return_status_tuple
def update_errors_and_pending_count(
        operation_id, db_time, conn=None
    ):
    """Update errors and pending count.
        DO NOT CALL DIRECTLY
    Args:
        operation_id (str): the id of the operation.
        db_time (rql date object): r.epoch_time

    Basic Usage:
        >>> from vFense.operations._db import update_errors_and_pending_count
        >>> operation_id = '5dc03727-de89-460d-b2a7-7f766c83d2f1'
        >>> db_time = r.epoch_time(time.time())
        >>> update_completed_and_errors_count(operation_id, db_time)

    Returns:
        Tuple (status_code, count, error, generated ids)
        >>> (2001, 1, None, [])
    """
    data = {}
    try:
        data = (
            r
            .table(OperationCollections.Agent)
            .get(operation_id)
            .update(
                {
                    AgentOperationKeys.AgentsCompletedWithErrorsCount: r.branch(
                        r.row[AgentOperationKeys.AgentsCompletedWithErrorsCount] < (
                            r.row[AgentOperationKeys.AgentsTotalCount]
                        ),
                        r.row[AgentOperationKeys.AgentsCompletedWithErrorsCount] + 1,
                        r.row[AgentOperationKeys.AgentsCompletedWithErrorsCount]
                    ),
                    AgentOperationKeys.AgentsPendingResultsCount: r.branch(
                        r.row[AgentOperationKeys.AgentsPendingResultsCount] > 0,
                        r.row[AgentOperationKeys.AgentsPendingResultsCount] - 1,
                        r.row[AgentOperationKeys.AgentsPendingResultsCount]
                    ),
                    AgentOperationKeys.UpdatedTime: db_time,
                    AgentOperationKeys.CompletedTime: db_time
                }
            )
            .run(conn)
        )

    except Exception as e:
        logger.exception(e)

    return data
