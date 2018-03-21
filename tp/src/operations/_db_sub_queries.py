#!/usr/bin/env python

import logging
import logging.config
from vFense import VFENSE_LOGGING_CONFIG
from vFense.db.client import r
from vFense.operations import AgentOperationKeys, OperationPerAgentKeys


logging.config.fileConfig(VFENSE_LOGGING_CONFIG)
logger = logging.getLogger('rvapi')


class OperationMerge():
    TIMES = {
        AgentOperationKeys.CompletedTime: (
            r.row[AgentOperationKeys.CompletedTime].to_epoch_time()
        ),
        AgentOperationKeys.CreatedTime: (
            r.row[AgentOperationKeys.CreatedTime].to_epoch_time()
        )
    }

class OperationPerAgentMerge():
    TIMES = {
        OperationPerAgentKeys.CompletedTime: (
            r.row[OperationPerAgentKeys.CompletedTime].to_epoch_time()
        ),
        OperationPerAgentKeys.ExpiredTime: (
            r.row[OperationPerAgentKeys.ExpiredTime].to_epoch_time()
        ),
        OperationPerAgentKeys.PickedUpTime: (
            r.row[OperationPerAgentKeys.PickedUpTime].to_epoch_time()
        )
    }
