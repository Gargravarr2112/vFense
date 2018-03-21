import logging
from time import time

from vFense import VFENSE_LOGGING_CONFIG
from vFense.core._constants import CommonKeys
from vFense.core._db_constants import DbTime
from vFense.core.agent import AgentKeys
from vFense.core.agent._constants import AgentVirtualKeys, \
    AgentStatusKeys, ProductionLevels

from vFense.core.agent._db import fetch_production_levels_from_agent, \
    fetch_supported_os_strings, fetch_agent_ids, fetch_agents, \
    fetch_all_agents_for_customer, fetch_agent_info, \
    update_agent_data, insert_agent_data, delete_all_agents_for_customer, \
    move_agents_to_customer, move_agent_to_customer, \
    move_all_agents_to_customer

from vFense.core.customer import Customer
from vFense.core.customer.customers import get_customer, create_customer
from vFense.core.decorators import time_it, results_message

from vFense.db.hardware import Hardware
#from vFense.errorz.results import Results
from vFense.errorz._constants import ApiResultKeys
from vFense.errorz.status_codes import DbCodes, GenericCodes,\
    AgentCodes, AgentFailureCodes, GenericFailureCodes, \
    AgentResultCodes, AgentFailureResultCodes
#from vFense.plugins.patching import *

logging.config.fileConfig(VFENSE_LOGGING_CONFIG)
logger = logging.getLogger('rvapi')


@time_it
def get_production_levels(customer_name):
    """Retrieve all the production levels that is in the database.
    Args:
        customer_name (str): Name of the customer, where the agent is located.

    Basic Usage:
        >>> from vFense.core.agent.agents import get_production_levels
        >>> customer_name = 'default'
        >>> get_production_levels(customer_name)
        [
            u'Development',
            u'Production'
        ]
    """
    data = fetch_production_levels_from_agent(customer_name)
    return data

@time_it
def get_supported_os_codes():
    """Retrieve all the base operating systems codes
        that is in the database.

    Basic Usage:
        >>> from vFense.core.agent.agents import get_supported_os_codes
        >>> get_supported_os_codes()
        [
            u'windows',
            u'linux',
            u'darwin',
        ]
    """
    oses = ['windows', 'linux', 'darwin']
    return oses

@time_it
def get_supported_os_strings(customer_name):
    """Retrieve all the operating systems that is in the database.
    Args:
        customer_name (str): Name of the customer, where the agent is located.

    Basic Usage:
        >>> from vFense.core.agent.agents import get_supported_os_strings
        >>> customer_name = 'default'
        >>> get_supported_os_strings(customer_name)
        [
            u'CentOS 6.5',
            u'Ubuntu 12.04',
            u'Windows 7 Professional Service Pack 1',
            u'Windows 8.1 '
        ]
    """
    data = fetch_supported_os_strings(customer_name)
    return data

@time_it
def get_all_agent_ids(customer_name=None, agent_os=None):
    """Retrieve all agent_ids by either customer_name or os code.
    Kwargs:
        customer_name (str, optional): Name of the customer, where the agent
            is located
        agent_os (str, optional): linux or windows or darwin

    Basic Usage::
        >>> from vFense.core.agent.agents import get_all_agent_ids
        >>> customer_name = 'default'
        >>> agent_os = 'os_code'
        >>> get_all_agent_ids(customer_name, agent_os)
        [
            u'52faa1db-290a-47a7-a4cf-e4ad70e25c38',
            u'3ea8fd7a-8aad-40da-aff0-8da6fa5f8766'
        ]
    """

    if agent_os and customer_name:
        agents = fetch_agent_ids(customer_name, agent_os)

    elif agent_os and not customer_name:
        agents = fetch_agent_ids(agent_os=agent_os)

    elif not agent_os and customer_name:
        agents = fetch_agent_ids(customer_name)

    elif not agent_os and not customer_name:
        agents = fetch_agent_ids()

    return agents

@time_it
def get_agents_info(customer_name=None, agent_os=None, keys_to_pluck=None):
    """Retrieve a list of agents by os code and or customer name.

    Kwargs:
        customer_name (str, optional): Name of the customer, where the agent
            is located
        agent_os (str, optional): The operating system you are filtering for.
            Ex: linux or windows or darwin
        keys_to_pluck (list, optional): List of specific keys that you
            are retrieving from the database.

    Basic Usage:
        >>> from vFense.core.agent.agents import get_agents_info
        >>> os_code = 'linux'
        >>> pluck = ['computer_name', 'agent_id']
        >>> get_agents_info(customer_name, os_code, keys_to_pluck=pluck)

    Returns:
        (list): list of dictionaries with agent data
            Ex:
                [
                    {
                        u'agent_id': u'52faa1db-290a-47a7-a4cf-e4ad70e25c38',
                        u'computer_name': u'ubuntu'
                    },
                    {
                        u'agent_id': u'3ea8fd7a-8aad-40da-aff0-8da6fa5f8766',
                        u'computer_name': u'localhost.localdomain'
                    }
                ]
    """

    if agent_os and not keys_to_pluck and customer_name:
        agents = (
            fetch_agents(
                customer_name=customer_name,
                filter_key=AgentKeys.OsCode,
                filter_val=agent_os
            )
        )

    elif agent_os and not keys_to_pluck and not customer_name:
        agents = (
            fetch_agents(
                filter_key=AgentKeys.OsCode,
                filter_val=agent_os
            )
        )

    elif agent_os and keys_to_pluck and customer_name:
        agents = (
            fetch_agents(
                customer_name=customer_name,
                filter_key=AgentKeys.OsCode,
                filter_val=agent_os,
                keys_to_pluck=keys_to_pluck,
            )
        )

    elif agent_os and keys_to_pluck and not customer_name:
        agents = (
            fetch_agents(
                filter_key=AgentKeys.OsCode,
                filter_val=agent_os,
                keys_to_pluck=keys_to_pluck,
            )
        )

    elif not agent_os and keys_to_pluck and customer_name:
        agents = (
            fetch_agents(
                customer_name=customer_name,
                keys_to_pluck=keys_to_pluck,
            )
        )

    elif not agent_os and keys_to_pluck and not customer_name:
        agents = (
            fetch_agents(
                keys_to_pluck=keys_to_pluck,
            )
        )

    elif not agent_os and not keys_to_pluck and not customer_name:
        agents = (
            fetch_agents()
        )

    elif not agent_os and not keys_to_pluck and customer_name:
        agents = (
            fetch_all_agents_for_customer(customer_name)
        )

    return agents


@time_it
def get_agent_info(agent_id, keys_to_pluck=None):
    """Retrieve agent information.
    Args:
        agent_id (str): 36 character uuid of the agent you are updating.

    Kwargs:
        keys_to_pluck (list, optional): List of specific keys that
        you are retrieving from the database.

    Basic Usage::
        >>> from vFense.core.agent.agents import get_agent_info
        >>> agent_id = '52faa1db-290a-47a7-a4cf-e4ad70e25c38'
        >>> keys_to_pluck = ['production_level', 'needs_reboot']
        >>> get_agent_info(agent_id, keys_to_pluck)
        {
            u'agent_id': u'52faa1db-290a-47a7-a4cf-e4ad70e25c38',
            u'production_level': u'Development'
        }
    """

    return fetch_agent_info(agent_id, keys_to_pluck)

@time_it
@results_message
def update_agent_field(
        agent_id, field, value,
        username=None, uri=None, method=None
    ):
    """Update a field for an agent.
    Args:
        agent_id (str): 36 character uuid of the agent you are updating.
        field (str): The field you are going to update.
        value (str): The field will be updated to this value.

    Kwargs:
        user_name (str): The name of the user who called this function.
        uri (str): The uri that was used to call this function.
        method (str): The HTTP methos that was used to call this function.

    Basic Usage::
        >>> from vFense.core.agent.agents import update_agent_field
        >>> agent_id = '0a1f9a3c-9200-42ef-ba63-f4fd17f0644c'
        >>> field = 'production_level'
        >>> value = 'Development'
        >>> update_agent_field(agent_id, field, value)
        {
            'uri': None,
            'rv_status_code': 1008,
            'http_method': None,
            'http_status': 200,
            'message': 'admin - agent 52faa1db-290a-47a7-a4cf-e4ad70e25c38 was updated',
            'data': {'needs_reboot': 'no'}
        }
    """
    agent_data = {field: value}
    status = update_agent_field.func_name + ' - '
    status_code, count, errors, generated_ids = (
        update_agent_data(
            agent_id, agent_data
        )
    )
    if status_code == DbCodes.Replaced:
        msg = 'agent_id %s updated'
        generic_status_code = GenericCodes.ObjectUpdated
        vfense_status_code = AgentCodes.AgentsUpdated

    elif status_code == DbCodes.Skipped:
        msg = 'agent_id %s does not exist'
        generic_status_code = GenericFailureCodes.FailedToUpdateObject
        vfense_status_code = AgentFailureCodes.AgentsDoesNotExist

    elif status_code == DbCodes.Unchanged:
        msg = 'agent_id %s was not updated, data was the same.'
        generic_status_code = GenericCodes.ObjectUnchanged
        vfense_status_code = GenericCodes.ObjectUnchanged

    elif status_code == DbCodes.Errors:
        msg = 'agent_id %s could not be updated'
        generic_status_code = GenericFailureCodes.FailedToUpdateObject
        vfense_status_code = AgentFailureCodes.AgentsFailedToUpdate

    results = {
        ApiResultKeys.DB_STATUS_CODE: status_code,
        ApiResultKeys.GENERIC_STATUS_CODE: generic_status_code,
        ApiResultKeys.VFENSE_STATUS_CODE: vfense_status_code,
        ApiResultKeys.MESSAGE: status + msg,
        ApiResultKeys.DATA: [agent_data],
        ApiResultKeys.USERNAME: username,
        ApiResultKeys.URI: uri,
        ApiResultKeys.HTTP_METHOD: method
    }

    return results

@time_it
@results_message
def update_agent_fields(
        agent_id, agent_data,
        username=None, uri=None,
        method=None
    ):
    """Update various fields in an agent.
    Args:
        agent_id (str): 36 character uuid of the agent you are updating.
        agent_data (dict): Dictionary of the data that you are updating.

    Kwargs:
        user_name (str): The name of the user who called this function.
        uri (str): The uri that was used to call this function.
        method (str): The HTTP methos that was used to call this function.

    Basic Usage::
        >>> from vFense.core.agent.agents import update_agent_fields
        >>> agent_id = '0a1f9a3c-9200-42ef-ba63-f4fd17f0644c'
        >>> agent_data = {'production_level': 'Development'}
        >>> update_agent_fields(agent_id, agent_data)
        {
            'uri': None,
            'rv_status_code': 1008,
            'http_method': None,
            'http_status': 200,
            'message': 'admin - agent 52faa1db-290a-47a7-a4cf-e4ad70e25c38 was updated',
            'data': {'needs_reboot': 'no'}
        }
    """
    status = update_agent_fields.func_name + ' - '
    status_code, count, errors, generated_ids = (
        update_agent_data(
            agent_id, agent_data
        )
    )
    if status_code == DbCodes.Replaced:
        msg = 'agent_id %s updated'
        generic_status_code = GenericCodes.ObjectUpdated
        vfense_status_code = AgentCodes.AgentsUpdated

    elif status_code == DbCodes.Skipped:
        msg = 'agent_id %s does not exist'
        generic_status_code = GenericFailureCodes.FailedToUpdateObject
        vfense_status_code = AgentFailureCodes.AgentsDoesNotExist

    elif status_code == DbCodes.Unchanged:
        msg = 'agent_id %s was not updated, data was the same.'
        generic_status_code = GenericCodes.ObjectUnchanged
        vfense_status_code = GenericCodes.ObjectUnchanged

    elif status_code == DbCodes.Errors:
        msg = 'agent_id %s could not be updated'
        generic_status_code = GenericFailureCodes.FailedToUpdateObject
        vfense_status_code = AgentFailureCodes.AgentsFailedToUpdate

    results = {
        ApiResultKeys.DB_STATUS_CODE: status_code,
        ApiResultKeys.GENERIC_STATUS_CODE: generic_status_code,
        ApiResultKeys.VFENSE_STATUS_CODE: vfense_status_code,
        ApiResultKeys.MESSAGE: status + msg,
        ApiResultKeys.DATA: [agent_data],
        ApiResultKeys.USERNAME: username,
        ApiResultKeys.URI: uri,
        ApiResultKeys.HTTP_METHOD: method
    }

    return results

@time_it
@results_message
def update_agent_status(agent_id, username=None, uri=None, method=None):
    """Update the status of an agent.
    Args:
        agent_id (str): 36 character uuid of the agent you are updating.

    Kwargs:
        user_name (str): The name of the user who called this function.
        uri (str): The uri that was used to call this function.
        method (str): The HTTP methos that was used to call this function.

    Basic Usage:
        >>> from vFense.core.agent.agents import update_agent_status
        >>> agent_id = '0a1f9a3c-9200-42ef-ba63-f4fd17f0644c'
        >>> update_agent_status(agent_id)
        {
            'uri': None,
            'rv_status_code': 1008,
            'http_method': None,
            'http_status': 200,
            'message': 'admin - agent 52faa1db-290a-47a7-a4cf-e4ad70e25c38 was updated',
            'data': {'needs_reboot': 'no'}
        }
    """
    status = update_agent_status.func_name + ' - '
    now = time()
    agent_data = {
        AgentKeys.LastAgentUpdate: DbTime.epoch_time_to_db_time(now),
        AgentKeys.AgentStatus: 'up'
    }
    status_code, count, error, generated_ids = (
        update_agent_data(agent_id, agent_data)
    )
    if status_code == DbCodes.Replaced:
        msg = 'agent_id %s updated'
        generic_status_code = GenericCodes.ObjectUpdated
        vfense_status_code = AgentCodes.AgentsUpdated

    elif status_code == DbCodes.Skipped:
        msg = 'agent_id %s does not exist'
        generic_status_code = GenericFailureCodes.FailedToUpdateObject
        vfense_status_code = AgentFailureCodes.AgentsDoesNotExist

    elif status_code == DbCodes.Errors:
        msg = 'agent_id %s could not be updated'
        generic_status_code = GenericFailureCodes.FailedToUpdateObject
        vfense_status_code = AgentFailureCodes.AgentsFailedToUpdate

    agent_data[AgentKeys.LastAgentUpdate] = now

    results = {
        ApiResultKeys.DB_STATUS_CODE: status_code,
        ApiResultKeys.GENERIC_STATUS_CODE: generic_status_code,
        ApiResultKeys.VFENSE_STATUS_CODE: vfense_status_code,
        ApiResultKeys.MESSAGE: status + msg,
        ApiResultKeys.DATA: [],
        ApiResultKeys.USERNAME: username,
        ApiResultKeys.URI: uri,
        ApiResultKeys.HTTP_METHOD: method
    }

    return results

@time_it
@results_message
def add_agent(
        system_info, hardware, username=None,
        customer_name=None, uri=None, method=None
    ):
    """Add a new agent to the database
    Args:
        system_info (dict): Dictionary with system related info
        hardware (list):  List of dictionaries that rpresent the hardware

    Kwargs:
        user_name (str): The name of the user who called this function.
        customer_name (str): The name of the customer.
        uri (str): The uri that was used to call this function.
        method (str): The HTTP methos that was used to call this function.

    Basic Usage:
        >>> from vFense.core.agent.agents import add_agent

    Returns:
        Dictionary
    """
    results = {
        ApiResultKeys.USERNAME: username,
        ApiResultKeys.URI: uri,
        ApiResultKeys.HTTP_METHOD: method
    }
    try:
        now = time()
        agent_data = {}
        agent_data[AgentKeys.AgentStatus] = AgentStatusKeys.UP
        agent_data[AgentKeys.MachineType] = AgentVirtualKeys.PHYSICAL
        agent_data[AgentKeys.Tags] = []
        agent_data[AgentKeys.NeedsReboot] = CommonKeys.NO
        agent_data[AgentKeys.DisplayName] = None
        agent_data[AgentKeys.HostName] = None
        agent_data[AgentKeys.CustomerName] = customer_name
        agent_data[AgentKeys.Hardware] = hardware

        if not AgentKeys.ProductionLevel in system_info:
            agent_data[AgentKeys.ProductionLevel] = ProductionLevels.PRODUCTION

        if customer_name != 'default':
            cexists = get_customer(customer_name)
            if not cexists and len(customer_name) >= 1:
                customer = Customer(customer_name)

                create_customer(
                    customer, username=username, uri=uri, method=method
                )

        for key, value in system_info.items():
            agent_data[key] = value

        agent_data[AgentKeys.LastAgentUpdate] = (
            DbTime.epoch_time_to_db_time(now)
        )

        object_status, object_count, error, generated_ids = (
            insert_agent_data(agent_data)
        )
        if object_status == DbCodes.Inserted and object_count > 0:
            agent_id = generated_ids.pop()
            Hardware().add(agent_id, agent_data[AgentKeys.Hardware])
            data = {
                AgentKeys.AgentId: agent_id,
                AgentKeys.CustomerName: agent_data[AgentKeys.CustomerName],
                AgentKeys.ComputerName: agent_data[AgentKeys.ComputerName],
                AgentKeys.Hardware: agent_data[AgentKeys.Hardware],
                AgentKeys.Tags: agent_data[AgentKeys.Tags],
                AgentKeys.OsCode: agent_data[AgentKeys.OsCode],
                AgentKeys.OsString: agent_data[AgentKeys.OsString],
            }
            msg = 'new agent_operation succeeded'
            generic_status_code = GenericCodes.ObjectCreated
            vfense_status_code = AgentResultCodes.NewAgentSucceeded
            results[ApiResultKeys.GENERIC_STATUS_CODE] = generic_status_code
            results[ApiResultKeys.VFENSE_STATUS_CODE] = vfense_status_code
            results[ApiResultKeys.MESSAGE] = msg
            results[ApiResultKeys.DATA] = [data]
            results[ApiResultKeys.GENERATED_IDS] = [agent_id]

        elif object_status == DbCodes.Errors:
            msg = 'new agent operation failed' % (error)
            generic_status_code = GenericFailureCodes.FailedToCreateObject
            vfense_status_code = AgentFailureResultCodes.NewAgentFailed
            results[ApiResultKeys.GENERIC_STATUS_CODE] = generic_status_code
            results[ApiResultKeys.VFENSE_STATUS_CODE] = vfense_status_code
            results[ApiResultKeys.MESSAGE] = msg

    except Exception as e:
        logger.exception(e)
        msg = 'new agent operation failed' % (e)
        generic_status_code = GenericFailureCodes.FailedToCreateObject
        vfense_status_code = AgentFailureResultCodes.NewAgentFailed
        results[ApiResultKeys.GENERIC_STATUS_CODE] = generic_status_code
        results[ApiResultKeys.VFENSE_STATUS_CODE] = vfense_status_code
        results[ApiResultKeys.MESSAGE] = msg

    return results

@time_it
@results_message
def update_agent(
        agent_id, system_info, hardware, rebooted,
        username=None, customer_name=None,
        uri=None, method=None
    ):
    """Update various aspects of agent
    Args:
        agent_id (str): 36 character uuid of the agent you are updating
        system_info (dict): Dictionary with system related info
        hardware (dict):  List of dictionaries that rpresent the hardware
        rebooted (str): yes or no

    Kwargs:
        user_name (str): The name of the user who called this function.
        customer_name (str): The name of the customer.
        uri (str): The uri that was used to call this function.
        method (str): The HTTP methos that was used to call this function.
    """
    results = {
        ApiResultKeys.USERNAME: username,
        ApiResultKeys.URI: uri,
        ApiResultKeys.HTTP_METHOD: method
    }
    agent_data = {}
    try:
        now = time()
        agent_orig_info = fetch_agent_info(agent_id)
        if agent_orig_info:
            agent_data[AgentKeys.Hardware] = hardware

            for key, value in system_info.items():
                agent_data[key] = value

            agent_data[AgentKeys.LastAgentUpdate] = (
                DbTime.epoch_time_to_db_time(now)
            )
            agent_data[AgentKeys.HostName] = (
                agent_orig_info.get(AgentKeys.HostName, None)
            )
            agent_data[AgentKeys.DisplayName] = (
                agent_orig_info.get(AgentKeys.DisplayName, None)
            )

            if rebooted == CommonKeys.YES:
                agent_data[AgentKeys.NeedsReboot] = CommonKeys.NO

            status_code, count, error, generated_ids = (
                update_agent_data(agent_id, agent_data)
            )

            if status_code == DbCodes.Replaced and count > 0:
                Hardware().add(agent_id, hardware)
                msg = 'agent %s updated successfully.' % (agent_id)

                results[ApiResultKeys.GENERIC_STATUS_CODE] = \
                    GenericCodes.ObjectUpdated
                results[ApiResultKeys.VFENSE_STATUS_CODE] = \
                    AgentResultCodes.ResultsUpdated
                results[ApiResultKeys.MESSAGE] = msg
                results[ApiResultKeys.DATA] = [agent_data]
                results[ApiResultKeys.UPDATED_IDS] = [agent_id]

            elif status_code == DbCodes.Unchanged:
                Hardware().add(agent_id, hardware)
                msg = 'agent %s unchanged, data is the same.' % (agent_id)

                results[ApiResultKeys.GENERIC_STATUS_CODE] = \
                    GenericCodes.ObjectUnchanged
                results[ApiResultKeys.VFENSE_STATUS_CODE] = \
                    AgentResultCodes.ResultsUpdated
                results[ApiResultKeys.MESSAGE] = msg
                results[ApiResultKeys.DATA] = [agent_data]
                results[ApiResultKeys.UNCHANGED_IDS] = [agent_id]

            elif status_code == DbCodes.Skipped:
                msg = 'agent %s does not exist.' % (agent_id)

                results[ApiResultKeys.GENERIC_STATUS_CODE] = \
                    GenericFailureCodes.InvalidId
                results[ApiResultKeys.VFENSE_STATUS_CODE] = \
                    AgentFailureCodes.AgentsDoesNotExist
                results[ApiResultKeys.MESSAGE] = msg
                results[ApiResultKeys.DATA] = [agent_data]

            elif status_code == DbCodes.Errors:
                msg = 'operation failed' % (error)

                results[ApiResultKeys.GENERIC_STATUS_CODE] = \
                    GenericFailureCodes.FailedToUpdateObject
                results[ApiResultKeys.VFENSE_STATUS_CODE] = \
                    AgentFailureResultCodes.ResultsFailedToUpdate
                results[ApiResultKeys.MESSAGE] = msg

        else:
            msg = 'agent %s does not exist.' % (agent_id)

            results[ApiResultKeys.GENERIC_STATUS_CODE] = \
                    GenericFailureCodes.InvalidId
            results[ApiResultKeys.VFENSE_STATUS_CODE] = \
                    AgentFailureCodes.AgentsDoesNotExist
            results[ApiResultKeys.MESSAGE] = msg
            results[ApiResultKeys.DATA] = [agent_data]

    except Exception as e:
        logger.exception(e)
        msg = 'operation failed' % (error)

        results[ApiResultKeys.GENERIC_STATUS_CODE] = \
            GenericFailureCodes.FailedToUpdateObject
        results[ApiResultKeys.VFENSE_STATUS_CODE] = \
            AgentFailureResultCodes.ResultsFailedToUpdate
        results[ApiResultKeys.MESSAGE] = msg

    return results

@time_it
@results_message
def remove_all_agents_for_customer(
        customer_name,
        user_name=None, uri=None, method=None
    ):
    """Remove all agents from the system, filtered by customer_name
    Args:
        customer_name (str): The name of the customer.

    Kwargs:
        user_name (str): The name of the user who called this function.
        uri (str): The uri that was used to call this function.
        method (str): The HTTP methos that was used to call this function.

    Basic Usage:
        >>> from vFense.core.agent.agents import remove_all_agents_for_customer
        >>> customer_name = 'tester'
        >>> remove_all_agents_for_customer(customer_name)
    """
    status = remove_all_agents_for_customer.func_name + ' - '

    status_code, count, error, generated_ids = (
        delete_all_agents_for_customer(customer_name)
    )
    msg = 'total number of agents deleted: %s' % (str(count))
    if status_code == DbCodes.Deleted:
        generic_status_code = GenericCodes.ObjectDeleted
        vfense_status_code = AgentCodes.AgentsDeleted

    elif status_code == DbCodes.Skipped:
        generic_status_code = GenericCodes.DoesNotExist
        vfense_status_code = AgentFailureCodes.AgentsDoesNotExist

    elif status_code == DbCodes.DoesNotExist:
        generic_status_code = GenericCodes.DoesNotExist
        vfense_status_code = AgentFailureCodes.AgentsDoesNotExist

    elif status_code == DbCodes.Errors:
        generic_status_code = GenericFailureCodes.FailedToDeleteObject
        vfense_status_code = AgentFailureCodes.AgentsFailedToDelete

    results = {
        ApiResultKeys.DB_STATUS_CODE: status_code,
        ApiResultKeys.GENERIC_STATUS_CODE: generic_status_code,
        ApiResultKeys.VFENSE_STATUS_CODE: vfense_status_code,
        ApiResultKeys.MESSAGE: status + msg,
        ApiResultKeys.DATA: [],
        ApiResultKeys.USERNAME: user_name,
        ApiResultKeys.URI: uri,
        ApiResultKeys.HTTP_METHOD: method
    }

    return results

@time_it
@results_message
def change_customer_for_all_agents_in_customer(
        current_customer, new_customer,
        user_name=None, uri=None, method=None
    ):
    """Move all agents from one customer to another 
    Args:
        current_customer (str): The name of the current customer.
        new_customer (str): The name of the new customer.

    Kwargs:
        user_name (str): The name of the user who called this function.
        uri (str): The uri that was used to call this function.
        method (str): The HTTP methos that was used to call this function.

    Basic Usage:
        >>> from vFense.core.agent.agents import change_customer_for_all_agents_in_customer
        >>> current_customer = 'default'
        >>> new_customer = 'tester'
        >>> change_customer_for_all_agents_in_customer(current_customer, new_customer)
    """
    status = change_customer_for_agents.func_name + ' - '

    status_code, count, error, generated_ids = (
        move_all_agents_to_customer(current_customer, new_customer)
    )
    msg = 'total number of agents moved: %s' % (str(count))
    if status_code == DbCodes.Replaced:
        generic_status_code = GenericCodes.ObjectUpdated
        vfense_status_code = AgentCodes.AgentsUpdated

    elif status_code == DbCodes.Skipped or status_code == DbCodes.Unchanged:
        generic_status_code = GenericCodes.DoesNotExist
        vfense_status_code = AgentFailureCodes.AgentsDoesNotExist

    elif status_code == DbCodes.DoesNotExist:
        generic_status_code = GenericCodes.DoesNotExist
        vfense_status_code = AgentFailureCodes.AgentsDoesNotExist

    elif status_code == DbCodes.Errors:
        generic_status_code = GenericFailureCodes.FailedToUpdateObject
        vfense_status_code = AgentFailureCodes.AgentsFailedToUpdate

    results = {
        ApiResultKeys.DB_STATUS_CODE: status_code,
        ApiResultKeys.GENERIC_STATUS_CODE: generic_status_code,
        ApiResultKeys.VFENSE_STATUS_CODE: vfense_status_code,
        ApiResultKeys.MESSAGE: status + msg,
        ApiResultKeys.DATA: [],
        ApiResultKeys.USERNAME: user_name,
        ApiResultKeys.URI: uri,
        ApiResultKeys.HTTP_METHOD: method
    }

    return results

@time_it
@results_message
def change_customer_for_agents(
        agent_ids, new_customer,
        user_name=None, uri=None, method=None
    ):
    """Move a list of agents from one customer to another 
    Args:
        agent_ids (list): List of agent ids
        new_customer (str): The name of the new customer.

    Kwargs:
        user_name (str): The name of the user who called this function.
        uri (str): The uri that was used to call this function.
        method (str): The HTTP methos that was used to call this function.

    Basic Usage:
        >>> from vFense.core.agent.agents import change_customer_for_agents
        >>> new_customer = 'tester'
        >>> agent_ids = ['7f242ab8-a9d7-418f-9ce2-7bcba6c2d9dc']
        >>> change_customer_for_agents(agent_ids, new_customer)
    """
    status = change_customer_for_agents.func_name + ' - '

    status_code, count, error, generated_ids = (
        move_agents_to_customer(agent_ids, new_customer)
    )
    msg = 'total number of agents moved: %s' % (str(count))
    if status_code == DbCodes.Replaced:
        generic_status_code = GenericCodes.ObjectUpdated
        vfense_status_code = AgentCodes.AgentsUpdated

    elif status_code == DbCodes.Skipped or status_code == DbCodes.Unchanged:
        generic_status_code = GenericCodes.DoesNotExist
        vfense_status_code = AgentFailureCodes.AgentsDoesNotExist

    elif status_code == DbCodes.DoesNotExist:
        generic_status_code = GenericCodes.DoesNotExist
        vfense_status_code = AgentFailureCodes.AgentsDoesNotExist

    elif status_code == DbCodes.Errors:
        generic_status_code = GenericFailureCodes.FailedToUpdateObject
        vfense_status_code = AgentFailureCodes.AgentsFailedToUpdate

    results = {
        ApiResultKeys.DB_STATUS_CODE: status_code,
        ApiResultKeys.GENERIC_STATUS_CODE: generic_status_code,
        ApiResultKeys.VFENSE_STATUS_CODE: vfense_status_code,
        ApiResultKeys.MESSAGE: status + msg,
        ApiResultKeys.DATA: [],
        ApiResultKeys.USERNAME: user_name,
        ApiResultKeys.URI: uri,
        ApiResultKeys.HTTP_METHOD: method
    }

    return results

@time_it
@results_message
def change_customer_for_agent(
        agent_id, new_customer,
        user_name=None, uri=None, method=None
    ):
    """Move an agent from one customer to another 
    Args:
        agent_id (str): 36 character UUID of the agent.
        new_customer (str): The name of the new customer.

    Kwargs:
        user_name (str): The name of the user who called this function.
        uri (str): The uri that was used to call this function.
        method (str): The HTTP methos that was used to call this function.

    Basic Usage:
        >>> from vFense.core.agent.agents import change_customer_for_agent
        >>> new_customer = 'tester'
        >>> agent_id = '7f242ab8-a9d7-418f-9ce2-7bcba6c2d9dc'
        >>> change_customer_for_agent(agent_id, new_customer)
    """
    status = change_customer_for_agent.func_name + ' - '

    status_code, count, error, generated_ids = (
        move_agent_to_customer(agent_id, new_customer)
    )
    msg = 'total number of agents moved: %s' % (str(count))
    if status_code == DbCodes.Replaced:
        generic_status_code = GenericCodes.ObjectUpdated
        vfense_status_code = AgentCodes.AgentsUpdated

    elif status_code == DbCodes.Skipped or status_code == DbCodes.Unchanged:
        generic_status_code = GenericCodes.DoesNotExist
        vfense_status_code = AgentFailureCodes.AgentsDoesNotExist

    elif status_code == DbCodes.DoesNotExist:
        generic_status_code = GenericCodes.DoesNotExist
        vfense_status_code = AgentFailureCodes.AgentsDoesNotExist

    elif status_code == DbCodes.Errors:
        generic_status_code = GenericFailureCodes.FailedToUpdateObject
        vfense_status_code = AgentFailureCodes.AgentsFailedToUpdate

    results = {
        ApiResultKeys.DB_STATUS_CODE: status_code,
        ApiResultKeys.GENERIC_STATUS_CODE: generic_status_code,
        ApiResultKeys.VFENSE_STATUS_CODE: vfense_status_code,
        ApiResultKeys.MESSAGE: status + msg,
        ApiResultKeys.DATA: [],
        ApiResultKeys.USERNAME: user_name,
        ApiResultKeys.URI: uri,
        ApiResultKeys.HTTP_METHOD: method
    }

    return results
