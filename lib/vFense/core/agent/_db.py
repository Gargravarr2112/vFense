import logging

from vFense import VFENSE_LOGGING_CONFIG
from vFense.db.client import db_create_close, r
from vFense.core.agent import AgentCollections, \
    AgentIndexes, AgentKeys
from vFense.core.agent._db_sub_queries import Merge
#from vFense.core.tag import *
#from vFense.plugins.patching import *
from vFense.core.decorators import return_status_tuple, time_it

logging.config.fileConfig(VFENSE_LOGGING_CONFIG)
logger = logging.getLogger('rvapi')


@time_it
@db_create_close
def fetch_production_levels_from_agent(customer_name, conn=None):
    """Retrieve all the production levels that is in the database
    Args:
        customer_name (str): Name of the customer, where the agent is located

    Basic Usage:
        >>> from vFense.core.agent._db import fetch_production_levels_from_agent
        >>> customer_name = 'default'
        >>> fetch_production_levels_from_agent(customer_name)

    Returns:
        List of Production levels in the system
        [
            u'Development',
            u'Production'
        ]
    """
    data = []
    try:
        data = (
            r
            .table(AgentCollections.Agents)
            .get_all(customer_name, index=AgentIndexes.CustomerName)
            .pluck(AgentKeys.ProductionLevel)
            .distinct()
            .map(lambda x: x[AgentKeys.ProductionLevel])
            .run(conn)
        )

    except Exception as e:
        logger.exception(e)

    return data

@time_it
@db_create_close
def total_agents_in_customer(customer_name, conn=None):
    """Retrieve the total number of agents in customer.
    Args:
        customer_name (str): Name of the customer, where the agent is located

    Basic Usage:
        >>> from vFense.core.agent._db import total_agents_in_customer
        >>> customer_name = 'default'
        >>> total_agents_in_customer(customer_name)

    Returns:
        Integer
    """
    count = 0
    try:
        count = (
            r
            .table(AgentCollections.Agents)
            .get_all(customer_name, index=AgentIndexes.CustomerName)
            .count()
            .run(conn)
        )

    except Exception as e:
        logger.exception(e)

    return count

@time_it
@db_create_close
def fetch_supported_os_strings(customer_name, conn=None):
    """Retrieve all the operating systems that is in the database
    Args:
        customer_name (str): Name of the customer, where the agent is located

    Basic Usage:
        >>> from vFense.core.agent._db import fetch_supported_os_strings
        >>> customer_name = 'default'
        >>> fetch_supported_os_strings(customer_name)

    Returns:
        List of available operating system strings in the database
        [
            u'CentOS 6.5',
            u'Ubuntu 12.04',
            u'Windows 7 Professional Service Pack 1',
            u'Windows 8.1 '
        ]
    """
    data = []
    try:
        data = (
            r
            .table(AgentCollections.Agents)
            .get_all(customer_name, index=AgentIndexes.CustomerName)
            .pluck(AgentKeys.OsString)
            .distinct()
            .map(lambda x: x[AgentKeys.OsString])
            .run(conn)
        )

    except Exception as e:
        logger.exception(e)

    return data

@time_it
@db_create_close
def fetch_agent_ids(customer_name=None, agent_os=None, conn=None):
    """Retrieve a list of agent ids
    Kwargs:
        customer_name (str): Name of the customer, where the agent is located
        agent_os (str):  The os code you are filtering on.
            (linux or windows or darwin)

    Basic Usage:
        >>> from vFense.core.agent._db import fetch_agent_ids
        >>> customer_name = 'default'
        >>> os_code = 'os_code'
        >>> fetch_agent_ids(customer_name, os_code)

    Returns:
        List of agent ids
        [
            u'52faa1db-290a-47a7-a4cf-e4ad70e25c38',
            u'3ea8fd7a-8aad-40da-aff0-8da6fa5f8766'
        ]
    """
    data = []
    try:
        if customer_name and agent_os:
            data = list(
                r
                .table(AgentCollections.Agents)
                .get_all(customer_name, index=AgentIndexes.CustomerName)
                .filter({AgentKeys.OsCode: agent_os})
                .map(lambda x: x[AgentKeys.AgentId])
                .run(conn)
            )

        elif customer_name and not agent_os:
            data = list(
                r
                .table(AgentCollections.Agents)
                .get_all(customer_name, index=AgentIndexes.CustomerName)
                .map(lambda x: x[AgentKeys.AgentId])
                .run(conn)
            )

        elif agent_os and not customer_name:
            data = list(
                r
                .table(AgentCollections.Agents)
                .filter({AgentKeys.OsCode: agent_os})
                .map(lambda x: x[AgentKeys.AgentId])
                .run(conn)
            )

        elif not agent_os and not customer_name:
            data = list(
                r
                .table(AgentCollections.Agents)
                .map(lambda x: x[AgentKeys.AgentId])
                .run(conn)
            )

    except Exception as e:
        logger.exception(e)

    return data

@time_it
@db_create_close
def fetch_agents(
        customer_name=None, filter_key=None,
        filter_val=None, keys_to_pluck=None,
        conn=None
    ):
    """Retrieve all agents by any key in the agent collection
    Kwargs:
        customer_name (str): Name of the customer, where the agent is located
        filter_key (str): The name of the key that you are filtering on.
        filter_val (str):  The value that you are searching for.
        keys_to_pluck (list): Specific keys that you are retrieving from the database

    Basic Usage:
        >>> from vFense.core.agent._db import fetch_agents
        >>> key = 'os_code'
        >>> val = 'linux'
        >>> pluck = ['computer_name', 'agent_id']
        >>> fetch_agents(customer_name, key, val, pluck)

    Return:
        List of agents
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
    data = []
    try:
        if (
                filter_key and filter_val and not customer_name
                and not keys_to_pluck
            ):

            data = list(
                r
                .table(AgentCollections.Agents)
                .filter({filter_key: filter_val})
                .merge(Merge.TAGS)
                .run(conn)
            )

        elif filter_key and filter_val and customer_name and not keys_to_pluck:

            data = list(
                r
                .table(AgentCollections.Agents)
                .get_all(customer_name, index=AgentIndexes.CustomerName)
                .filter({filter_key: filter_val})
                .merge(Merge.TAGS)
                .run(conn)
            )

        elif filter_key and filter_val and keys_to_pluck and not customer_name:

            data = list(
                r
                .table(AgentCollections.Agents)
                .filter({filter_key: filter_val})
                .merge(Merge.TAGS)
                .pluck(keys_to_pluck)
                .run(conn)
            )

        elif filter_key and filter_val and keys_to_pluck and customer_name:

            data = list(
                r
                .table(AgentCollections.Agents)
                .get_all(customer_name, index=AgentIndexes.CustomerName)
                .filter({filter_key: filter_val})
                .merge(Merge.TAGS)
                .pluck(keys_to_pluck)
                .run(conn)
            )

        elif (
                not filter_key and not filter_val
                and not customer_name and keys_to_pluck
            ):

            data = list(
                r
                .table(AgentCollections.Agents)
                .merge(Merge.TAGS)
                .pluck(keys_to_pluck)
                .run(conn)
            )

        elif (
                not filter_key and not filter_val
                and customer_name and keys_to_pluck
            ):

            data = list(
                r
                .table(AgentCollections.Agents)
                .get_all(customer_name, index=AgentIndexes.CustomerName)
                .merge(Merge.TAGS)
                .pluck(keys_to_pluck)
                .run(conn)
            )

        elif (
                not filter_key and not filter_val
                and not customer_name and not keys_to_pluck
            ):

            data = list(
                r
                .table(AgentCollections.Agents)
                .merge(Merge.TAGS)
                .run(conn)
            )

        elif (
                not filter_key and not filter_val
                and customer_name and not keys_to_pluck
            ):

            data = list(
                r
                .table(AgentCollections.Agents)
                .get_all(customer_name, index=AgentIndexes.CustomerName)
                .merge(Merge.TAGS)
                .run(conn)
            )

    except Exception as e:
        logger.exception(e)

    return data

@time_it
@db_create_close
def fetch_agent_info(agent_id, keys_to_pluck=None, conn=None):
    """Retrieve information of an agent
    Args:
        agent_id(str): 36 character uuid of the agent you are updating

    Kwargs:
        keys_to_pluck(list): (Optional) Specific keys that you are retrieving
        from the database

    Basic Usage:
        >>> from vFense.core.agent._db import fetch_agent_info
        >>> agent_id = '52faa1db-290a-47a7-a4cf-e4ad70e25c38'
        >>> keys_to_pluck = ['production_level', 'needs_reboot']
        >>> fetch_agent_info(agent_id, keys_to_pluck)

    Return:
        Dictionary of the agent data
        {
            u'agent_id': u'52faa1db-290a-47a7-a4cf-e4ad70e25c38',
            u'production_level': u'Development'
        }
    """
    data = {}
    try:
        if agent_id and keys_to_pluck:
            data = (
                r
                .table(AgentCollections.Agents)
                .get(agent_id)
                .merge(Merge.TAGS)
                .pluck(keys_to_pluck)
                .run(conn)
            )

        elif agent_id and not keys_to_pluck:
            data = (
                r
                .table(AgentCollections.Agents)
                .get(agent_id)
                .merge(Merge.TAGS)
                .run(conn)
            )

    except Exception as e:
        logger.exception(e)

    return data

@time_it
@db_create_close
@return_status_tuple
def fetch_all_agents_for_customer(customer_name, conn=None):
    """Retrieve all agents for a customer.
    Args:
        customer_name (str): Name of the customer.

    Basic Usage:
        >>> from vFense.agent._db import fetch_all_agents_for_customer
        >>> customer_name = 'test'
        >>> fetch_all_agents_for_customer(customer_nam)

    Return:
        List of dictionaries.
    """
    data = []
    try:
        data = list(
            r
            .table(AgentCollections.Agents)
            .get_all(customer_name, index=AgentIndexes.CustomerName)
            .run(conn)
        )

    except Exception as e:
        logger.exception(e)

    return data

@time_it
@db_create_close
@return_status_tuple
def update_agent_data(agent_id, agent_data, conn=None):
    """Update Agent data
    Args:
        agent_id (str): 36 character uuid of the agent you are updating
        agent_data(list|dict): Dictionary of the data you are updating

    Basic Usage::
        >>> from vFense.core.agent._db import update_agent_data
        >>> agent_id = '0a1f9a3c-9200-42ef-ba63-f4fd17f0644c'
        >>> data = {'production_level': 'Development', 'needs_reboot': 'no'}
        >>> update_agent(agent_id, data)

    Return:
        Tuple (status_code, count, error, generated ids)
        >>> (2001, 1, None, [])
    """
    data = {}
    try:
        data = (
            r
            .table(AgentCollections.Agents)
            .get(agent_id)
            .update(agent_data)
            .run(conn)
        )

    except Exception as e:
        logger.exception(e)

    return data

@time_it
@db_create_close
@return_status_tuple
def insert_agent_data(agent_data, conn=None):
    """ Insert a new agent and its properties into the database
        This function should not be called directly.
    Args:
        agent_data (list|dict): Can either be a list of
            dictionaries or a dictionary of the data
            you are inserting.

    Basic Usage:
        >>> from vFense.core.agent._db import insert_agent_data
        >>> agent_data = {'customer_name': 'vFense', 'needs_reboot': 'no'}
        >>> insert_agent_data(agent_data)

    Return:
        Tuple (status_code, count, error, generated ids)
        >>> (2001, 1, None, [])
    """
    data = {}
    try:
        data = (
            r
            .table(AgentCollections.Agents)
            .insert(agent_data)
            .run(conn)
        )

    except Exception as e:
        logger.exception(e)

    return data

@time_it
@db_create_close
@return_status_tuple
def delete_all_agents_for_customer(customer_name, conn=None):
    """Retrieve a user from the database
    Args:
        customer_name (str): Name of the customer.

    Basic Usage:
        >>> from vFense.agent._db import delete_all_agents_for_customer
        >>> customer_name = 'test'
        >>> delete_all_agents_for_customer(customer_nam)

    Return:
        Tuple (status_code, count, error, generated ids)
        >>> (2001, 1, None, [])
    """
    data = {}
    try:
        data = (
            r
            .table(AgentCollections.Agents)
            .get_all(customer_name, index=AgentIndexes.CustomerName)
            .delete()
            .run(conn)
        )

    except Exception as e:
        logger.exception(e)

    return data

@time_it
@db_create_close
@return_status_tuple
def move_all_agents_to_customer(current_customer, new_customer, conn=None):
    """Move all agents in current customer to the new customer.
    Args:
        current_customer (str): Name of the current customer.
        new_customer (str): Name of the new customer.

    Basic Usage:
        >>> from vFense.agent._db import move_all_agents_to_customer
        >>> current_customer = 'default'
        >>> new_customer = 'test'
        >>> move_all_agents_to_customer(current_customer, new_customer)

    Returns:
        Tuple (status_code, count, error, generated ids)
        >>> (2001, 1, None, [])
    """
    data = {}
    try:
        data = (
            r
            .table(AgentCollections.Agents)
            .get_all(current_customer, index=AgentIndexes.CustomerName)
            .update(
                {
                    AgentKeys.CustomerName: new_customer
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
def move_agents_to_customer(agent_ids, new_customer, conn=None):
    """Move a list of agents into another customer
    Args:
        agent_ids (list): List of agent ids
        new_customer (str): Name of the new customer.

    Basic Usage:
        >>> from vFense.agent._db import move_agents_to_customer
        >>> new_customer = 'test'
        >>> agent_ids = ['7f242ab8-a9d7-418f-9ce2-7bcba6c2d9dc']
        >>> move_agents_to_customer(agent_ids, new_customer)

    Returns:
        Tuple (status_code, count, error, generated ids)
        >>> (2001, 1, None, [])
    """
    data = {}
    try:
        data = (
            r
            .expr(agent_ids)
            .for_each(
                lambda agent_id:
                r
                .table(AgentCollections.Agents)
                .get(agent_id)
                .update(
                    {
                        AgentKeys.CustomerName: new_customer
                    }
                )
            )
            .run(conn)
        )

    except Exception as e:
        logger.exception(e)

    return data

@time_it
@db_create_close
@return_status_tuple
def move_agent_to_customer(agent_id, new_customer, conn=None):
    """Move an agent into another customer
    Args:
        agent_id (str): The 36 character UUID of an agent.
        new_customer (str): Name of the new customer.

    Basic Usage:
        >>> from vFense.agent._db import move_agent_to_customer
        >>> new_customer = 'test'
        >>> agent_id = '7f242ab8-a9d7-418f-9ce2-7bcba6c2d9dc'
        >>> move_agent_to_customer(agent_id, new_customer)

    Returns:
        Tuple (status_code, count, error, generated ids)
        >>> (2001, 1, None, [])
    """
    data = {}
    try:
        data = (
            r
            .table(AgentCollections.Agents)
            .get(agent_id)
            .update(
                {
                    AgentKeys.CustomerName: new_customer
                }
            )
            .run(conn)
        )

    except Exception as e:
        logger.exception(e)

    return data
