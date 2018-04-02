import logging, logging.config
from vFense import VFENSE_LOGGING_CONFIG

from vFense.core.group import *
from vFense.core.group._constants import *
from vFense.core.decorators import return_status_tuple, time_it
from vFense.db.client import db_create_close, r

logging.config.fileConfig(VFENSE_LOGGING_CONFIG)
logger = logging.getLogger('rvapi')


@db_create_close
def fetch_group(group_id, conn=None):
    """Retrieve a group from the database
    Args:
        group_id: 36 Character UUID.

    Basic Usage:
        >>> from vFense.group._db import fetch_group
        >>> group_id = 'a7d4690e-5851-4d92-9626-07e16acaea1f'
        >>> fetch_group(group_id)

    Returns:
        Returns a Dict of the properties of a group
        {
            u'group_name': u'Administrator',
            u'customer_name': u'default',
            u'id': u'8757b79c-7321-4446-8882-65457f28c78b',
            u'Permissions': [
                u'administrator'
            ]
        }
    """
    data = {}
    try:
        data = (
            r
            .table(GroupCollections.Groups)
            .get(group_id)
            .run(conn)
        )

    except Exception as e:
        logger.exception(e)

    return(data)


@db_create_close
def fetch_group_properties(group_id, conn=None):
    """Retrieve a group and all of its properties.
    Args:
        group_id: 36 Character UUID.

    Basic Usage:
        >>> from vFense.group._db import fetch_group_properties
        >>> group_id = 'a7d4690e-5851-4d92-9626-07e16acaea1f'
        >>> fetch_group_properties(group_id)

    Returns:
        Returns a Dict of the properties of a group
        {
            "users": [
                {
                    "user_name": "admin"
                }, 
                {
                    "user_name": "agent_api"
                }
            ], 
            "permissions": [
                "administrator"
            ], 
            "group_name": "Administrator", 
            "id": "1b74a706-34e5-482a-bedc-ffbcd688f066", 
            "customer_name": "default"
        }
    """
    map_hash = (lambda x:
        {
            GroupKeys.GroupId: x[GroupKeys.GroupId],
            GroupKeys.GroupName: x[GroupKeys.GroupName],
            GroupKeys.CustomerName: x[GroupKeys.CustomerName],
            GroupKeys.Permissions: x[GroupKeys.Permissions],
            GroupKeys.Users: (
                r
                .table(GroupCollections.GroupsPerUser)
                .get_all(group_id, index=GroupsPerUserIndexes.GroupId)
                .coerce_to('array')
                .pluck(GroupsPerUserKeys.UserName)
            )
        }
    )
    data = {}
    try:
        data = (
            r
            .table(GroupCollections.Groups)
            .get_all(group_id)
            .map(map_hash)
            .run(conn)
        )
        if data:
            data = data[0]

    except Exception as e:
        logger.exception(e)

    return(data)

@db_create_close
def fetch_properties_for_all_groups(customer_name=None, conn=None):
    """Retrieve properties for all groupcs.
    Kwargs:
        customer_name: Name of the customer, which the group is part of.

    Basic Usage:
        >>> from vFense.group._db import fetch_properties_for_all_groups
        >>> customer_name = 'test'
        >>> fetch_properties_for_all_groups(customer_name)

    Returns:
        Returns a List of a groups and their properties.
        [
            {
                "users": [
                    {
                        "user_name": "admin"
                    }, 
                    {
                        "user_name": "agent_api"
                    }
                ], 
                "permissions": [
                    "install", 
                    "uninstall"
                ], 
                "group_name": "JR ADMIN", 
                "id": "2171dff9-cf6d-4deb-9da3-18434acbd1c7", 
                "customer_name": "Test"
            }, 
        ]
    """
    map_hash = (lambda x:
        {
            GroupKeys.GroupId: x[GroupKeys.GroupId],
            GroupKeys.GroupName: x[GroupKeys.GroupName],
            GroupKeys.CustomerName: x[GroupKeys.CustomerName],
            GroupKeys.Permissions: x[GroupKeys.Permissions],
            GroupKeys.Users: (
                r
                .table(GroupCollections.GroupsPerUser)
                .get_all(
                    x[GroupKeys.GroupId],
                    index=GroupsPerUserIndexes.GroupId
                )
                .coerce_to('array')
                .pluck(GroupsPerUserKeys.UserName)
            )
        }
    )
    data = {}
    try:
        if customer_name:
            data = list(
                r
                .table(GroupCollections.Groups)
                .get_all(customer_name, index=GroupsPerUserIndexes.CustomerName)
                .map(map_hash)
                .run(conn)
            )

        else:
            data = list(
                r
                .table(GroupCollections.Groups)
                .map(map_hash)
                .run(conn)
            )

    except Exception as e:
        logger.exception(e)

    return(data)


@time_it
@db_create_close
def fetch_group_by_name(
    group_name, customer_name,
    fields_to_pluck=None, conn=None):
    """Retrieve a group by its name from the database
    Args:
        group_name (str): Name of group.
        customer_name (str): name of the customer, that the group belongs to.
    
    Kwargs:
        fields_to_pluck (list): List of fields you want to retrieve.

    Basic Usage:
        >>> from vFense.group._db import fetch_group_by_name
        >>> group_name = 'Administrator'
        >>> customer_name = 'default'
        >>> fetch_group_by_name(group_name, customer_name)

    Returns:
        Returns a Dict of the properties of a customer
        {
            u'group_name': u'Administrator',
            u'customer_name': u'default',
            u'id': u'8757b79c-7321-4446-8882-65457f28c78b',
            u'Permissions': [
                u'administrator'
            ]
        }
    """
    try:
        if fields_to_pluck:
            data = list(
                r
                .table(GroupCollections.Groups)
                .filter(
                    {
                        GroupKeys.GroupName: group_name,
                        GroupKeys.CustomerName: customer_name
                    }
                )
                .pluck(fields_to_pluck)
                .run(conn)
            )
        else:
            data = list(
                r
                .table(GroupCollections.Groups)
                .filter(
                    {
                        GroupKeys.GroupName: group_name,
                        GroupKeys.CustomerName: customer_name
                    }
                )
                .run(conn)
            )

        if len(data) == 1:
            data = data[0]

    except Exception as e:
        logger.exception(e)
        data = {}

    return(data)


@time_it
@db_create_close
def fetch_users_in_group(group_id, fields_to_pluck=None, conn=None):
    """Fetch all users for group_id
    Args:
        group_id (str): 36 Character UUID

    Kwargs:
        fields_to_pluck (list): List of fields you want to
        pluck from the database.

    Basic Usage:
        >>> from vFense.group._db import fetch_users_in_group
        >>> group_id = 'a7d4690e-5851-4d92-9626-07e16acaea1f'
        >>> fetch_users_in_group(group_id, [GroupsPerUserKeys.UserName])

    Returns:
        Returns a list of users
        [
            {
                u'user_name': u'testing123'
            },
            {
                u'user_name': u'tester'
            },
            {
                u'user_name': u'testing'
            }
        ]
    """
    data = []
    try:
        if fields_to_pluck:
            data = list(
                r
                .table(GroupCollections.GroupsPerUser)
                .get_all(group_id, index=GroupsPerUserIndexes.GroupId)
                .pluck(fields_to_pluck)
                .run(conn)
            )
        else:
            data = list(
                r
                .table(GroupCollections.GroupsPerUser)
                .get_all(group_id, index=GroupsPerUserIndexes.GroupId)
                .run(conn)
            )

    except Exception as e:
        logger.exception(e)

    return(data)


@time_it
@db_create_close
def fetch_groups_for_user(username, fields_to_pluck=None, conn=None):
    """Retrieve all groups for a user by username
    Args:
        username (str): Get all groups for which this user is part of.

    Kwargs:
        fields_to_pluck (list): List of fields you want to pluck
        from the database

    Basic Usage:
        >>> from vFense.group._db import fetch_groups_for_user
        >>> username = 'alien'
        >>> fetch_groups_for_user(username)

    Returns:
        Returns a list of groups that the user belongs to.
        [
            {
                u'group_name': u'FooLah',
                u'group_id': u'0834e656-27a5-4b13-ba56-635797d0d1fc',
                u'user_name': u'alien',
                u'id': u'ee54820c-cb4e-46a1-9d11-73afe8c4c4e3',
                u'customer_name': u'default'
            },
            {
                u'group_name': u'Administrator',
                u'group_id': u'8757b79c-7321-4446-8882-65457f28c78b',
                u'user_name': u'alien',
                u'id': u'6bd51a04-fcec-46a7-bbe1-48c6221115ec',
                u'customer_name': u'default'
            }
        ]
    """
    data = []
    try:
        if username and not fields_to_pluck:
            data = list(
                r
                .table(GroupCollections.GroupsPerUser)
                .get_all(username, index=GroupsPerUserIndexes.UserName)
                .run(conn)
            )

        elif username and fields_to_pluck:
            data = list(
                r
                .table(GroupCollections.GroupsPerUser)
                .get_all(username, index=GroupsPerUserIndexes.UserName)
                .pluck(fields_to_pluck)
                .run(conn)
            )

    except Exception as e:
        logger.exception(e)

    return(data)

@time_it
@db_create_close
def user_exist_in_group(username, group_id, conn=None):
    """Return True if and user is part of group_id
    Args:
        username (str): username.
        group_id (str): 36 Character UUID

    Basic Usage:
        >>> from vFense.group._db import user_exist_in_group
        >>> username = 'alien'
        >>> group_id = '0834e656-27a5-4b13-ba56-635797d0d1fc'
        >>> user_exist_in_group(username, group_id)

    Returns:
        Returns a boolean True or False
    """
    exist = False
    try:
        is_empty = (
            r
            .table(GroupCollections.GroupsPerUser)
            .get_all(username, index=GroupsPerUserIndexes.UserName)
            .filter({GroupsPerUserKeys.GroupId: group_id})
            .is_empty()
            .run(conn)
        )

        if not is_empty:
            exist = True

    except Exception as e:
        logger.exception(e)

    return(exist)


@time_it
@db_create_close
def usernames_exist_in_group_id(usernames, group_id, conn=None):
    """Return True if and user is part of group_id
    Args:
        usernames (list): List of usernames.
        group_id (str): 36 Character UUID

    Basic Usage:
        >>> from vFense.group._db import users_exist_in_group
        >>> usernames = ['alien', 'tester']
        >>> group_id = '0834e656-27a5-4b13-ba56-635797d0d1fc'
        >>> users_exist_in_group(usernames, group_id)

    Returns:
        Returns a boolean True or False
    """
    exist = False
    try:
        for username in usernames:
            is_empty = (
                r
                .table(GroupCollections.GroupsPerUser)
                .get_all(username, index=GroupsPerUserIndexes.UserName)
                .filter({GroupsPerUserKeys.GroupId: group_id})
                .is_empty()
                .run(conn)
            )
            if not is_empty:
                exist = True

    except Exception as e:
        logger.exception(e)

    return(exist)


@time_it
@db_create_close
def users_exist_in_group_ids(group_ids, conn=None):
    """Return True if and user is part of group_id
    Args:
        group_ids (list): List of group ids.

    Basic Usage:
        >>> from vFense.group._db import users_exist_in_group_ids
        >>> group_ids = ['0834e656-27a5-4b13-ba56-635797d0d1fc']
        >>> users_exist_in_group(group_ids)

    Returns:
        Returns a boolean True or False
    """
    exist = False
    try:
        for group_id in group_ids:
            is_empty = (
                r
                .table(GroupCollections.GroupsPerUser)
                .get_all(group_id, index=GroupsPerUserIndexes.GroupId)
                .is_empty()
                .run(conn)
            )
            if not is_empty:
                exist = True

    except Exception as e:
        logger.exception(e)

    return(exist)


@time_it
@db_create_close
def fetch_groups(
    customer_name=None, groupname=None,
    fields_to_pluck=None, conn=None
    ):
    """Retrieve all groups that is in the database by customer_name or
        all of the groups or by regex.

    Kwargs:
        customer_name (str):  Name of the customer,
        groupname (str):  Name of the group you are searching for.
            This is a regular expression match.
        fields_to_pluck (list):  List of fields you want to pluck
        from the database

    Basic Usage:
        >>> from vFense.group._db import fetch_groups
        >>> customer_name = 'default'
        >>> groupname = 'fo'
        >>> fetch_groups(customer_name, groupname)

    Returns:
        Returns a Dict of the properties of a group
        [
            {
                u'group_name': u'FooLee',
                u'customer_name': u'default',
                u'id': u'5215a906-4b05-46fa-b0fc-4f55f974ebbc',
                u'Permissions': [
                    u'shutdown',
                    u'reboot'
                ]
                                                
            },
            {
                u'group_name': u'FooLah',
                u'customer_name': u'default',
                u'id': u'1fbdd995-1a6b-4dc8-80a4-9ed23e32864e',
                u'Permissions': [
                    u'install',
                    u'uninstall'
                ]
            }
        ]
    """
    data = []
    try:
        if not customer_name and not groupname and not fields_to_pluck:
            data = list(
                r
                .table(GroupCollections.Groups)
                .run(conn)
            )

        elif not customer_name and not groupname and fields_to_pluck:
            data = list(
                r
                .table(GroupCollections.Groups)
                .pluck(fields_to_pluck)
                .run(conn)
            )

        elif not customer_name and groupname and not fields_to_pluck:
            data = list(
                r
                .table(GroupCollections.Groups)
                .filter(
                    lambda x:
                    x[GroupKeys.GroupName].match("(?i)" + groupname)
                )
                .run(conn)
            )

        elif not customer_name and groupname and fields_to_pluck:
            data = list(
                r
                .table(GroupCollections.Groups)
                .filter(
                    lambda x:
                    x[GroupKeys.GroupName].match("(?i)" + groupname)
                )
                .pluck(fields_to_pluck)
                .run(conn)
            )

        elif customer_name and not groupname and not fields_to_pluck:
            data = list(
                r
                .table(GroupCollections.Groups)
                .get_all(
                    customer_name, index=GroupIndexes.CustomerName
                )
                .run(conn)
            )

        elif customer_name and not groupname and fields_to_pluck:
            data = list(
                r
                .table(GroupCollections.Groups)
                .get_all(
                    customer_name, index=GroupIndexes.CustomerName
                )
                .pluck(fields_to_pluck)
                .run(conn)
            )

        elif customer_name and groupname and not fields_to_pluck:
            data = list(
                r
                .table(GroupCollections.Groups)
                .get_all(
                    customer_name, index=GroupIndexes.CustomerName
                )
                .filter(
                    lambda x:
                    x[GroupKeys.GroupName].match("(?i)" + groupname)
                )
                .run(conn)
            )

        elif customer_name and groupname and fields_to_pluck:
            data = list(
                r
                .table(GroupCollections.Groups)
                .get_all(
                    customer_name, index=GroupIndexes.CustomerName
                )
                .filter(
                    lambda x:
                    x[GroupKeys.GroupName].match("(?i)" + groupname)
                )
                .pluck(fields_to_pluck)
                .run(conn)
            )

    except Exception as e:
        logger.exception(e)

    return(data)


@time_it
@db_create_close
@return_status_tuple
def insert_group(group_data, conn=None):
    """ Insert a new group into the database
    Args:
        group_data (list|dict): Can either be a list of dictionaries or a dictionary
        of the data you are inserting.

    Basic Usage:
        >>> from vFense.group._db import insert_group
        >>> group_data = {'customer_name': 'vFense', 'needs_reboot': 'no'}
        >>> insert_group(group_data)

    Return:
        Tuple (status_code, count, error, generated ids)
        >>> (2001, 1, None, [])
    """
    data = {}
    try:
        data = (
            r
            .table(GroupCollections.Groups)
            .insert(group_data)
            .run(conn)
        )

    except Exception as e:
        logger.exception(e)

    return(data)


@time_it
@db_create_close
@return_status_tuple
def insert_group_per_user(group_data, conn=None):
    """Add a group to a user, this function should not be called directly.
    Args:
        group_data (list|dict): Can either be a list of dictionaries or a dictionary
        of the data you are inserting.

    Basic Usage:
        >>> from vFense.group._db import insert_group_per_user
        >>> group_data = {'customer_name': 'vFense', 'needs_reboot': 'no'}
        >>> insert_group_per_user(group_data)

    Return:
        Tuple (status_code, count, error, generated ids)
        >>> (2001, 1, None, [])
    """
    data = {}
    try:
        data = (
            r
            .table(GroupCollections.GroupsPerUser)
            .insert(group_data)
            .run(conn)
        )

    except Exception as e:
        logger.exception(e)

    return(data)


@time_it
@db_create_close
@return_status_tuple
def update_group(group_id, group_data, conn=None):
    """Update verious fields of a group
    Args:
        group_idi (str): group id  of the group you are updateing.

    Basic Usage::
        >>> from vFense.group._db import update_group
        >>> group_id = 'd081a343-cc6c-4f08-81d9-62a116fda025'
        >>> data = {'production_level': 'Development', 'needs_reboot': 'no'}
        >>> update_group(group_id)

    Return:
        Tuple (status_code, count, error, generated ids)
        >>> (2001, 1, None, [])
    """
    data = {}
    try:
        data = (
            r
            .table(GroupCollections.Groups)
            .get(group_id)
            .update(group_data)
            .run(conn)
        )

    except Exception as e:
        logger.exception(e)

    return(data)


@time_it
@db_create_close
@return_status_tuple
def delete_groups_from_user(username, group_ids=None, conn=None):
    """Remove a group from a user or remove all groups for a user.
    Args:
        username (str): Name of the user.

    Kwargs:
        group_ids(list): List of group_ids

    Basic Usage::
        >>> from vFense.group._db delete_groups_from_user
        >>> username = 'agent_api'
        >>> delete_groups_from_user(username)

    Return:
        Tuple (status_code, count, error, generated ids)
        >>> (2001, 1, None, [])
    """
    data = {}
    try:
        if group_ids:
            data = (
                r
                .expr(group_ids)
                .for_each(
                    lambda group_id:
                    r
                    .table(GroupCollections.GroupsPerUser)
                    .filter(
                        {
                            GroupsPerUserKeys.UserName: username,
                            GroupsPerUserKeys.GroupId: group_id
                        }
                    )
                    .delete()
                )
                .run(conn)
            )

        else:
            data = (
                r
                .table(GroupCollections.GroupsPerUser)
                .filter(
                    {
                        GroupsPerUserKeys.UserName: username,
                    }
                )
                .delete()
                .run(conn)
            )

    except Exception as e:
        logger.exception(e)

    return(data)


@time_it
@db_create_close
@return_status_tuple
def delete_users_in_group(usernames, group_id, conn=None):
    """Remove a group from a user or remove all groups for a user.
    Args:
        usernames (list): Name of the users.
        group_id (str): 36 character group UUID

    Basic Usage::
        >>> from vFense.group._db delete_users_from_group
        >>> usernames = ['agent_api']
        >>> delete_users_from_group(usernames, group_id)

    Return:
        Tuple (status_code, count, error, generated ids)
        >>> (2001, 1, None, [])
    """
    data = {}
    try:
        data = (
            r
            .expr(usernames)
            .for_each(
                lambda username:
                    r
                    .table(GroupCollections.GroupsPerUser)
                    .filter(
                        {
                            GroupsPerUserKeys.UserName: username,
                            GroupsPerUserKeys.GroupId: group_id
                        }
                    )
                    .delete()
                )
                .run(conn)
            )

    except Exception as e:
        logger.exception(e)

    return(data)


@time_it
@db_create_close
@return_status_tuple
def delete_group(group_id, conn=None):
    """Delete a group from the database.
    Args:
        group_id (str): group id of the group you are deleteing

    Basic Usage::
        >>> from vFense.group._db import delete_group
        >>> group_id = 'd081a343-cc6c-4f08-81d9-62a116fda025'
        >>> delete_group(group_id)

    Return:
        Tuple (status_code, count, error, generated ids)
        >>> (2001, 1, None, [])
    """
    data = {}
    try:

        data = (
            r
            .table(GroupCollections.Groups)
            .get(group_id)
            .delete()
            .run(conn)
        )

    except Exception as e:
        logger.exception(e)

    return(data)


@time_it
@db_create_close
@return_status_tuple
def delete_groups(group_ids, conn=None):
    """Delete a group from the database.
    Args:
        group_ids (list): group ids of the group you are deleteing

    Basic Usage::
        >>> from vFense.group._db import delete_groups
        >>> group_ids = ['d081a343-cc6c-4f08-81d9-62a116fda025']
        >>> delete_groups(group_ids)

    Return:
        Tuple (status_code, count, error, generated ids)
        >>> (2001, 1, None, [])
    """
    data = {}
    try:

        data = (
            r
            .expr(group_ids)
            .for_each(
                lambda group_id:
                r
                .table(GroupCollections.Groups)
                .get(group_id)
                .delete()
            )
            .run(conn)
        )

    except Exception as e:
        logger.exception(e)

    return(data)


@time_it
@db_create_close
@return_status_tuple
def delete_groups_from_customer(customer_name, conn=None):
    """Delete groups that belong to a customer.
    Args:
        customer_name (str): the name of the customer, that the groups belong too.

    Basic Usage::
        >>> from vFense.group._db import delete_groups_from_customer
        >>> customer_name = 'test'
        >>> delete_groups_from_customer(customer_name)

    Return:
        Tuple (status_code, count, error, generated ids)
        >>> (2001, 1, None, [])
    """
    data = {}
    try:

        data = (
            r
            .table(GroupCollections.Groups)
            .get_all(customer_name, index=GroupIndexes.CustomerName)
            .delete()
            .run(conn)
        )

    except Exception as e:
        logger.exception(e)

    return(data)
