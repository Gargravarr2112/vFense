import re
import logging, logging.config
from vFense import VFENSE_LOGGING_CONFIG
from vFense.core._constants import *
from vFense.core.group import *
from vFense.core.group._constants import *
from vFense.core.user import *
from vFense.core.user._constants import *
from vFense.core.customer import *
from vFense.core.customer._constants import *
from vFense.core.permissions._constants import *
from vFense.core._db import retrieve_object
from vFense.core.group._db import insert_group, fetch_group, fetch_groups, \
    insert_group_per_user, fetch_group_by_name, delete_groups_from_user, \
    fetch_users_in_group, fetch_groups_for_user, delete_group, \
    fetch_properties_for_all_groups, fetch_group_properties, \
    user_exist_in_group, users_exist_in_group_ids, delete_groups

from vFense.core.decorators import results_message, time_it
from vFense.errorz.status_codes import *
from vFense.errorz._constants import *

logging.config.fileConfig(VFENSE_LOGGING_CONFIG)
logger = logging.getLogger('rvapi')


@time_it
def get_group(group_id):
    """Retrieve a group from the database
    Args:
        group_id: 36 Character UUID.

    Basic Usage:
        >>> from vFense.group.groups import get_group
        >>> group_id = '8757b79c-7321-4446-8882-65457f28c78b'
        >>> get_group(group_id)

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
    data = fetch_group(group_id)
    return(data)


@time_it
def get_group_properties(group_id):
    """Retrieve a group and all of its properties.
    Args:
        group_id: 36 Character UUID.

    Basic Usage:
        >>> from vFense.group.groups import get_group_properties
        >>> group_id = 'a7d4690e-5851-4d92-9626-07e16acaea1f'
        >>> get_group_properties(group_id)

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

    data = fetch_group_properties(group_id)
    return(data)


@time_it
def get_properties_for_all_groups(customer_name=None):
    """Retrieve properties for all groupcs.
    Kwargs:
        customer_name: Name of the customer, which the group is part of.

    Basic Usage:
        >>> from vFense.group.groups import get_properties_for_all_groups
        >>> customer_name = 'test'
        >>> get_properties_for_all_groups(customer_name)

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

    data = fetch_properties_for_all_groups(customer_name)
    return(data)


@time_it
def get_groups_for_user(username, fields_to_pluck=None):
    """Retrieve all groups for a user by username
    Args:
        username (str): Get all groups for which this user is part of.

    Kwargs:
        fields_to_pluck (list): List of fields you want to pluck
        from the database

    Basic Usage:
        >>> from vFense.group.groups import get_groups_for_user
        >>> username = 'alien'
        >>> get_groups_for_user(username)

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
    data = fetch_groups_for_user(username, fields_to_pluck)

    return(data)


@time_it
def get_group_by_name(group_name, customer_name, fields_to_pluck=None):
    """Retrieve a group by its name from the database
    Args:
        group_name (str): Name of group.
        customer_name (str): name of the customer, that the group belongs to.
    
    Kwargs:
        fields_to_pluck (list): List of fields you want to retrieve.

    Basic Usage:
        >>> from vFense.group.groups import get_group_by_name
        >>> group_name = 'Administrator'
        >>> customer_name = 'default'
        >>> get_group_by_name(group_name, customer_name)

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
    data = fetch_group_by_name(group_name, customer_name)
    return(data)


@time_it
def get_users_in_group(group_id, fields_to_pluck=None,):
    """Fetch all users for group_id
    Args:
        group_id (str): 36 Character UUID

    Kwargs:
        fields_to_pluck (list): List of fields you want to
        pluck from the database.

    Basic Usage:
        >>> from vFense.core.group.groups get_users_in_group
        >>> group_id = ['17753c6a-2099-4389-b97a-e6e2658b6396']
        >>> get_users_in_group(group_id)

    Returns:
        Returns a list of users
        [
            {
                u'group_name': u'Administrator',
                u'group_id': u'8757b79c-7321-4446-8882-65457f28c78b',
                u'user_name': u'alllllen',
                u'id': u'3477f6d9-731e-4313-a765-e4bd05277f2d',
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
    data = fetch_users_in_group(group_id, fields_to_pluck)
    return(data)


@time_it
def get_groups(
    customer_name=None, groupname=None,
    fields_to_pluck=None
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
        >>> from vFense.group.groups import get_groups
        >>> customer_name = 'default'
        >>> groupname = 'Ad'
        >>> get_groups(customer_name, groupname)

    Returns:
        Returns a List of dictionaries of the properties of a group
        [
            {
                u'permissions': [
                    u'administrator'
                ],
                u'group_name': u'Administrator',
                u'id': u'3ffc2a67-1203-4cb0-ada2-2ae870072680',
                u'customer_name': u'default'
                                                
            }
        ]
    """
    data = fetch_groups(customer_name, groupname, fields_to_pluck)
    return(data)


@time_it
def validate_group_ids(group_ids, customer_name=None):
    """Validate a list if group ids exist in the database.
    Args:
        group_ids (list): List of group ids

    Kwargs:
        customer_name (str): Name of the customer the group belongs too.

    Basic Usage:
        >>> from vFense.group.groups import validate_group_ids
        >>> group_ids = ['4b114647-a6ea-449f-a5a0-d5e1961afb28', '3e27f278-7839-416e-b516-fe4f7cbe98d7']
        >>> validate_group_ids(group_ids)

    Return:
        Tuple (Boolean, [valid_group_ids], [invalid_group_ids])
        (True, ['3ffc2a67-1203-4cb0-ada2-2ae870072680', '0834e656-27a5-4b13-ba56-635797d0d1fc'], [])
    """
    validated = True
    invalid_groups = []
    valid_groups = []
    if isinstance(group_ids, list):
        for group_id in group_ids:
            group = get_group(group_id)
            if group:
                if customer_name:
                    if group.get(GroupKeys.CustomerName) == customer_name:
                        valid_groups.append(group_id)
                    else:
                        invalid_groups.append(group_id)
                        validated = False
                else:
                    valid_groups.append(group_id)
            else:
                invalid_groups.append(group_id)
                validated = False
    else:
        validated = False
        invalid_groups = [group_ids]

    return(validated, valid_groups, invalid_groups)


@time_it
@results_message
def add_user_to_groups(
    username, customer_name, group_ids,
    user_name=None, uri=None, method=None
    ):
    """Add a user into a vFense group
    Args:
        username (str):  Name of the user already in vFense.
        customer_name (str): The customer this user is part of.
        group_ids (list): List of group ids.

    Kwargs:
        user_name (str): The name of the user who called this function.
        uri (str): The uri that was used to call this function.
        method (str): The HTTP methos that was used to call this function.

    Basic Usage:
        >>> from vFense.group.groups import add_user_to_groups
        >>> username = 'alien'
        >>> customer_name = 'default'
        >>> group_ids = ['0834e656-27a5-4b13-ba56-635797d0d1fc']
        >>> add_user_to_groups(username, customer_name, group_ids)

    Returns:
        Returns the results in a dictionary
    {
        'uri': None,
        'rv_status_code': 1010,
        'http_method': None,
        'http_status': 200,
        'message': "None - groups per user [u'ee54820c-cb4e-46a1-9d11-73afe8c4c4e3'] was created",
        'data': {
            'group_name': u'FooLah',
            'user_name': 'alien',
            'group_id': '0834e656-27a5-4b13-ba56-635797d0d1fc',
            'customer_name': 'default'
        }
    }
    """
    status = add_user_to_groups.__name__ + ' - '
    groups_are_valid = validate_group_ids(group_ids, customer_name)
    user_exist = retrieve_object(username, UserCollections.Users)
    customer_exist = retrieve_object(customer_name, CustomerCollections.Customers)
    results = None
    generated_ids = []
    users_group_exist = []
    generic_status_code = 0
    vfense_status_code = 0
    if groups_are_valid[0] and user_exist and customer_exist:
        data_list = []
        for group_id in group_ids:
            group_exist = get_group(group_id)
            user_in_group = (
                user_exist_in_group(username, group_id)
            )
            if not user_in_group:
                data_to_add = (
                    {
                        GroupsPerUserKeys.CustomerName: customer_name,
                        GroupsPerUserKeys.UserName: username,
                        GroupsPerUserKeys.GroupName: group_exist[GroupKeys.GroupName],
                        GroupsPerUserKeys.GroupId: group_id
                    }
                )
                data_list.append(data_to_add)

            else:
                users_group_exist.append(group_id)
        if len(data_list) == len(group_ids):
            status_code, object_count, error, generated_ids = (
                insert_group_per_user(data_list)
            )

            if status_code == DbCodes.Inserted:
                msg = 'user %s add to groups' % (username)
                generic_status_code = GenericCodes.ObjectCreated
                vfense_status_code = GroupCodes.GroupCreated


        else:
            msg = (
                'user %s is already in groups %s' % (
                    username, ' and '.join(users_group_exist)
                )
            )
            status_code = DbCodes.Skipped
            generic_status_code = GenericCodes.ObjectExists
            vfense_status_code = GroupFailureCodes.GroupExistForUser


    elif not groups_are_valid[0]:
        msg = (
            'Group Ids are invalid: %s' % (
                ' and '.join(groups_are_valid[2])
            )
        )
        status_code = DbCodes.Errors
        generic_status_code = GenericCodes.InvalidId
        vfense_status_code = GroupFailureCodes.InvalidGroupId

    elif not user_exist:
        msg = 'User name is invalid: %s' % (username)
        status_code = DbCodes.Errors
        generic_status_code = GenericCodes.InvalidId
        vfense_status_code = UserFailureCodes.InvalidUserName

    elif not customer_exist:
        msg = 'Customer name is invalid: %s' % (customer_name)
        status_code = DbCodes.Errors
        generic_status_code = GenericCodes.InvalidId
        vfense_status_code = CustomerFailureCodes.CustomerDoesNotExist

    results = {
        ApiResultKeys.DB_STATUS_CODE: status_code,
        ApiResultKeys.GENERIC_STATUS_CODE: generic_status_code,
        ApiResultKeys.VFENSE_STATUS_CODE: vfense_status_code,
        ApiResultKeys.GENERATED_IDS: generated_ids,
        ApiResultKeys.MESSAGE: status + msg,
        ApiResultKeys.DATA: [],
        ApiResultKeys.USERNAME: user_name,
        ApiResultKeys.URI: uri,
        ApiResultKeys.HTTP_METHOD: method
    }

    return(results)


@time_it
@results_message
def create_group(
        group_name, customer_name, permissions,
        user_name=None, uri=None, method=None
    ):
    """Create a group in vFense
    Args:
        group_name (str): The name of the group.
        customer_name (str): The name of the customer you are adding this group too.
        permissions (list): List of permissions, this group has.

    Kwargs:
        user_name (str): The name of the user who called this function.
        uri (str): The uri that was used to call this function.
        method (str): The HTTP methos that was used to call this function.

    Basic Usage:
        >>> from vFense.group.groups import create_group
        >>> group_name = 'Linux Admins'
        >>> customer_name = 'default'
        >>> permissions = ['administrator']
        >>> create_group(group_name, customer_name, permissions)

    Returns:
        Returns the results in a dictionary
        {
            'uri': None,
            'rv_status_code': 1010,
            'http_method': None,
            'http_status': 200,
            'message': "None - create group [u'8757b79c-7321-4446-8882-65457f28c78b'] was created",
            'data': {
                'Permissions': [
                    'administrator'
                ],
                'group_name': 'Linux Admins',
                'customer_name': 'default'
            }
        }
    """

    status = create_group.__name__ + ' - '
    generated_ids = []
    valid_group_name = (
        re.search('((?:[A-Za-z0-9_-](?!\s+")|\s(?!\s*")){1,36})', group_name)
    )
    valid_group_length = (
        len(group_name) <= DefaultStringLength.GROUP_NAME
    )
    group_data = (
        {
            GroupKeys.CustomerName: customer_name,
            GroupKeys.GroupName: group_name,
            GroupKeys.Permissions: permissions,
        }
    )
    try:
        group_exist = get_group_by_name(group_name, customer_name)
        permissions_valid = (
            set(permissions).issubset(set(Permissions.VALID_PERMISSIONS))
        )
        if (not group_exist and permissions_valid and
            valid_group_length and valid_group_name):

            status_code, status_count, error, generated_ids = (
                insert_group(group_data)
            )

            if status_code == DbCodes.Inserted:
                msg = 'group %s created' % (group_name)
                generic_status_code = GenericCodes.ObjectCreated
                vfense_status_code = GroupCodes.GroupCreated

        elif not group_exist and not permissions_valid:
            msg = 'invalid permissions %s' % (permissions)
            status_code = DbCodes.Errors
            generic_status_code = GenericCodes.InvalidPermission
            vfense_status_code = GroupFailureCodes.InvalidPermissions


        elif group_exist:
            msg = 'group %s exists' % (group_name)
            status_code = DbCodes.Unchanged
            generic_status_code = GenericCodes.ObjectExists
            vfense_status_code = GroupFailureCodes.GroupIdExists


        elif not valid_group_length or not valid_group_name:
            status_code = DbCodes.Errors
            msg = (
                'group name is not within the 36 character range '+
                'or contains unsupported characters :%s' %
                (group_name)
            )
            generic_status_code = GenericCodes.InvalidId
            vfense_status_code = GroupFailureCodes.InvalidGroupName

        results = {
            ApiResultKeys.DB_STATUS_CODE: status_code,
            ApiResultKeys.GENERIC_STATUS_CODE: generic_status_code,
            ApiResultKeys.VFENSE_STATUS_CODE: vfense_status_code,
            ApiResultKeys.GENERATED_IDS: generated_ids,
            ApiResultKeys.MESSAGE: status + msg,
            ApiResultKeys.DATA: group_data,
            ApiResultKeys.USERNAME: user_name,
            ApiResultKeys.URI: uri,
            ApiResultKeys.HTTP_METHOD: method
        }

    except Exception as e:
        logger.exception(e)
        status_code = DbCodes.Errors
        generic_status_code = GenericFailureCodes.FailedToCreateObject
        vfense_status_code = GroupFailureCodes.FailedToCreateGroup
        msg = 'Failed to create group %s: %s' % (group_name, str(e))

        results = {
            ApiResultKeys.DB_STATUS_CODE: status_code,
            ApiResultKeys.GENERIC_STATUS_CODE: generic_status_code,
            ApiResultKeys.VFENSE_STATUS_CODE: vfense_status_code,
            ApiResultKeys.GENERATED_IDS: generated_ids,
            ApiResultKeys.MESSAGE: status + msg,
            ApiResultKeys.DATA: [],
            ApiResultKeys.USERNAME: user_name,
            ApiResultKeys.URI: uri,
            ApiResultKeys.HTTP_METHOD: method
        }

    return(results)


@time_it
@results_message
def remove_groups_from_user(
    username, group_ids=None,
    user_name=None, uri=None, method=None
    ):
    """Remove a group from a user
    Args:
        username(str): Name of the user

    Kwargs:
        group_ids(list): List of group_ids.
        user_name (str): The name of the user who called this function.
        uri (str): The uri that was used to call this function.
        method (str): The HTTP methos that was used to call this function.

    Basic Usage::
        >>> from vFense.core.group.groups remove_groups_from_user
        >>> username = 'alien'
        >>> group_ids = ['0834e656-27a5-4b13-ba56-635797d0d1fc', '8757b79c-7321-4446-8882-65457f28c78b']
        >>> remove_groups_from_user(username, group_ids)

    Returns:
        Returns the results in a dictionary
        {
            'rv_status_code': 1004,
            'message': 'None - remove_groups_from_user - group ids: 0834e656-27a5-4b13-ba56-635797d0d1fc, 8757b79c-7321-4446-8882-65457f28c78b does not exist',
            'http_method': None,
            'uri': None,
            'http_status': 409
        }
    """
    status = remove_groups_from_user.__name__ + ' - '
    user_does_not_exist_in_group = False
    admin_user = False
    admin_group_id = None
    admin_group_id_exists_in_group_ids = False
    if username == DefaultUsers.ADMIN:
        admin_user = True
        admin_group_id = (
            fetch_group_by_name(
                DefaultGroups.ADMIN, DefaultCustomers.DEFAULT,
                GroupKeys.GroupId
            )[GroupKeys.GroupId]
        )

    try:
        if not group_ids:
            group_ids = (
                [x[GroupsPerUserKeys.GroupId] for x in get_groups_for_user(username, GroupsPerUserKeys.GroupId)]
            )

        if group_ids:
            if not admin_group_id in group_ids:
                msg = 'group ids: ' + 'and '.join(group_ids)
                for gid in group_ids:
                    user_in_group = user_exist_in_group(username, gid)
                    if not user_in_group:
                        user_does_not_exist_in_group = True
            else:
                admin_group_id_exists_in_group_ids = True
                msg = (
                    'Cannot remove the %s group from the %s user' %
                    (DefaultGroups.ADMIN, DefaultUsers.ADMIN)
                )
        else:
            user_does_not_exist_in_group = True

        if (not user_does_not_exist_in_group and
            not admin_group_id_exists_in_group_ids):

            status_code, count, errors, generated_ids = (
                delete_groups_from_user(username, group_ids)
            )
            if status_code == DbCodes.Deleted:
                generic_status_code = GenericCodes.ObjectDeleted
                vfense_status_code = GroupCodes.GroupsRemovedFromUser

            elif status_code == DbCodes.Unchanged:
                generic_status_code = GenericCodes.ObjectUnchanged
                vfense_status_code = GroupCodes.GroupUnchanged

            elif status_code == DbCodes.Skipped:
                generic_status_code = GenericCodes.InvalidId
                vfense_status_code = GroupFailureCodes.InvalidGroupId

        elif admin_group_id_exists_in_group_ids:
            status_code = DbCodes.Skipped
            generic_status_code = GenericCodes.InvalidId
            vfense_status_code = GroupFailureCodes.CantRemoveAdminFromGroup

        else:
            msg = (
                'groups %s do not exist for user %s' %
                (' and '.join(group_ids), username)
            )
            status_code = DbCodes.Skipped
            generic_status_code = GenericCodes.InvalidId
            vfense_status_code = GroupFailureCodes.GroupDoesNotExistForUser

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

    except Exception as e:
        logger.exception(e)
        status_code = DbCodes.Errors
        generic_status_code = GenericFailureCodes.FailedToDeleteObject
        vfense_status_code = GroupFailureCodes.FailedToRemoveGroupFromUser

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

    return(results)


@time_it
@results_message
def remove_group(group_id, user_name=None, uri=None, method=None):
    """Remove  a group in vFense
    Args:
        group_id (str): 36 Character UUID

    Kwargs:
        user_name (str): The name of the user who called this function.
        uri (str): The uri that was used to call this function.
        method (str): The HTTP methos that was used to call this function.

    Basic Usage::
        >>> from vFense.core.group.groups import remove_group
        >>> group_id = 'b4c29dc2-aa44-4ff7-bfc9-f84d38cc7686'
        >>> remove_group(group_id)

    Returns:
        Returns the results in a dictionary
        {
            'rv_status_code': 1012,
            'message': 'None - remove_group - b4c29dc2-aa44-4ff7-bfc9-f84d38cc7686 was deleted',
            'http_method': None,
            'uri': None,
            'http_status': 200
        }
    """
    status = remove_group.__name__ + ' - '
    ids_deleted = []
    try:
        users_exist = get_users_in_group(group_id)
        group_exist = get_group(group_id)
        if not users_exist and group_exist:
            status_code, status_count, error, generated_id = (
                delete_group(group_id)
            )
            if status_code == DbCodes.Deleted:
                msg = 'group_id %s deleted' % (group_id)
                generic_status_code = GenericCodes.ObjectDeleted
                vfense_status_code = GroupCodes.GroupDeleted
                ids_deleted = [group_id]

        elif users_exist:
            msg = (
                'users exist for group %s' % (group_id)
            )
            status_code = DbCodes.Unchanged
            generic_status_code = GenericCodes.ObjectUnchanged
            vfense_status_code = GroupCodes.GroupUnchanged

        elif not group_exist:
            msg = 'group_id %s does not exist' % (group_id)
            status_code = DbCodes.Skipped
            generic_status_code = GenericCodes.ObjectUnchanged
            vfense_status_code = GroupCodes.GroupUnchanged

        results = {
            ApiResultKeys.DB_STATUS_CODE: status_code,
            ApiResultKeys.GENERIC_STATUS_CODE: generic_status_code,
            ApiResultKeys.VFENSE_STATUS_CODE: vfense_status_code,
            ApiResultKeys.DELETED_IDS: ids_deleted,
            ApiResultKeys.MESSAGE: status + msg,
            ApiResultKeys.DATA: [],
            ApiResultKeys.USERNAME: user_name,
            ApiResultKeys.URI: uri,
            ApiResultKeys.HTTP_METHOD: method
        }

    except Exception as e:
        logger.exception(e)
        status_code = DbCodes.Errors
        generic_status_code = GenericFailureCodes.FailedToDeleteObject
        vfense_status_code = GroupFailureCodes.FailedToRemoveGroup
        msg = 'failed to remove group %s: %s' % (group_id, str(e))

        results = {
            ApiResultKeys.DB_STATUS_CODE: status_code,
            ApiResultKeys.GENERIC_STATUS_CODE: generic_status_code,
            ApiResultKeys.VFENSE_STATUS_CODE: vfense_status_code,
            ApiResultKeys.DELETED_IDS: ids_deleted,
            ApiResultKeys.MESSAGE: status + msg,
            ApiResultKeys.DATA: [],
            ApiResultKeys.USERNAME: user_name,
            ApiResultKeys.URI: uri,
            ApiResultKeys.HTTP_METHOD: method
        }

    return(results)


@time_it
@results_message
def remove_groups(group_ids, user_name=None, uri=None, method=None):
    """Remove multiple groups in vFense
    Args:
        group_ids (list): List of group ids

    Kwargs:
        user_name (str): The name of the user who called this function.
        uri (str): The uri that was used to call this function.
        method (str): The HTTP methos that was used to call this function.

    Basic Usage::
        >>> from vFense.core.group.groups import remove_groups
        >>> group_ids = ['b4c29dc2-aa44-4ff7-bfc9-f84d38cc7686']
        >>> remove_groups(group_ids)

    Returns:
        Returns the results in a dictionary
        {
            'rv_status_code': 1012,
            'message': 'None - remove_group - b4c29dc2-aa44-4ff7-bfc9-f84d38cc7686 was deleted',
            'http_method': None,
            'uri': None,
            'http_status': 200
        }
    """
    status = remove_groups.__name__ + ' - '
    ids_deleted = []
    try:
        users_exist = users_exist_in_group_ids(group_ids)
        groups_exist = validate_group_ids(group_ids)
        if not users_exist and groups_exist[0]:
            status_code, status_count, error, generated_id = (
                delete_groups(group_ids)
            )
            if status_code == DbCodes.Deleted:
                msg = 'group_id %s deleted' % (group_ids)
                generic_status_code = GenericCodes.ObjectDeleted
                vfense_status_code = GroupCodes.GroupDeleted
                ids_deleted = group_ids

        elif users_exist:
            msg = (
                'users exist for groups %s' % (' and'.join(group_ids))
            )
            status_code = DbCodes.Unchanged
            generic_status_code = GenericCodes.ObjectUnchanged
            vfense_status_code = GroupCodes.GroupUnchanged

        elif not group_exist:
            msg = 'group_ids %s does not exist' % (' and '.join(group_ids))
            status_code = DbCodes.Skipped
            generic_status_code = GenericCodes.ObjectUnchanged
            vfense_status_code = GroupCodes.GroupUnchanged

        results = {
            ApiResultKeys.DB_STATUS_CODE: status_code,
            ApiResultKeys.GENERIC_STATUS_CODE: generic_status_code,
            ApiResultKeys.DELETED_IDS: ids_deleted,
            ApiResultKeys.VFENSE_STATUS_CODE: vfense_status_code,
            ApiResultKeys.MESSAGE: status + msg,
            ApiResultKeys.DATA: [],
            ApiResultKeys.USERNAME: user_name,
            ApiResultKeys.URI: uri,
            ApiResultKeys.HTTP_METHOD: method
        }

    except Exception as e:
        logger.exception(e)
        status_code = DbCodes.Errors
        generic_status_code = GenericFailureCodes.FailedToDeleteObject
        vfense_status_code = GroupFailureCodes.FailedToRemoveGroup
        msg = 'failed to remove groups %s: %s' % (group_ids, str(e))

        results = {
            ApiResultKeys.DB_STATUS_CODE: status_code,
            ApiResultKeys.GENERIC_STATUS_CODE: generic_status_code,
            ApiResultKeys.VFENSE_STATUS_CODE: vfense_status_code,
            ApiResultKeys.DELETED_IDS: ids_deleted,
            ApiResultKeys.MESSAGE: status + msg,
            ApiResultKeys.DATA: [],
            ApiResultKeys.USERNAME: user_name,
            ApiResultKeys.URI: uri,
            ApiResultKeys.HTTP_METHOD: method
        }

    return(results)
