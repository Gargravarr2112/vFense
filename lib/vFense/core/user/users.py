import re
import logging                                                                                                     
from vFense import VFENSE_LOGGING_CONFIG
from vFense.core._constants import *
from vFense.errorz._constants import *
from vFense.core.user import *
from vFense.core.user._constants import *
from vFense.core.group import *
from vFense.core.group._constants import *
from vFense.core.customer import *

from vFense.core.customer._db import users_exists_in_customer, \
    insert_user_per_customer, delete_users_in_customer

from vFense.core.user._db import insert_user, fetch_user, fetch_users, \
    delete_user, update_user, fetch_user_and_all_properties, \
    fetch_users_and_all_properties, delete_users, user_status_toggle

from vFense.core.group._db import user_exist_in_group, insert_group_per_user, \
    delete_users_in_group

from vFense.core.group.groups import validate_group_ids, \
    add_user_to_groups, remove_groups_from_user, get_group

from vFense.core.customer.customers import get_customer, \
    add_user_to_customers, remove_customers_from_user, \
    validate_customer_names

from vFense.utils.security import Crypto, check_password
from vFense.core.decorators import results_message, time_it
from vFense.errorz.status_codes import *

logging.config.fileConfig(VFENSE_LOGGING_CONFIG)
logger = logging.getLogger('rvapi')


@time_it
def get_user(username, without_fields=['password']):
    """Retrieve a user from the database
    Args:
        username (str): Name of the user.

    Kwargs:
        without_fields (list): List of fields you do not want to include.

    Basic Usage:
        >>> from vFense.user.users import get_user
        >>> username = 'admin'
        >>> get_user(username, without_fields=['password'])

    Return:
        Dictionary of user properties.
        {
            u'current_customer': u'default',
            u'enabled': True,
            u'full_name': u'TopPatchAgentCommunicationAccount',
            u'default_customer': u'default',
            u'user_name': u'agent',
            u'email': u'admin@toppatch.com'
        }
    """
    data = fetch_user(username, without_fields)
    return(data)


@time_it
def get_user_property(username, user_property):
    """Retrieve user property.
    Args:
        username (str):  Name of the user.
        user_property (str): Property you want to retrieve.

    Basic Usage:
        >>> from vFense.user.users get_user_property
        >>> username = 'admin'
        >>> user_property = 'current_customer'
        >>> get_user_property(username, user_property)

    Return:
        String
    """
    user_data = fetch_user(username)
    user_key = None
    if user_data:
        user_key = user_data.get(user_property)

    return(user_key)

@time_it
def get_user_properties(username):
    """Retrieve a user and all of its properties by username.
    Args:
        username (str): Name of the user.

    Basic Usage:
        >>> from vFense.user.user import get_user_and_all_properties
        >>> username = 'admin'
        >>> get_user_and_all_properties(username')

    Return:
        Dictionary of user properties.
        {
            "current_customer": "default", 
            "customers": [
                {
                    "admin": true, 
                    "name": "default"
                }
            ], 
            "groups": [
                {
                    "group_id": "1b74a706-34e5-482a-bedc-ffbcd688f066", 
                    "group_name": "Administrator"
                }
            ], 
                "default_customer": "default", 
                "user_name": "admin", 
                "permissions": [
                    "administrator"
                ]
        }
    """
    user_data = fetch_user_and_all_properties(username)
    return(user_data)


@time_it
def get_properties_for_all_users(customer_name=None):
    """Retrieve users and all of its properties by customer_name.
    Kwargs:
        customer_name (str): Name of the customer.

    Basic Usage:
        >>> from vFense.user.user import get_properties_for_all_users
        >>> customer_name = 'default'
        >>> get_properties_for_all_users(customer_name')

    Return:
        List of users and their properties.
        [
            {
                "current_customer": "default", 
                "customers": [
                    {
                        "admin": true, 
                        "name": "default"
                    }
                ], 
                "groups": [
                    {
                        "group_id": "1b74a706-34e5-482a-bedc-ffbcd688f066", 
                        "group_name": "Administrator"
                    }
                ], 
                    "default_customer": "default", 
                    "user_name": "admin", 
                    "permissions": [
                        "administrator"
                    ]
            }
        ]
    """
    user_data = fetch_users_and_all_properties(customer_name)
    return(user_data)


@time_it
def get_users(customer_name=None, username=None, without_fields=None):
    """Retrieve all users that is in the database by customer_name or
        all of the customers or by regex.

    Kwargs:
        customer_name (str): Name of the customer, where the agent
            is located.
        username (str): Name of the user you are searching for.
            This is a regular expression match.
        without_fields (list): List of fields you do not want to include.

    Basic Usage::
        >>> from vFense.user.users import get_users
        >>> customer_name = 'default'
        >>> username = 'al'
        >>> without_fields = ['password']
        >>> get_users(customer_name, username, without_fields)

    Returns:
        List of users:
        [
            {
                "current_customer": "default", 
                "email": "test@test.org", 
                "full_name": "is doing it", 
                "default_customer": "default", 
                "user_name": "alien", 
                "id": "ba9682ef-7adf-4916-8002-9637485b30d8", 
                "customer_name": "default"
            }
        ]
    """
    data = fetch_users(customer_name, username, without_fields) 
    return(data)


@time_it
def validate_user_names(user_names):
    """Validate a list of user names exist in the database.
    Args:
        user_names (list): List of user names

    Basic Usage:
        >>> from vFense.group.groups import validate_user_names
        >>> user_names = ['tester1', 'tester2']
        >>> validate_user_names(user_names)

    Return:
        Tuple (Boolean, [valid_user_names], [invalid_user_names])
        (True, ['tester1', 'tester2'], [])
    """
    validated = True
    invalid_user_names = []
    valid_user_names = []
    if isinstance(user_names, list):
        for user_name in user_names:
            user = get_user(user_name)
            if user:
                valid_user_names.append(user_name)
            else:
                invalid_user_names.append(user_name)
                validated = False

    return(validated, valid_user_names, invalid_user_names)


@time_it
@results_message
def add_users_to_customer(
    usernames, customer_name,
    user_name=None, uri=None, method=None
    ):
    """Add a multiple customers to a user
    Args:
        usernames (list):  Name of the users already in vFense.
        customer_name (str): The name of the customer,
            these users will be added to.

    Kwargs:
        user_name (str): The name of the user who called this function.
        uri (str): The uri that was used to call this function.
        method (str): The HTTP methos that was used to call this function.

    Basic Usage:
        >>> from vFense.core.user.users import add_users_to_customer
        >>> usernames = ['tester1', 'tester2']
        >>> customer_names = 'default'
        >>> add_users_to_customer(usernames, customer_name)

    Returns:
        Dictionary of the status of the operation.
        {
            'uri': None,
            'rv_status_code': 1017,
            'http_method': None,
            'http_status': 200,
            'message': "None - add_user_to_customers - customer names existed 'default', 'TopPatch', 'vFense' unchanged",
            'data': []

        }
    """
    users_are_valid = validate_user_names(usernames)
    customer_is_valid = validate_customer_names([customer_name])
    results = None
    data_list = []
    status = add_users_to_customer.__name__ + ' - '
    msg = ''
    status_code = 0
    generic_status_code = 0
    vfense_status_code = 0
    generated_ids = []
    data_list = []
    if users_are_valid[0] and customer_is_valid[0]:
        for username in usernames:
            if not users_exists_in_customer(username, customer_name):
                data_to_add = (
                    {
                        CustomerPerUserKeys.CustomerName: customer_name,
                        CustomerPerUserKeys.UserName: username,
                    }
                )
                data_list.append(data_to_add)

        if len(data_list) == len(usernames):
            status_code, _, _, generated_ids = (
                insert_user_per_customer(data_list)
            )

            if status_code == DbCodes.Inserted:
                msg = (
                    'user %s added to %s' % (
                       ' and '.join(usernames), customer_name
                    )
                )
                generic_status_code = GenericCodes.ObjectCreated
                vfense_status_code = UserCodes.UsersAddedToCustomer

        else:
            status_code = DbCodes.Unchanged
            msg = (
                'user names %s existed for customer %s' %
                (' and '.join(usernames), customer_name)
            )
            generic_status_code = GenericCodes.ObjectExists
            vfense_status_code = CustomerFailureCodes.UsersExistForCustomer

    elif not customer_is_valid[0]:
        status_code = DbCodes.Errors
        msg = (
            'customer names are invalid: %s' % (
                ' and '.join(customer_is_valid[2])
            )
        )
        generic_status_code = GenericCodes.InvalidId
        vfense_status_code = CustomerFailureCodes.InvalidCustomerName

    elif not users_are_valid[0]:
        status_code = DbCodes.Errors
        msg = (
            'user names are invalid: %s' % (
                ' and '.join(users_are_valid[2])
            )
        )
        generic_status_code = GenericCodes.InvalidId
        vfense_status_code = UserFailureCodes.InvalidUserName

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
def remove_users_from_customer(
    usernames, customer_name,
    user_name=None, uri=None, method=None
    ):
    """Remove users from a customer
    Args:
        usernames (list): List of usernames, you are
            removing from the customer.
        customer_name (str): Name of the customer,
            you want to remove the users from

    Kwargs:
        user_name (str): The name of the user who called this function.
        uri (str): The uri that was used to call this function.
        method (str): The HTTP methos that was used to call this function.

    Basic Usage:
        >>> from vFense.customer.customers remove_users_from_customer
        >>> usernames = ['tester1', 'tester2']
        >>> customer_name = 'Tester'
        >>> remove_users_from_customer(usernames, customer_name)

    Return:
        Dictionary of the status of the operation.
    {
        'rv_status_code': 1004,
        'message': 'None - remove_users_from_customer - removed customers from user alien: TopPatch and vFense does not exist',
        'http_method': None,
        'uri': None,
        'http_status': 409
    }
    """
    status = remove_users_from_customer.__name__ + ' - '
    admin_in_list = DefaultUsers.ADMIN in usernames
    try:
        if not admin_in_list:
            status_code, _, _, _ = (
                delete_users_in_customer(usernames, customer_name)
            )
            if status_code == DbCodes.Deleted:
                msg = (
                    'removed users %s from customer %s' %
                    (' and '.join(usernames), customer_name)
                )
                generic_status_code = GenericCodes.ObjectDeleted
                vfense_status_code = UserCodes.UsersRemovedFromCustomer

            elif status_code == DbCodes.Skipped:
                msg = 'invalid customer name or invalid username'
                generic_status_code = GenericCodes.InvalidId
                vfense_status_code = CustomerFailureCodes.InvalidCustomerName

            elif status_code == DbCodes.DoesNotExist:
                msg = 'customer name or username does not exist'
                generic_status_code = GenericCodes.DoesNotExist
                vfense_status_code = CustomerFailureCodes.UsersDoNotExistForCustomer

        else:
            msg = 'can not remove the admin user from any customer'
            status_code = DbCodes.Skipped
            generic_status_code = GenericCodes.InvalidId
            vfense_status_code = UserFailureCodes.CantDeleteAdminFromCustomer


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
        msg = (
            'Failed to remove users %s from customer %s: %s' % 
            (' and '.join(usernames), customer_name, str(e))
        )
        status_code = DbCodes.Errors
        generic_status_code = GenericFailureCodes.FailedToDeleteObject
        vfense_status_code = UserFailureCodes.FailedToRemoveUsersFromCustomer

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
def add_users_to_group(
    group_id, usernames,
    user_name=None, uri=None, method=None
    ):
    """Add a multiple users to a group
    Args:
        group_id (str):  The 36 character group UUID.
        usernames (list):  Name of the users already in vFense.

    Kwargs:
        user_name (str): The name of the user who called this function.
        uri (str): The uri that was used to call this function.
        method (str): The HTTP methos that was used to call this function.

    Basic Usage:
        >>> from vFense.core.user.users import add_users_to_group
        >>> group_id = '6ce3423e-544b-4206-b3cb-2296d39956b7'
        >>> usernames = ['tester1', 'tester2']
        >>> add_users_to_group(group_id, usernames)

    Returns:
        Dictionary of the status of the operation.
        {
            'uri': None,
            'rv_status_code': 1017,
            'http_method': None,
            'http_status': 200,
            'message': "None - add_users_to_group - customer names existed 'default', 'TopPatch', 'vFense' unchanged",
            'data': []

        }
    """
    users_are_valid = validate_user_names(usernames)
    group = get_group(group_id)
    results = None
    data_list = []
    status = add_users_to_group.__name__ + ' - '
    msg = ''
    status_code = 0
    generic_status_code = 0
    vfense_status_code = 0
    generated_ids = []
    data_list = []
    if users_are_valid[0] and group:
        for username in usernames:
            if not user_exist_in_group(username, group_id):
                data_to_add = (
                    {
                        GroupsPerUserKeys.GroupId: group_id,
                        GroupsPerUserKeys.GroupName: group[GroupKeys.GroupName],
                        GroupsPerUserKeys.CustomerName: group[GroupKeys.CustomerName],
                        GroupsPerUserKeys.UserName: username,
                    }
                )
                data_list.append(data_to_add)

        if len(data_list) == len(usernames):
            status_code, _, _, generated_ids = (
                insert_group_per_user(data_list)
            )

            if status_code == DbCodes.Inserted:
                msg = (
                    'user %s added to %s' % (
                       ' and '.join(usernames), group_id
                    )
                )
                generic_status_code = GenericCodes.ObjectCreated
                vfense_status_code = UserCodes.UsersAddedToGroup

        else:
            status_code = DbCodes.Unchanged
            msg = (
                'user names %s existed for group %s' %
                (' and '.join(usernames), group_id)
            )
            generic_status_code = GenericCodes.ObjectExists
            vfense_status_code = GroupFailureCodes.UsersExistForGroup

    elif not group:
        status_code = DbCodes.Errors
        msg = 'group id is invalid: %s' % (group_id)
        generic_status_code = GenericCodes.InvalidId
        vfense_status_code = GroupFailureCodes.InvalidGroupId

    elif not users_are_valid[0]:
        status_code = DbCodes.Errors
        msg = (
            'user names are invalid: %s' % (
                ' and '.join(users_are_valid[2])
            )
        )
        generic_status_code = GenericCodes.InvalidId
        vfense_status_code = UserFailureCodes.InvalidUserName

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
def remove_users_from_group(
    group_id, usernames,
    user_name=None, uri=None, method=None
    ):
    """Remove users from a group id.
    Args:
        group_id (str): The 36 character group id
            you want to remove the users from
        usernames (list): List of usernames, you are
            removing from the group_id.

    Kwargs:
        user_name (str): The name of the user who called this function.
        uri (str): The uri that was used to call this function.
        method (str): The HTTP methos that was used to call this function.

    Basic Usage:
        >>> from vFense.user.users remove_users_from_group
        >>> usernames = ['tester1', 'tester2']
        >>> group_id = '57095e37-e8b7-4cc9-89c1-f49621886548'
        >>> remove_users_from_group(usernames, group_id)

    Return:
        Dictionary of the status of the operation.
    {
        'rv_status_code': 1004,
        'message': 'None - remove_users_from_group - removed group from user alien: TopPatch and vFense does not exist',
        'http_method': None,
        'uri': None,
        'http_status': 409
    }
    """
    status = remove_users_from_group.__name__ + ' - '
    admin_in_list = DefaultUsers.ADMIN in usernames
    try:
        if not admin_in_list:
            status_code, _, _, _ = (
                delete_users_in_group(usernames, group_id)
            )
            if status_code == DbCodes.Deleted:
                msg = (
                    'removed users %s from group_id %s' %
                    (' and '.join(usernames), group_id)
                )
                generic_status_code = GenericCodes.ObjectDeleted
                vfense_status_code = UserCodes.UsersRemovedFromGroup

            elif status_code == DbCodes.Skipped:
                msg = 'invalid group id or invalid username'
                generic_status_code = GenericCodes.InvalidId
                vfense_status_code = GroupFailureCodes.InvalidGroupId

            elif status_code == DbCodes.DoesNotExist:
                msg = 'group id or username does not exist'
                generic_status_code = GenericCodes.DoesNotExist
                vfense_status_code = GroupFailureCodes.UsersDoNotExistForGroup

        else:
            msg = 'can not remove the admin user from any group_id'
            generic_status_code = GenericCodes.InvalidId
            vfense_status_code = GroupFailureCodes.CantRemoveAdminFromGroup


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
        msg = (
            'Failed to remove users %s from group %s: %s' % 
            (' and '.join(usernames), group_id, str(e))
        )
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
def toggle_user_status(username, user_name=None, uri=None, method=None):
    """Enable or disable a user
    Args:
        username (str): The username you are enabling or disabling

    Kwargs:
        user_name (str): The name of the user who called this function.
        uri (str): The uri that was used to call this function.
        method (str): The HTTP methos that was used to call this function.

    Basic Usage:
        >>> from vFense.user.users import toggle_user_status
        >>> username = 'tester'
        >>> toggle_user_status(username)

    Return:
        Dictionary of the status of the operation.
        {
            "rv_status_code": 13001, 
            "http_method": null, 
            "updated_ids": [
                "tester"
            ], 
            "http_status": 200, 
            "unchanged_ids": [], 
            "message": "toggle_user_status - user tester is enabled", 
            "data": [], 
            "uri": null
        }
    """
    status = toggle_user_status.__name__ + ' - '
    status_code, _, _, _ = (
        user_status_toggle(username)
    )
    if status_code == DbCodes.Replaced:
        user_exist = fetch_user(username)
        if user_exist[UserKeys.Enabled] == CommonKeys.YES:
            msg = 'user %s is enabled' % (username)

        else:
            msg = 'user %s is disabled' % (username)

        generic_status_code = GenericCodes.ObjectUpdated
        vfense_status_code = UserCodes.UserUpdated

    elif status_code == DbCodes.Skipped:
        msg = 'user %s is invalid' % (username)
        generic_status_code = GenericCodes.InvalidId
        vfense_status_code = UserFailureCodes.InvalidUserName


    results = {
        ApiResultKeys.DB_STATUS_CODE: status_code,
        ApiResultKeys.GENERIC_STATUS_CODE: generic_status_code,
        ApiResultKeys.VFENSE_STATUS_CODE: vfense_status_code,
        ApiResultKeys.MESSAGE: status + msg,
        ApiResultKeys.UPDATED_IDS: [username],
        ApiResultKeys.DATA: [],
        ApiResultKeys.USERNAME: user_name,
        ApiResultKeys.URI: uri,
        ApiResultKeys.HTTP_METHOD: method
    }

    return(results)

@time_it
@results_message
def create_user(
    username, fullname, password, group_ids,
    customer_name, email, enabled=CommonKeys.YES, user_name=None,
    uri=None, method=None
    ):
    """Add a new user into vFense
    Args:
        username (str): The name of the user you are creating.
        fullname (str): The full name of the user you are creating.
        password (str): The unencrypted password of the user.
        group_ids (list): List of vFense group ids to add the user too.
        customer_name (str): The customer, this user will be part of.
        email (str): Email address of the user.
        enabled (str): yes or no
            Default=no

    Kwargs:
        user_name (str): The name of the user who called this function.
        uri (str): The uri that was used to call this function.
        method (str): The HTTP methos that was used to call this function.

    Basic Usage:
        >>> from vFense.user.users import create_user
        >>> username = 'testing123'
        >>> fullname = 'testing 4 life'
        >>> password = 'Testing123#'
        >>> group_ids = ['8757b79c-7321-4446-8882-65457f28c78b']
        >>> customer_name = 'default'
        >>> email = 'test@test.org'
        >>> enabled = 'yes'
        >>> create_user(
                username, fullname, password,
                group_ids, customer_name, email, enabled
            )

    Return:
        Dictionary of the status of the operation.
        {
            'uri': None,
            'rv_status_code': 1010,
            'http_method': None,
            'http_status': 200,
            'message': 'None - create user testing123 was created',
            'data': {
                'current_customer': 'default',
                'full_name': 'tester4life',
                'default_customer': 'default',
                'password': '$2a$12$HFAEabWwq8Hz0TIZ.jV59eHLoy0DdogdtR9TgvZnBCye894oljZOe',
                'user_name': 'testing123',
                'enabled': 'yes',
                'email': 'test@test.org'
            }
        }
    """

    user_exist = fetch_user(username)
    pass_strength = check_password(password)
    status = create_user.__name__ + ' - '
    generated_ids = []
    generic_status_code = 0
    vfense_status_code = 0
    user_data = (
        {
            UserKeys.CurrentCustomer: customer_name,
            UserKeys.DefaultCustomer: customer_name,
            UserKeys.FullName: fullname,
            UserKeys.UserName: username,
            UserKeys.Enabled: enabled,
            UserKeys.Email: email
        }
    )
    if enabled != CommonKeys.YES or enabled != CommonKeys.NO:
        enabled = CommonKeys.NO


    valid_user_name = (
        re.search('([A-Za-z0-9_-]{1,24})', username)
    )
    valid_user_length = (
        len(username) <= DefaultStringLength.USER_NAME
    )

    try:
        if (not user_exist and pass_strength[0] and
                valid_user_length and valid_user_name):
            encrypted_password = Crypto().hash_bcrypt(password)
            user_data[UserKeys.Password] = encrypted_password
            customer_is_valid = get_customer(customer_name)
            validated_groups, _, invalid_groups = validate_group_ids(
                group_ids, customer_name
            )

            if customer_is_valid and validated_groups:
                object_status, _, _, generated_ids = (
                    insert_user(user_data)
                )
                generated_ids.append(username)

                add_user_to_customers(
                    username, [customer_name],
                    user_name, uri, method
                )

                add_user_to_groups(
                    username, customer_name, group_ids,
                    user_name, uri, method
                )
                if object_status == DbCodes.Inserted:
                    msg = 'user name %s created' % (username)
                    generic_status_code = GenericCodes.ObjectCreated
                    vfense_status_code = UserCodes.UserCreated
                    user_data.pop(UserKeys.Password)

            elif not customer_is_valid and validated_groups:
                msg = 'customer name %s does not exist' % (customer_name)
                object_status = DbCodes.Skipped
                generic_status_code = GenericCodes.InvalidId
                vfense_status_code = CustomerFailureCodes.CustomerDoesNotExist

            elif not validated_groups and customer_is_valid:
                msg = 'group ids %s does not exist' % (invalid_groups)
                object_status = DbCodes.Skipped
                generic_status_code = GenericCodes.InvalidId
                vfense_status_code = GroupFailureCodes.InvalidGroupId

            else:
                group_error = (
                    'group ids %s does not exist' % (invalid_groups)
                )
                customer_error = (
                    'customer name %s does not exist' % (customer_name)
                )
                msg = group_error + ' and ' + customer_error
                object_status = DbCodes.Errors
                generic_status_code = GenericFailureCodes.FailedToCreateObject
                vfense_status_code = UserFailureCodes.FailedToCreateUser

        elif user_exist:
            msg = 'username %s already exists' % (username)
            object_status = GenericCodes.ObjectExists
            generic_status_code = GenericCodes.ObjectExists
            vfense_status_code = UserFailureCodes.UserNameExists

        elif not pass_strength[0]:
            msg = (
                    'password does not meet the min requirements: strength=%s'
                    % (pass_strength[1])
            )
            object_status = GenericFailureCodes.FailedToCreateObject
            generic_status_code = GenericFailureCodes.FailedToCreateObject
            vfense_status_code = UserFailureCodes.WeakPassword

        elif not valid_user_name or not valid_user_length:
            status_code = DbCodes.Errors
            msg = (
                'user name is not within the 24 character range '+
                'or contains unsupported characters :%s' %
                (username)
            )
            generic_status_code = GenericCodes.InvalidId
            vfense_status_code = UserFailureCodes.InvalidUserName

        results = {
            ApiResultKeys.DB_STATUS_CODE: object_status,
            ApiResultKeys.GENERIC_STATUS_CODE: generic_status_code,
            ApiResultKeys.VFENSE_STATUS_CODE: vfense_status_code,
            ApiResultKeys.MESSAGE: status + msg,
            ApiResultKeys.GENERATED_IDS: generated_ids,
            ApiResultKeys.DATA: [user_data],
            ApiResultKeys.USERNAME: user_name,
            ApiResultKeys.URI: uri,
            ApiResultKeys.HTTP_METHOD: method
        }

    except Exception as e:
        logger.exception(e)
        msg = 'Failed to create user %s: %s' % (username, str(e))
        status_code = DbCodes.Errors
        generic_status_code = GenericFailureCodes.FailedToCreateObject
        vfense_status_code = UserFailureCodes.FailedToCreateUser

        results = {
            ApiResultKeys.DB_STATUS_CODE: status_code,
            ApiResultKeys.GENERIC_STATUS_CODE: generic_status_code,
            ApiResultKeys.VFENSE_STATUS_CODE: vfense_status_code,
            ApiResultKeys.MESSAGE: status + msg,
            ApiResultKeys.GENERATED_IDS: [],
            ApiResultKeys.DATA: [user_data],
            ApiResultKeys.USERNAME: user_name,
            ApiResultKeys.URI: uri,
            ApiResultKeys.HTTP_METHOD: method
        }

    return(results)


@time_it
@results_message
def remove_user(username, user_name=None, uri=None, method=None):
    """Remove a user from vFense
    Args:
        username (str): The name of the user you are deleteing.

    Kwargs:
        user_name (str): The name of the user who called this function.
        uri (str): The uri that was used to call this function.
        method (str): The HTTP methos that was used to call this function.

    Return:
        Dictionary of the status of the operation.
    """

    user_exist = fetch_user(username)
    status = remove_user.__name__ + ' - '
    usernames_not_to_delete = []
    usernames_to_delete = []
    try:
        if user_exist and username != DefaultUsers.ADMIN:
            remove_groups_from_user(username)
            remove_customers_from_user(username)
            usernames_to_delete.append(username)

            object_status, _, _, _ = (
                delete_user(username)
            )

            if object_status == DbCodes.Deleted:
                generic_status_code = GenericCodes.ObjectDeleted
                vfense_status_code = UserCodes.UserDeleted
                msg = 'User removed %s' % (username)

        elif username == DefaultUsers.ADMIN:
            msg = 'Can not delete the %s user' % (username)
            usernames_not_to_delete.append(username)
            object_status = DbCodes.Skipped
            generic_status_code = GenericCodes.CouldNotBeDeleted
            vfense_status_code = UserFailureCodes.AdminUserCanNotBeDeleted

        else:
            msg = 'User does not exist %s' % (username)
            usernames_not_to_delete.append(username)
            object_status = DbCodes.Skipped
            generic_status_code = GenericCodes.InvalidId
            vfense_status_code = UserFailureCodes.UserNameDoesNotExist

        results = {
            ApiResultKeys.DB_STATUS_CODE: object_status,
            ApiResultKeys.GENERIC_STATUS_CODE: generic_status_code,
            ApiResultKeys.VFENSE_STATUS_CODE: vfense_status_code,
            ApiResultKeys.MESSAGE: status + msg,
            ApiResultKeys.UNCHANGED_IDS: usernames_not_to_delete,
            ApiResultKeys.DELETED_IDS: usernames_to_delete,
            ApiResultKeys.DATA: [],
            ApiResultKeys.USERNAME: user_name,
            ApiResultKeys.URI: uri,
            ApiResultKeys.HTTP_METHOD: method
        }


    except Exception as e:
        logger.exception(e)
        msg = 'Failed to remove user %s: %s' % (username, str(e))
        status_code = DbCodes.Errors
        generic_status_code = GenericFailureCodes.FailedToDeleteObject
        vfense_status_code = UserFailureCodes.FailedToRemoveUser

        results = {
            ApiResultKeys.DB_STATUS_CODE: status_code,
            ApiResultKeys.GENERIC_STATUS_CODE: generic_status_code,
            ApiResultKeys.VFENSE_STATUS_CODE: vfense_status_code,
            ApiResultKeys.MESSAGE: status + msg,
            ApiResultKeys.UNCHANGED_IDS: usernames_not_to_delete,
            ApiResultKeys.DELETED_IDS: usernames_to_delete,
            ApiResultKeys.DATA: [],
            ApiResultKeys.USERNAME: user_name,
            ApiResultKeys.URI: uri,
            ApiResultKeys.HTTP_METHOD: method
        }

    return(results)


@time_it
@results_message
def remove_users(usernames, user_name=None, uri=None, method=None):
    """Remove a user from vFense
    Args:
        usernames (list): List of usernames that will be deleted.

    Kwargs:
        user_name (str): The name of the user who called this function.
        uri (str): The uri that was used to call this function.
        method (str): The HTTP methos that was used to call this function.

    Return:
        Dictionary of the status of the operation.
    """

    status = change_password.__name__ + ' - '
    usernames_not_to_delete = []
    usernames_to_delete = []
    generic_status_code = 0
    vfense_status_code = 0
    msg = ''
    try:
        if not isinstance(usernames, list):
            usernames = usernames.split(',')
        for username in usernames:
            user_exist = fetch_user(username)
            status = remove_users.__name__ + ' - '
            if user_exist and username != DefaultUsers.ADMIN:
                remove_groups_from_user(username)
                remove_customers_from_user(username)
                usernames_to_delete.append(username)

            elif username == DefaultUsers.ADMIN:
                msg = 'Can not delete the %s user' % (username)
                usernames_not_to_delete.append(username)
                generic_status_code = GenericCodes.CouldNotBeDeleted
                vfense_status_code = UserFailureCodes.AdminUserCanNotBeDeleted
                object_status = DbCodes.Skipped

            else:
                msg = 'User does not exist %s' % (username)
                usernames_not_to_delete.append(username)
                generic_status_code = GenericCodes.InvalidId
                vfense_status_code = UserFailureCodes.UserNameDoesNotExist
                object_status = DbCodes.Skipped

        if len(usernames_to_delete) > 0:
            object_status, _, _, _ = (
                delete_users(usernames_to_delete)
            )

            if object_status == DbCodes.Deleted:
                generic_status_code = GenericCodes.ObjectDeleted
                vfense_status_code = UserCodes.UserDeleted
                msg = 'Users removed %s' % (' and '.join(usernames_to_delete))

            if object_status == DbCodes.DoesNotExist:
                generic_status_code = GenericCodes.DoesNotExist
                vfense_status_code = UserFailureCodes.UserNameDoesNotExist
                msg = 'Users  %s do not exist' % (' and '.join(usernames_to_delete))

        else:
            object_status = DbCodes.Unchanged
            generic_status_code = GenericFailureCodes.FailedToDeleteObject
            vfense_status_code = UserFailureCodes.FailedToRemoveUser
            msg = 'Users can not be removed %s' % (
                ' and '.join(usernames_not_to_delete))

        results = {
            ApiResultKeys.DB_STATUS_CODE: object_status,
            ApiResultKeys.GENERIC_STATUS_CODE: generic_status_code,
            ApiResultKeys.VFENSE_STATUS_CODE: vfense_status_code,
            ApiResultKeys.MESSAGE: status + msg,
            ApiResultKeys.UNCHANGED_IDS: usernames_not_to_delete,
            ApiResultKeys.DELETED_IDS: usernames_to_delete,
            ApiResultKeys.DATA: [],
            ApiResultKeys.USERNAME: user_name,
            ApiResultKeys.URI: uri,
            ApiResultKeys.HTTP_METHOD: method
        }


    except Exception as e:
        logger.exception(e)
        msg = 'Failed to remove user %s: %s' % (username, str(e))
        generic_status_code = GenericFailureCodes.FailedToDeleteObject
        vfense_status_code = UserFailureCodes.FailedToRemoveUser

        results = {
            ApiResultKeys.DB_STATUS_CODE: DbCodes.Errors,
            ApiResultKeys.GENERIC_STATUS_CODE: generic_status_code,
            ApiResultKeys.VFENSE_STATUS_CODE: vfense_status_code,
            ApiResultKeys.MESSAGE: status + msg,
            ApiResultKeys.UNCHANGED_IDS: usernames_not_to_delete,
            ApiResultKeys.DELETED_IDS: usernames_to_delete,
            ApiResultKeys.DATA: [],
            ApiResultKeys.USERNAME: user_name,
            ApiResultKeys.URI: uri,
            ApiResultKeys.HTTP_METHOD: method
        }

    return(results)



@time_it
@results_message
def change_password(
    username, password, new_password,
    user_name=None, uri=None, method=None
    ):
    """Change password for a user.
    Args:
        username (str): The name of the user you are deleteing.
        password (str): Original password.
        new_password (str): New password.

    Kwargs:
        user_name (str): The name of the user who called this function.
        uri (str): The uri that was used to call this function.
        method (str): The HTTP methos that was used to call this function.

    Return:
        Dictionary of the status of the operation.
        {
            'uri': None,
            'rv_status_code': 1008,
            'http_method': None,
            'http_status': 200,
            'message': 'None - change_password - Password changed for user admin - admin was updated',
            'data': []
        }
    """
    user_exist = fetch_user(username, without_fields=None)
    status = change_password.__name__ + ' - '
    try:
        generic_status_code = 0
        vfense_status_code = 0
        if user_exist:
            pass_strength = check_password(new_password)
            original_encrypted_password = user_exist[UserKeys.Password].encode('utf-8')
            original_password_verified = (
                Crypto().verify_bcrypt_hash(password, original_encrypted_password)
            )
            encrypted_new_password = Crypto().hash_bcrypt(new_password)
            new_password_verified_against_orignal_password = (
                Crypto().verify_bcrypt_hash(new_password, original_encrypted_password)
            )
            if (original_password_verified and pass_strength[0] and
                    not new_password_verified_against_orignal_password):

                user_data = {UserKeys.Password: encrypted_new_password}

                object_status, _, _, _ = (
                    update_user(username, user_data)
                )

                if object_status == DbCodes.Replaced:
                    msg = 'Password changed for user %s - ' % (username)
                    generic_status_code = GenericCodes.ObjectUpdated
                    vfense_status_code = UserCodes.PasswordChanged

            elif new_password_verified_against_orignal_password:
                msg = 'New password is the same as the original - user %s - ' % (username)
                object_status = DbCodes.Unchanged
                generic_status_code = GenericFailureCodes.FailedToUpdateObject
                vfense_status_code = UserFailureCodes.NewPasswordSameAsOld

            elif original_password_verified and not pass_strength[0]:
                msg = 'New password is to weak for user %s - ' % (username)
                object_status = DbCodes.Unchanged
                generic_status_code = GenericFailureCodes.FailedToUpdateObject
                vfense_status_code = UserFailureCodes.WeakPassword

            elif not original_password_verified:
                msg = 'Password not verified for user %s - ' % (username)
                object_status = DbCodes.Unchanged
                generic_status_code = GenericFailureCodes.FailedToUpdateObject
                vfense_status_code = UserFailureCodes.InvalidPassword

            results = {
                ApiResultKeys.DB_STATUS_CODE: object_status,
                ApiResultKeys.GENERIC_STATUS_CODE: generic_status_code,
                ApiResultKeys.VFENSE_STATUS_CODE: vfense_status_code,
                ApiResultKeys.UPDATED_IDS: [username],
                ApiResultKeys.MESSAGE: status + msg,
                ApiResultKeys.DATA: [],
                ApiResultKeys.USERNAME: user_name,
                ApiResultKeys.URI: uri,
                ApiResultKeys.HTTP_METHOD: method
            }


        else:
            msg = 'User %s does not exist - ' % (username)
            object_status = DbCodes.Skipped
            generic_status_code = GenericCodes.InvalidId
            vfense_status_code = UserFailureCodes.UserNameDoesNotExist

            results = {
                ApiResultKeys.DB_STATUS_CODE: object_status,
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
        generic_status_code = GenericFailureCodes.FailedToUpdateObject
        vfense_status_code = UserFailureCodes.FailedToUpdateUser
        msg = 'Failed to update password for user %s: %s' % (username, str(e))

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

def _validate_user_data(username, **kwargs):
    data_validated = True
    if kwargs.get(UserKeys.CurrentCustomer):
        current_customer = kwargs.get(UserKeys.CurrentCustomer)
        valid_current_customer = False
        customer_validated = users_exists_in_customer(username, current_customer)
        if customer_validated:
            valid_current_customer = True

        return(valid_current_customer)

    return(data_validated)


@time_it
@results_message
def edit_user_properties(username, **kwargs):
    """ Edit the properties of a customer. 
    Args:
        username (str): Name of the user you are editing.

    Kwargs:
        full_name (str): The full name of the user
        email (str): The email address of the user
        user_name (str): The name of the user who called this function.
        current_customer (str): The name of the customer you want to manage.
        uri (str): The uri that was used to call this function.
        method (str): The HTTP methos that was used to call this function.

    Return:
        Dictionary of the status of the operation.
        {
            'uri': None,
            'rv_status_code': 1008,
            'http_method': None,
            'http_status': 200,
            'message': 'None - edit_user_properties - admin was updated',
            'data': {
                'full_name': 'vFense Admin'
            }
        }
    """
    if not kwargs.get(ApiResultKeys.USERNAME):
        user_name = None
    else:
        user_name = kwargs.pop(ApiResultKeys.USERNAME)

    if not kwargs.get(ApiResultKeys.URI):
        uri = None
    else:
        uri = kwargs.pop(ApiResultKeys.URI)

    if not kwargs.get(ApiResultKeys.HTTP_METHOD):
        method = None
    else:
        method = kwargs.pop(ApiResultKeys.HTTP_METHOD)

    if kwargs.get(UserKeys.Password):
        kwargs.pop(UserKeys.Password)

    user_exist = fetch_user(username, without_fields=None)
    status = edit_user_properties.__name__ + ' - '
    generic_status_code = 0
    vfense_status_code = 0
    try:
        if user_exist:
            data_validated = _validate_user_data(username, **kwargs)
            if data_validated:
                object_status, _, _, _ = (
                    update_user(username, kwargs)
                )

                if object_status == DbCodes.Replaced:
                    msg = 'User %s was updated - ' % (username)
                    generic_status_code = GenericCodes.ObjectUpdated
                    vfense_status_code = UserCodes.UserUpdated

                elif object_status == DbCodes.Unchanged:
                    msg = 'User %s was not updated - ' % (username)
                    generic_status_code = GenericCodes.ObjectUnchanged
                    vfense_status_code = UserCodes.UserUnchanged

            else:
                object_status = DbCodes.Skipped
                generic_status_code = GenericCodes.InvalidId
                vfense_status_code = UserFailureCodes.FailedToUpdateUser
                msg = 'User %s properties were invalid - ' % (username)

        else:
            object_status = DbCodes.Skipped
            generic_status_code = GenericCodes.InvalidId
            vfense_status_code = UserFailureCodes.UserNameDoesNotExist
            msg = 'User %s does not exist - ' % (username)

        results = {
            ApiResultKeys.DB_STATUS_CODE: object_status,
            ApiResultKeys.GENERIC_STATUS_CODE: generic_status_code,
            ApiResultKeys.VFENSE_STATUS_CODE: vfense_status_code,
            ApiResultKeys.UPDATED_IDS: username,
            ApiResultKeys.MESSAGE: status + msg,
            ApiResultKeys.DATA: [kwargs],
            ApiResultKeys.USERNAME: user_name,
            ApiResultKeys.URI: uri,
            ApiResultKeys.HTTP_METHOD: method
        }

    except Exception as e:
        logger.exception(e)
        generic_status_code = GenericFailureCodes.FailedToUpdateObject
        vfense_status_code = UserFailureCodes.FailedToUpdateUser
        msg = 'Failed to update properties for user %s: %s' % (username, str(e))

        results = {
            ApiResultKeys.DB_STATUS_CODE: DbCodes.Errors,
            ApiResultKeys.GENERIC_STATUS_CODE: generic_status_code,
            ApiResultKeys.VFENSE_STATUS_CODE: vfense_status_code,
            ApiResultKeys.MESSAGE: status + msg,
            ApiResultKeys.DATA: [kwargs],
            ApiResultKeys.USERNAME: user_name,
            ApiResultKeys.URI: uri,
            ApiResultKeys.HTTP_METHOD: method
        }

    return(results)
