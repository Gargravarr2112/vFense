import logging
import logging.config
from vFense import VFENSE_LOGGING_CONFIG
from vFense.db.client import *

from vFense.server.hierarchy import *
#from server.hierarchy.group import *
#from server.hierarchy.user import *
#from server.hierarchy.customer import *

logging.config.fileConfig(VFENSE_LOGGING_CONFIG)
logger = logging.getLogger('rvapi')

_main_db = 'vFense'


@db_create_close
def initialization(conn=None):

    _create_tables(conn)
    _create_indices(conn)


def _create_tables(conn):

    tables = r.db(_main_db).table_list().run(conn)

    if Collection.Users not in tables:
        _create_users_table(conn)

    if Collection.Groups not in tables:
        _create_groups_table(conn)

    if Collection.Customers not in tables:
        _create_customers_table(conn)

#    if Collection.GroupsPerCustomer not in tables:
#        _create_GPC_table(conn)

    if Collection.GroupsPerUser not in tables:
        _create_GPU_table(conn)

    if Collection.UsersPerCustomer not in tables:
        _create_UPC_table(conn)


def _create_indices(conn):

    _create_groups_indices(conn)
    # _create_GPC_indices(conn)
    _create_GPU_indices(conn)
    _create_UPC_indices(conn)

def _create_UPC_table(conn=None):

    try:

        r.db(_main_db).table_create(
            Collection.UsersPerCustomer
        ).run(conn)

    except Exception as e:

        logger.error(
            "Unable to create %s table." % Collection.UsersPerCustomer
        )
        logger.exception(e)

def _create_UPC_indices(conn):

    try:

        indices = r.table(Collection.UsersPerCustomer).index_list().run(conn)

        if UsersPerCustomerKeys.UserId not in indices:
            r.table(
                Collection.UsersPerCustomer
            ).index_create(UsersPerCustomerKeys.UserId).run(conn)

        if UsersPerCustomerKeys.CustomerId not in indices:
            r.table(
                Collection.UsersPerCustomer
            ).index_create(UsersPerCustomerKeys.CustomerId).run(conn)

        if UsersPerCustomerKeys.UserAndCustomerId not in indices:
            r.table(
                Collection.UsersPerCustomer
            ).index_create(
                UsersPerCustomerKeys.UserAndCustomerId,
                lambda row:
                [
                    row[UsersPerCustomerKeys.UserId],
                    row[UsersPerCustomerKeys.CustomerId]
                ]
            ).run(conn)

    except Exception as e:

        logger.error(
            "Unable to create indices for %s table." % Collection.UsersPerCustomer
        )
        logger.exception(e)


def _create_GPU_table(conn=None):

    try:

        r.db(_main_db).table_create(
            Collection.GroupsPerUser
        ).run(conn)

    except Exception as e:

        logger.error(
            "Unable to create %s table." % Collection.GroupsPerUser
        )
        logger.exception(e)


def _create_GPU_indices(conn=None):

    try:

        indices = r.table(Collection.GroupsPerUser).index_list().run(conn)

        if GroupsPerUserKeys.UserId not in indices:
            r.table(
                Collection.GroupsPerUser
            ).index_create(GroupsPerUserKeys.UserId).run(conn)

        if GroupsPerUserKeys.GroupIdAndCustomerId not in indices:
            r.table(
                Collection.GroupsPerUser
            ).index_create(
                GroupsPerUserKeys.GroupIdAndCustomerId,
                lambda row:
                [
                    row[GroupsPerUserKeys.GroupId],
                    row[GroupsPerUserKeys.CustomerId]
                ]
            ).run(conn)

        if GroupsPerUserKeys.UserIdAndCustomerId not in indices:
            r.table(
                Collection.GroupsPerUser
            ).index_create(
                GroupsPerUserKeys.UserIdAndCustomerId,
                lambda row:
                [
                    row[GroupsPerUserKeys.UserId],
                    row[GroupsPerUserKeys.CustomerId]
                ]
            ).run(conn)

        if GroupsPerUserKeys.GroupUserAndCustomerId not in indices:
            r.table(
                Collection.GroupsPerUser
            ).index_create(
                GroupsPerUserKeys.GroupUserAndCustomerId,
                lambda row:
                [
                    row[GroupsPerUserKeys.GroupId],
                    row[GroupsPerUserKeys.UserId],
                    row[GroupsPerUserKeys.CustomerId]
                ]
            ).run(conn)

    except Exception as e:

        logger.error(
            "Unable to create indices for %s table." % Collection.GroupsPerUser
        )
        logger.exception(e)

def _create_GPC_table(conn=None):

    try:

        r.db(_main_db).table_create(
            Collection.GroupsPerCustomer
        ).run(conn)

    except Exception as e:

        logger.error(
            "Unable to create %s table." % Collection.GroupsPerCustomer
        )
        logger.exception(e)


def _create_GPC_indices(conn=None):

    try:

        indices = r.table(Collection.GroupsPerCustomer).index_list().run(conn)

        if GroupsPerCustomerKeys.GroupId not in indices:
            r.table(
                Collection.GroupsPerCustomer
            ).index_create(GroupsPerCustomerKeys.GroupId).run(conn)

        if GroupsPerCustomerKeys.CustomerId not in indices:
            r.table(
                Collection.GroupsPerCustomer
            ).index_create(GroupsPerCustomerKeys.CustomerId).run(conn)

        if GroupsPerCustomerKeys.GroupAndCustomerId not in indices:
            r.table(
                Collection.GroupsPerCustomer
            ).index_create(
                GroupsPerCustomerKeys.GroupAndCustomerId,
                lambda row:
                [
                    row[GroupsPerCustomerKeys.GroupId],
                    row[GroupsPerCustomerKeys.CustomerId]
                ]
            ).run(conn)

    except Exception as e:

        logger.error(
            "Unable to create indices for table  %s." % Collection.GroupsPerCustomer
        )
        logger.exception(e)

def _create_groups_table(conn=None):

    try:

        r.db(_main_db).table_create(Collection.Groups).run(conn)

    except Exception as e:

        logger.error("Unable to create %s table." % Collection.Groups)
        logger.exception(e)


def _create_groups_indices(conn=None):

    try:

        indices = r.table(Collection.Groups).index_list().run(conn)

        if GroupKeys.GroupName not in indices:
            r.table(
                Collection.Groups
            ).index_create(GroupKeys.GroupName).run(conn)

        if GroupKeys.CustomerId not in indices:
            r.table(
                Collection.Groups
            ).index_create(GroupKeys.CustomerId).run(conn)

        if GroupKeys.GroupNameAndCustomerId not in indices:
            r.table(
                Collection.Groups
            ).index_create(
                GroupKeys.GroupNameAndCustomerId,
                lambda row:
                [
                    row[GroupKeys.GroupName],
                    row[GroupKeys.CustomerId]
                ]
            ).run(conn)

    except Exception as e:

        logger.error("Unable to create indices for table %s." % Collection.Groups)
        logger.exception(e)

def _create_customers_table(conn=None):

    try:

        r.db(_main_db).table_create(
            Collection.Customers,
            primary_key=CustomerKeys.CustomerName
        ).run(conn)

    except Exception as e:

        logger.error("Unable to create %s table." % Collection.Customers)
        logger.exception(e)


def _create_users_table(conn=None):

    try:
        r.db(_main_db).table_create(
            Collection.Users,
            primary_key=UserKeys.UserName
        ).run(conn)

    except Exception as e:

        logger.error("Unable to create %s table." % Collection.Users)
        logger.exception(e)
