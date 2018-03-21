# This is the backend for hierarchy package. _db should not be used directly.
# Safer to use hierarchy and its User, Group, Customer class.

import logging
import logging.config
from vFense import VFENSE_LOGGING_CONFIG
from copy import deepcopy
from vFense.db.client import *

from vFense.groups import *
from vFense.users import *
from vFense.customers import *

logging.config.fileConfig(VFENSE_LOGGING_CONFIG)
logger = logging.getLogger('rvapi')


@db_create_close
def _db_document_exist(_id=None, collection_name=None, conn=None):
    """Checks if a document exist for given id.

     Args:

        _id: Used to check for a document.

        collection_name: Name of collection to be searched.

    Returns:

        True if a document exist, False otherwise.
    """

    if not _id and not collection_name:

        return False

    doc = r.table(collection_name).get(_id).run(conn)

    if doc:

        return True

    return False


class _RawModels():
    """Wrapper class to help with converting models to a basic raw dict.
    """

    @staticmethod
    def _db_raw_group(group):
        """Creates a raw dict with Group properties.

        Args:

            group: A Group instance.

        Returns:

            A dict with group properties.
        """

        _raw = {}

        if not group:

            return _raw

        _raw[GroupKeys.Name] = group.name
        _raw[GroupKeys.Id] = group.id
        _raw[GroupKeys.Permissions] = group.get_permissions()
        _raw[GroupKeys.Customer] = group.get_customer(raw=True)
        _raw[GroupKeys.Users] = group.get_users(raw=True)

        return _raw

    @staticmethod
    def _db_raw_user(user):
        """Creates a raw dict with User properties.

        Args:

            user: A User instance.

        Returns:

            A dict with user properties.
        """

        _raw = {}

        if not user:

            return _raw

        _raw[UserKeys.Name] = user.name
        _raw[UserKeys.Id] = user.id
        _raw[UserKeys.FullName] = user.full_name
        _raw[UserKeys.Email] = user.email
        _raw[UserKeys.Password] = user.hash_password
        _raw[UserKeys.Enabled] = user.enabled

        _raw[UserKeys.CurrentCustomer] = user.get_current_customer(raw=True)
        _raw[UserKeys.DefaultCustomer] = user.get_default_customer(raw=True)

        _raw[UserKeys.Customers] = user.get_customers(raw=True)
        _raw[UserKeys.Groups] = user.get_groups(raw=True)

        return _raw

    @staticmethod
    def _db_raw_customer(customer):
        """Creates a raw dict with Customer properties.

        Args:

            customer: A Customer instance.

        Returns:

            A dict with customer properties.
        """

        _raw = {}

        if not customer:

            return _raw

        _raw[CustomerKeys.Name] = customer.name
        _raw[CustomerKeys.Id] = customer.id
        _raw[CustomerKeys.NetThrottle] = customer.net_throttle

        _raw[CustomerKeys.Groups] = customer.get_groups(raw=True)
        _raw[CustomerKeys.Users] = customer.get_users(raw=True)

        return _raw


@db_create_close
def get_all_customers(conn=None):

    customers = list(
        r.table("customers")
        .pluck(CustomerKeys.Name)
        .run(conn)
    )

    return customers


def _db_build_customer(data_doc):
    """ Builds a Customer instance.

    Based on the data document passed, a Customer object is built.

    Args:
        data_doc: A dict with data representing a Customer.

    Returns:
        A Customer instance.
    """

    if not data_doc:

        return None

    customer = Customer()
    customer.name = data_doc.get(CustomerKeys.Name)

    customer.id = data_doc.get(CustomerKeys.Name)
    customer.cpu_throttle = data_doc.get(CustomerKeys.CpuThrottle)
    customer.net_throttle = data_doc.get(CustomerKeys.NetThrottle)

    if data_doc.get(CustomerKeys.Users):

        for doc in data_doc[CustomerKeys.Users]:

            u = _db_document_exist(_id=doc[UserKeys.Name],
                                   collection_name=UserCollection)

            if u:

                u = User(doc[CustomerKeys.Name])

                customer.add_user(u)

    if data_doc.get(CustomerKeys.Groups):

        for doc in data_doc[CustomerKeys.Groups]:

            g = _db_document_exist(_id=doc[GroupKeys.Id],
                                   collection_name=GroupCollection)

            if g:

                g = Group(doc[GroupKeys.Name])
                g.id = doc[GroupKeys.Id]

                customer.add_group(g)

    return customer


def _db_build_group(data_doc):
    """ Builds a Group instance.

    Based on the data document passed, a Group object is built.

    Args:
        data_doc: A dict with data representing a group.

    Returns:
        A Group instance.
    """

    if not data_doc:

        return None

    group = Group()
    group.name = data_doc.get(GroupKeys.Name)
    group.id = data_doc.get(GroupKeys.Id)

    if data_doc.get(GroupKeys.Permissions):

        for perm in data_doc.get(GroupKeys.Permissions):

            group.add_permission(perm)

    if data_doc.get(GroupKeys.Customer):

        c = _db_document_exist(
            _id=data_doc[GroupKeys.Customer][CustomerKeys.Name],
            collection_name=CustomerCollection
        )

        if c:

            c = Customer(data_doc[GroupKeys.Customer][CustomerKeys.Name])

            group.set_customer(c)

    if data_doc.get(GroupKeys.Users):

        for doc in data_doc[GroupKeys.Users]:

            u = _db_document_exist(_id=doc[UserKeys.Name],
                                   collection_name=UserCollection)

            if u:

                u = User(doc[UserKeys.Name])

                group.add_user(u)

    return group


def _db_build_user(data_doc):
    """ Builds a User instance.

    Based on the data document passed, a User object is built.

    Args:
        data_doc: A dict with data representing a User.

    Returns:
        A User instance.
    """

    if not data_doc:

        return None

    user = User()
    user.name = data_doc.get(UserKeys.Name)
    user.id = user.name

    user.full_name = data_doc.get(UserKeys.FullName)
    user.password = data_doc.get(UserKeys.Password)
    user.email = data_doc.get(UserKeys.Email)
    user.enabled = data_doc.get(UserKeys.Enabled)

    if data_doc.get(UserKeys.Groups):

        for doc in data_doc[UserKeys.Groups]:

            g = _db_document_exist(_id=doc[GroupKeys.Id],
                                   collection_name=GroupCollection)

            if g:

                g = Group(doc[GroupKeys.Name])
                g.id = doc[GroupKeys.Id]

                user.add_group(g)

    if data_doc.get(UserKeys.Customers):

        for doc in data_doc[UserKeys.Customers]:

            c = _db_document_exist(_id=doc[CustomerKeys.Name],
                                   collection_name=CustomerCollection)

            if c:

                c = Customer(doc[CustomerKeys.Name])

                user.add_customer(c)

    if data_doc.get(UserKeys.CurrentCustomer):

        current_customer = data_doc[UserKeys.CurrentCustomer]

        c = _db_document_exist(_id=current_customer[CustomerKeys.Name],
                               collection_name=CustomerCollection)

        if c:

            c = Customer(current_customer[CustomerKeys.Name])

            user.set_current_customer(c)

    if data_doc.get(UserKeys.DefaultCustomer):

        default_customer = data_doc[UserKeys.DefaultCustomer]

        c = _db_document_exist(_id=default_customer[CustomerKeys.Name],
                               collection_name=CustomerCollection)

        if c:

            c = Customer(default_customer[CustomerKeys.Name])

            user.set_default_customer(c)

    return user

@db_create_close
def _db_save(_id=None, collection_name=None, data=None, conn=None):
    """Attempts to save data to the DB.

    If an document ID is provided, then the document gets updated. Otherwise
    a new document is inserted.

    Args:

        _id: Id representing a document if it has one.

        collection_name: Name of the collection to be used.

        data: Data to be inserted or replaced.

    Returns:

        A DB generated ID is returned (empty string if no ID is available)
            on successful insert, False otherwise.
        A boolean True if updating was successful, False otherwise.

    """

    success = False

    if _id:

        result = (
            r.table(collection_name)
            .get(_id)
            .update(data)
            .run(conn)
        )

        if result.get('replaced') and result.get('replaced') > 0:

            success = True

    else:

        result = r.table(collection_name).insert(data).run(conn)

        if result.get('inserted') and result.get('inserted') > 0:

            if 'generated_keys' in result:

                success = result['generated_keys'][0]

            else:

                success = ''

    return success

@db_create_close
def _db_get(collection_name=None, _id=None, _filter=None, conn=None):
    """Attempts to get data from the DB.

    Tries to get a document based on the id. If a filter is used, then a list
    of documents is returned that match said filter.

    Args:

        collection_name: Name of the collection to be used.

        _id: Id (primary key) representing a document.

        _filter: A dict type that contains key(s)/value(s) of the
            document to get.

    Returns:

        If the document id is provided, then that document is returned.
        If a filter is used, then a list of documents is returned.

    """

    document = None

    if _id:

        document = r.table(collection_name).get(_id).run(conn)

    else:

        document = list(r.table(collection_name).filter(_filter).run(conn))

    return document

@db_create_close
def _db_delete(collection_name=None, _id=None, conn=None):
    """Attempts to delete data from the DB.

    Tries to delete a document based on the id or filter provided. If filter is
    used, the first document returned is deleted.

    Args:

        collection_name: Name of the collection to be used.

        _id: Id (primary key) representing a document

    Returns:

        True if document was deleted, False otherwise.

    """

    success = None

    if _id:

        result = r.table(collection_name).get(_id).delete().run(conn)

        if 'deleted' in result and result['deleted'] > 0:

            success = True

    return success


def save_customer(customer):
    """Saves the customer to DB.

    If an id attribute is found, the document representing that id is updated.
    Otherwise we create a new document.

    Args:

        customer: A Customer instance.

    Returns:

        True is customer was saved successfully, False otherwise.

    """

    _customer = {}

    _customer[CustomerKeys.Name] = customer.name
    _customer[CustomerKeys.NetThrottle] = customer.net_throttle
    _customer[CustomerKeys.CpuThrottle] = customer.cpu_throttle

    _customer[CustomerKeys.Groups] = customer.get_groups(raw=True)

    _customer[CustomerKeys.Users] = customer.get_users(raw=True)

    success = _db_save(_id=customer.id, collection_name=CustomerCollection,
                       data=_customer)

    return success


def save_user(user):
    """Saves the user to DB.

    If an id attribute is found, the document representing that id is updated.
    Otherwise we create a new document.

    Args:

        user: A User instance.

    Returns:

        True is customer was saved successfully, False otherwise.

    """

    _user = {}

    _user[UserKeys.Name] = user.name
    _user[UserKeys.FullName] = user.full_name
    _user[UserKeys.Email] = user.email
    _user[UserKeys.Enabled] = user.enabled
    _user[UserKeys.Password] = user.password

    _user[UserKeys.Groups] = user.get_groups(raw=True)

    _user[UserKeys.Customers] = user.get_customers(raw=True)
    _user[UserKeys.CurrentCustomer] = user.get_current_customer(raw=True)
    _user[UserKeys.DefaultCustomer] = user.get_default_customer(raw=True)

    success = _db_save(_id=user.id, collection_name=UserCollection, data=_user)

    return success


def save_group(group):
    """Saves the group to DB.

    If an id attribute is found, the document representing that id is updated.
    Otherwise we create a new document.

    Args:

        group: A Group instance.

    Returns:

        True is customer was saved successfully, False otherwise.

    """

    _group = {}

    _group[GroupKeys.Name] = group.name
    _group[GroupKeys.Customer] = group.get_customer(raw=True)
    _group[GroupKeys.Permissions] = group.get_permissions()

    _group[GroupKeys.Users] = group.get_users(raw=True)

    success = _db_save(_id=group.id, collection_name=GroupCollection,
                       data=_group)

    return success


def get_customer(name=None):
    """Gets the Customer from the DB.

    Based on the id or name given, retrieve said customer.

    Args:

        _id: Id representing the customer to retrieve.

        name: Name representing the customer to retrieve.

    Returns:

        A Customer instance.

    """

    data_doc = None

    if name:

        data_doc = _db_get(collection_name=CustomerCollection, _id=name)

    if data_doc:

        customer = _db_build_customer(data_doc)

    else:

        customer = None

    return customer


def get_user(name=None):
    """Gets the User from the DB.

    Based on the name given, retrieve said user.

    Args:

        name: Name representing the user to retrieve.

    Returns:

        A User instance.

    """
    data_doc = None

    if name:

        data_doc = _db_get(collection_name=UserCollection, _id=name)

    if data_doc:

        user = _db_build_user(data_doc)

    else:

        user = None

    return user


def get_group(_id=None, name=None, all_groups=False):
    """Gets the Group from the DB.

    Based on the id or name given, retrieve said group.

    Args:

        _id: Id representing the group to retrieve.

        name: Name representing the group to retrieve.

        all_groups: True if a list of all groups matching the name is to
            be returned. Does not work with _id.

    Returns:

        A Group instance.

    """

    data_doc = None

    if _id:

        data_doc = _db_get(collection_name=GroupCollection, _id=_id)

    elif name:

        data_doc = _db_get(collection_name=GroupCollection,
                           _filter={GroupKeys.Name: name})

        if data_doc:

            if not all_groups:

                data_doc = data_doc[0]

        else:

            data_doc = {}

    if isinstance(data_doc, list):

        groups = []

        for g in data_doc:
            groups.append(_db_build_group(g))

        return groups

    elif data_doc:

        return _db_build_group(data_doc)

    return None
