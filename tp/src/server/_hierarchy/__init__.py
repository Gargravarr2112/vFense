from collections import namedtuple

UserCollection = 'users'
GroupCollection = 'groups'
CustomerCollection = 'customers'
DefaultCustomer = 'default'


class UserKeys():

    Name = 'name'  # Primary key!
    Id = 'id'
    FullName = 'full_name'
    Email = 'email'
    Password = 'password'
    Enabled = 'enabled'
    Groups = 'groups'
    Customers = 'customers'
    CurrentCustomer = 'current_customer'
    DefaultCustomer = 'default_customer'

UserInfo = namedtuple('UserInfo', [UserKeys.Name])


class GroupKeys():

    Id = 'id'
    Name = 'name'
    Customer = 'customer'
    Users = 'users'
    Permissions = 'permissions'

GroupInfo = namedtuple('GroupInfo', [GroupKeys.Id, GroupKeys.Name])


class CustomerKeys():

    Name = 'name'  # Primary key!!
    Id = 'id'
    Groups = 'groups'
    Users = 'users'

    # Temporary hacks
    NetThrottle = 'net_throttle'
    CpuThrottle = 'cpu_throttle'

CustomerInfo = namedtuple('CustomerInfo', [CustomerKeys.Name])
