class GroupCollections():
    Groups = 'groups'
    GroupsPerUser = 'groups_per_user'

class GroupKeys():
    GroupName = 'group_name'
    CustomerName = 'customer_name'
    Permissions = 'permissions'
    GroupId = 'id'
    Users = 'users' #Mapped Keys


class GroupIndexes():
    CustomerName = 'customer_name'
    GroupName = 'group_name'
    Permissions = 'permissions'


class GroupsPerUserKeys():
    CustomerName = 'customer_name'
    UserName = 'user_name'
    GroupName = 'group_name'
    GroupId = 'group_id'
    Id = 'id'


class GroupsPerUserIndexes():
    CustomerName = 'customer_name'
    UserName = 'user_name'
    GroupName = 'group_name'
    GroupId = 'group_id'
