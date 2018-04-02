from vFense.server.hierarchy import GroupKeys


class Group():

    def __init__(
        self,
        group_name,
        customer,
        permissions=[],
        group_id=None
    ):

        self.id = group_id

        self.group_name = group_name
        self.customer = customer

        self.permissions = permissions

    def add_permission(self, permission):

        if permission not in self.permissions:
            self.permissions.append(permission)

    def remove_permission(self, permission):

        if permission in self.permissions:
            self.permissions.remove(permission)

    def set_permissions(self, permissions):

        self.permissions = permissions

    def set_customer(self, customer_name):

        self.customer = customer_name

    def dict(self):

        return {
            GroupKeys.Id: self.id,
            GroupKeys.GroupName: self.group_name,
            GroupKeys.Permissions: self.permissions,
            GroupKeys.CustomerId: self.customer
        }

    def __repr__(self):

        return (
            "Group(name=%r,id=%r, customer=%r)"
            % (self.group_name, self.id, self.customer)
        )
