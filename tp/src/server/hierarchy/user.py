from vFense.server.hierarchy import UserKeys, DefaultCustomer


class User():

    def __init__(
        self, user_name, password, full_name, email,
        current_customer=DefaultCustomer, default_customer=DefaultCustomer,
        enabled=True
    ):

        self.user_name = user_name
        self.password = password
        self.full_name = full_name
        self.email = email
        self.enabled = enabled

        self.current_customer = current_customer
        self.default_customer = default_customer

    def dict(self):

        return {
            UserKeys.UserName: self.user_name,
            UserKeys.FullName: self.full_name,
            UserKeys.Email: self.email,
            UserKeys.Enabled: self.enabled,
            UserKeys.CurrentCustomer: self.current_customer,
            UserKeys.DefaultCustomer: self.default_customer
        }

    @staticmethod
    def from_dict(user):

        u = User(
            user.get(UserKeys.UserName),
            user.get(UserKeys.Password),
            user.get(UserKeys.FullName),
            user.get(UserKeys.Email),
            user.get(UserKeys.CurrentCustomer),
            user.get(UserKeys.DefaultCustomer),
            user.get(UserKeys.Enabled)
        )

        return u

    def __repr__(self):

        return (
            "User(name=%r, fullname=%r, email=%r)"
            % (self.user_name, self.full_name, self.email)
        )
