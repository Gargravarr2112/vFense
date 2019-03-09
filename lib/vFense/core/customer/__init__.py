import re

from vFense.core._constants import CPUThrottleValues, DefaultStringLength
from vFense.core.customer._constants import CustomerDefaults

class CustomerCollections():
    Customers = 'customers'
    CustomersPerUser = 'customers_per_user'


class CustomerKeys():
    CustomerName = 'customer_name'
    Properties = 'properties'
    NetThrottle = 'net_throttle'
    CpuThrottle = 'cpu_throttle'
    PackageUrl = 'package_download_url_base'
    ServerQueueTTL = 'server_queue_ttl' # in minutes
    AgentQueueTTL = 'agent_queue_ttl' # in minutes
    Users = 'users' #Mapped Keys
    Groups = 'groups' #Mapped Keys


class CustomerPerUserKeys():
    CustomerName = 'customer_name'
    UserName = 'user_name'
    Id = 'id'


class CustomerPerUserIndexes():
    CustomerName = 'customer_name'
    UserName = 'user_name'


class Customer(object):
    """Used to represent an instance of a customer."""

    def __init__(
        self, name, net_throttle=None, cpu_throttle=None,
        server_queue_ttl=None, agent_queue_ttl=None,
        package_download_url=None
    ):
        """
        Args:
            name (str): The name of the customer
            net_throttle (int): The default net throttling for downloading
                packages for agents in this customer, in KB/s.
            cpu_throttle (str): The default cpu throttling for operations
                in this customer. Has to be a valid cpu throttling keyword.
                    valid: ['idle', 'below_normal', 'normal', 'above_normal', 'high']
            server_queue_ttl (int): The default time an operation will sit
                on the server queue, in minutes. Must be above 0.
            agent_queue_ttl (int): The default time an operation will sit
                on the agent queue, in minutes. Must be above 0.
            package_download_url (str): The base url used to construct the
                urls where the packages will be downloaded from.
                    Ex:
                        'https://192.168.1.1/packages/'
        """
        self.name = name
        self.net_throttle = net_throttle
        self.cpu_throttle = cpu_throttle
        self.server_queue_ttl = server_queue_ttl
        self.agent_queue_ttl = agent_queue_ttl
        self.package_download_url = package_download_url

        if net_throttle:
            self.net_throttle = int(net_throttle)

        if server_queue_ttl:
            self.server_queue_ttl = int(server_queue_ttl)

        if agent_queue_ttl:
            self.agent_queue_ttl = int(agent_queue_ttl)

    def fill_in_defaults(self):
        """Replace all the fields that have None as their value with
        the hardcoded default values.
        
        Use case(s):
            Useful when creating a new customer instance and only want to fill
            in a few fields, then allow the create customer functions call this
            method to fill in the rest.
        """

        if not self.net_throttle:
            self.net_throttle = CustomerDefaults.NET_THROTTLE

        if not self.cpu_throttle:
            self.cpu_throttle = CustomerDefaults.CPU_THROTTLE

        if not self.server_queue_ttl:
            self.server_queue_ttl = CustomerDefaults.SERVER_QUEUE_TTL

        if not self.agent_queue_ttl:
            self.agent_queue_ttl = CustomerDefaults.AGENT_QUEUE_TTL

    def get_invalid_fields(self):
        """Check the customer for any invalid fields.

        Returns:
            (list): List of key/value pair dictionaries corresponding
                to the invalid fields.

                Ex:
                    [
                        {'customer_name': 'the invalid name in question'},
                        {'net_throttle': -10}
                    ]
        """
        invalid_fields = []

        if isinstance(self.name, str):
            valid_symbols = re.search(
                '((?:[A-Za-z0-9_-](?!\s+")|\s(?!\s*")){1,36})', self.name
            )
            valid_length = len(self.name) <= DefaultStringLength.CUSTOMER_NAME

            if not valid_symbols or not valid_length:
                invalid_fields.append(
                    {CustomerKeys.CustomerName: self.name}
                )
        else:
            invalid_fields.append(
                {CustomerKeys.CustomerName: self.name}
            )

        if self.net_throttle:
            if isinstance(self.net_throttle, int):
                if self.net_throttle < 0:
                    invalid_fields.append(
                        {CustomerKeys.NetThrottle: self.net_throttle}
                    )
            else:
                invalid_fields.append(
                    {CustomerKeys.NetThrottle: self.net_throttle}
                )

        if self.cpu_throttle:
            if self.cpu_throttle not in CPUThrottleValues.VALID_VALUES:
                invalid_fields.append(
                    {CustomerKeys.CpuThrottle: self.cpu_throttle}
                )

        if self.server_queue_ttl:
            if isinstance(self.server_queue_ttl, int):
                if self.server_queue_ttl <= 0:
                    invalid_fields.append(
                        {CustomerKeys.ServerQueueTTL: self.server_queue_ttl}
                    )
            else:
                invalid_fields.append(
                    {CustomerKeys.ServerQueueTTL: self.server_queue_ttl}
                )

        if self.agent_queue_ttl:
            if isinstance(self.agent_queue_ttl, int):
                if self.agent_queue_ttl <= 0:
                    invalid_fields.append(
                        {CustomerKeys.AgentQueueTTL: self.agent_queue_ttl}
                    )
            else:
                invalid_fields.append(
                    {CustomerKeys.AgentQueueTTL: self.agent_queue_ttl}
                )

        # TODO: check for invalid package url

        return invalid_fields

    def to_dict(self):
        """ Turn the customer fields into a dictionary.

        Returns:
            (dict): A dictionary with the fields corresponding to the
                customer.

                Ex:
                {
                    "agent_queue_ttl": 100 ,
                    "cpu_throttle":  "high" ,
                    "customer_name":  "default" ,
                    "net_throttle": 100 ,
                    "package_download_url_base": https://192.168.8.14/packages/,
                    "server_queue_ttl": 100
                }
                    
        """

        return {
            CustomerKeys.CustomerName: self.name,
            CustomerKeys.NetThrottle: self.net_throttle,
            CustomerKeys.CpuThrottle: self.cpu_throttle,
            CustomerKeys.ServerQueueTTL: self.server_queue_ttl,
            CustomerKeys.AgentQueueTTL: self.agent_queue_ttl,
            CustomerKeys.PackageUrl: self.package_download_url
        }

    def to_dict_non_null(self):
        """ Use to get non None fields of customer. Useful when
        filling out just a few fields to update the customer in the db.

        Returns:
            (dict): a dictionary with the non None fields of this customer.
        """
        customer_dict = self.to_dict()

        return {k:customer_dict[k] for k in customer_dict
                if customer_dict[k] != None}


