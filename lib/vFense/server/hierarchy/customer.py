from vFense.server.hierarchy import CustomerKeys


class Customer():

    def __init__(self, name, properties={}):

        self.customer_name = name
        self.properties = properties

    def dict(self):

        return {
            CustomerKeys.CustomerName: self.customer_name,
            CustomerKeys.Properties: self.properties
        }

    def __repr__(self):

        return (
            "Customer(name=%r)"
            % (self.customer_name)
        )

    def __eq__(self, other):

        try:

            return self.customer_name == other.customer_name

        except:

            return False
