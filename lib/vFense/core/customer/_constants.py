from vFense.core._constants import CPUThrottleValues


class DefaultCustomers():
    DEFAULT = 'default'


class CustomerDefaults():
    NET_THROTTLE = 0
    CPU_THROTTLE = CPUThrottleValues.NORMAL
    SERVER_QUEUE_TTL = 10  #minutes
    AGENT_QUEUE_TTL = 10  #minutes
