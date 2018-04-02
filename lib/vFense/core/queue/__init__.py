class QueueCollections():
    Agent = 'agent_queue'


class AgentQueueKeys():
    Id = 'id'
    AgentId = 'agent_id'
    OrderId = 'order_id'
    CreatedTime = 'created_time'
    ServerQueueTTL = 'server_queue_ttl'
    AgentQueueTTL = 'agent_queue_ttl'
    ExpireMinutes = 'expire_minutes'
    Expired = 'expired'
    CustomerName = 'customer_name'
    OperationId = 'operation_id'
    RequestMethod = 'request_method'
    ResponseURI = 'response_uri'


class AgentQueueIndexes():
    AgentId = 'agent_id'
