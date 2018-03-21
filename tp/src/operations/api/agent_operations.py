import simplejson as json
import re
import logging
import logging.config
from vFense import VFENSE_LOGGING_CONFIG
from vFense.core.api.base import BaseHandler
from vFense.core.api._constants import ApiArguments
from vFense.core._constants import SortValues, DefaultQueryValues
from vFense.operations import *
from vFense.operations.agent_operations import get_agent_operation
from vFense.operations.search.agent_search import AgentOperationRetriever
from vFense.core.decorators import authenticated_request
from vFense.errorz.error_messages import GenericResults
from vFense.core.user.users import get_user_property
from vFense.core.user import UserKeys

logging.config.fileConfig(VFENSE_LOGGING_CONFIG)
logger = logging.getLogger('rvapi')


class GetTransactionsHandler(BaseHandler):
    @authenticated_request
    def get(self):
        username = self.get_current_user()
        customer_name = (
            get_user_property(username, UserKeys.CurrentCustomer)
        )
        uri = self.request.uri
        method = self.request.method
        try:
            count = (
                int(
                    self.get_argument(ApiArguments.COUNT,
                        DefaultQueryValues.COUNT
                    )
                )
            )
            offset = (
                int(
                    self.get_argument(
                        ApiArguments.OFFSET,
                        DefaultQueryValues.OFFSET
                    )
                )
            )
            sort = self.get_argument(ApiArguments.SORT, SortValues.DESC)
            sort_by = (
                self.get_argument(
                    ApiArguments.SORT_BY,
                    AgentOperationKeys.CreatedTime
                )
            )
            operation = self.get_argument(ApiArguments.OPERATION, None)

            operations = (
                AgentOperationRetriever(
                    customer_name,
                    count, offset, sort, sort_by,
                    username, uri, method
                )
            )

            if operation:
                results = operations.get_all_by_operation(operation)

            else:
                results = operations.get_all()

            self.set_status(results['http_status'])
            self.set_header('Content-Type', 'application/json')
            self.write(json.dumps(results, indent=4))

        except Exception as e:
            results = (
                GenericResults(
                    username, uri, method
                ).something_broke('operation', 'search by oper type', e)
            )
            logger.exception(results)
            self.set_status(results['http_status'])
            self.set_header('Content-Type', 'application/json')
            self.write(json.dumps(results, indent=4))

class AgentOperationsHandler(BaseHandler):
    @authenticated_request
    def get(self, agent_id):
        username = self.get_current_user()
        customer_name = (
            get_user_property(username, UserKeys.CurrentCustomer)
        )
        uri = self.request.uri
        method = self.request.method
        try:
            count = (
                int(
                    self.get_argument(ApiArguments.COUNT,
                        DefaultQueryValues.COUNT
                    )
                )
            )
            offset = (
                int(
                    self.get_argument(
                        ApiArguments.OFFSET,
                        DefaultQueryValues.OFFSET
                    )
                )
            )
            sort = self.get_argument(ApiArguments.SORT, SortValues.DESC)
            sort_by = (
                self.get_argument(
                    ApiArguments.SORT_BY,
                    AgentOperationKeys.CreatedTime
                )
            )

            operations = (
                AgentOperationRetriever(
                    customer_name,
                    count, offset, sort, sort_by,
                    username, uri, method
                )
            )

            results = operations.get_all_by_agentid(agent_id)

            self.set_status(results['http_status'])
            self.set_header('Content-Type', 'application/json')
            self.write(json.dumps(results, indent=4))

        except Exception as e:
            results = (
                GenericResults(
                    username, uri, method
                ).something_broke('operation', 'search by oper type', e)
            )
            logger.exception(results)
            self.set_status(results['http_status'])
            self.set_header('Content-Type', 'application/json')
            self.write(json.dumps(results, indent=4))


class TagOperationsHandler(BaseHandler):
    @authenticated_request
    def get(self, tag_id):
        username = self.get_current_user()
        customer_name = (
            get_user_property(username, UserKeys.CurrentCustomer)
        )
        uri = self.request.uri
        method = self.request.method
        try:
            count = (
                int(
                    self.get_argument(ApiArguments.COUNT,
                        DefaultQueryValues.COUNT
                    )
                )
            )
            offset = (
                int(
                    self.get_argument(
                        ApiArguments.OFFSET,
                        DefaultQueryValues.OFFSET
                    )
                )
            )
            sort = self.get_argument(ApiArguments.SORT, SortValues.DESC)
            sort_by = (
                self.get_argument(
                    ApiArguments.SORT_BY,
                    AgentOperationKeys.CreatedTime
                )
            )

            operations = (
                AgentOperationRetriever(
                    customer_name,
                    count, offset, sort, sort_by,
                    username, uri, method
                )
            )

            results = operations.get_all_by_tagid(tag_id)

            self.set_status(results['http_status'])
            self.set_header('Content-Type', 'application/json')
            self.write(json.dumps(results, indent=4))

        except Exception as e:
            results = (
                GenericResults(
                    username, uri, method
                ).something_broke('operation', 'search by oper type', e)
            )
            logger.exception(results)
            self.set_status(results['http_status'])
            self.set_header('Content-Type', 'application/json')
            self.write(json.dumps(results, indent=4))

class OperationHandler(BaseHandler):
    @authenticated_request
    def get(self, operation_id):
        username = self.get_current_user()
        customer_name = (
            get_user_property(username, UserKeys.CurrentCustomer)
        )
        uri = self.request.uri
        method = self.request.method
        try:
            count = (
                int(
                    self.get_argument(ApiArguments.COUNT,
                        DefaultQueryValues.COUNT
                    )
                )
            )
            offset = (
                int(
                    self.get_argument(
                        ApiArguments.OFFSET,
                        DefaultQueryValues.OFFSET
                    )
                )
            )
            sort = self.get_argument(ApiArguments.SORT, SortValues.DESC)
            sort_by = (
                self.get_argument(
                    ApiArguments.SORT_BY,
                    AgentOperationKeys.CreatedTime
                )
            )

            operations = (
                AgentOperationRetriever(
                    customer_name,
                    count, offset, sort, sort_by,
                    username, uri, method
                )
            )

            operation_data = get_agent_operation(operation_id)
            if operation_data:
                if re.search('install', operation_data[AgentOperationKeys.Operation]):
                    results = operations.get_install_operation_by_id(operation_id)
                else:
                    results = operations.get_operation_by_id(operation_id)
            self.set_status(results['http_status'])
            self.set_header('Content-Type', 'application/json')
            self.write(json.dumps(results, indent=4))

        except Exception as e:
            results = (
                GenericResults(
                    username, uri, method
                ).something_broke('operation', 'search by oper type', e)
            )
            logger.exception(results)
            self.set_status(results['http_status'])
            self.set_header('Content-Type', 'application/json')
            self.write(json.dumps(results, indent=4))
