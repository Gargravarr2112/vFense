import logging

from vFense import VFENSE_LOGGING_CONFIG
from vFense.core._constants import SortValues, DefaultQueryValues
from vFense.errorz._constants import ApiResultKeys

from vFense.core.agent._constants import AgentCommonKeys
from vFense.core.agent import AgentKeys 

from vFense.core.agent.search._db import FetchAgents
from vFense.core.decorators import time_it, results_message
from vFense.errorz.status_codes import GenericCodes, GenericFailureCodes

logging.config.fileConfig(VFENSE_LOGGING_CONFIG)
logger = logging.getLogger('rvapi')


class RetrieveAgents(object):
    def __init__(
        self, customer_name=None,
        count=DefaultQueryValues.COUNT,
        offset=DefaultQueryValues.OFFSET,
        sort=SortValues.ASC,
        sort_key=AgentKeys.ComputerName,
        user_name=None, uri=None, method=None
        ):

        self.user_name = user_name
        self.customer_name = customer_name
        self.uri = uri
        self.method = method
        self.count = count
        self.offset = offset
        self.sort = sort

        self.list_of_valid_keys = [
            AgentKeys.ComputerName, AgentKeys.HostName,
            AgentKeys.DisplayName, AgentKeys.OsCode,
            AgentKeys.OsString, AgentKeys.AgentId, AgentKeys.AgentStatus,
            AgentKeys.NeedsReboot, AgentKeys.BasicStats,
            AgentKeys.ProductionLevel, AgentKeys.LastAgentUpdate
        ]

        self.valid_keys_to_filter_by = (
            [
                AgentKeys.OsCode,
                AgentKeys.OsString,
                AgentKeys.AgentStatus,
                AgentKeys.ProductionLevel
            ]
        )

        valid_keys_to_sort_by = (
            [
                AgentKeys.ComputerName,
                AgentKeys.HostName,
                AgentKeys.DisplayName,
                AgentKeys.OsCode,
                AgentKeys.OsString,
                AgentKeys.AgentStatus,
                AgentKeys.ProductionLevel,
                AgentCommonKeys.AVAIL_VULN,
                AgentCommonKeys.AVAIL_UPDATES,
                AgentKeys.LastAgentUpdate,
            ]
        )
        if sort_key in valid_keys_to_sort_by:
            self.sort_key = sort_key
        else:
            self.sort_key = AgentKeys.ComputerName
        
        self.fetch_agents = (
            FetchAgents(
                customer_name, self.count, self.offset,
                self.sort, self.sort_key
            )
        )

    @time_it
    @results_message
    def by_name(self, query):
        """Query agents by computer and display name.
        Args:
            name (str): The regex you are searching by

        Basic Usage:
            >>> from vFense.core.agent.search.search import RetrieveAgents
            >>> customer_name = 'default'
            >>> search_agents = RetrieveAgents(customer_name='default')
            >>> search_agents.by_name('ubu')

        Returns:
            List of dictionairies.
            {
                "count": 1, 
                "uri": null, 
                "rv_status_code": 1001, 
                "http_method": null, 
                "http_status": 200, 
                "message": null, 
                "data": [
                    {
                        "display_name": null, 
                        "production_level": "Production", 
                        "tags": [
                            {
                                "tag_name": "Foo Bar", 
                                "tag_id": "6ef12d9d-a5a0-49c8-9890-206a7b362ce4"
                            }
                        ], 
                        "available_vulnerabilities": 8, 
                        "os_code": "linux", 
                        "available_updates": 17, 
                        "agent_status": "up", 
                        "agent_id": "d4119b36-fe3c-4973-84c7-e8e3d72a3e02", 
                        "computer_name": "ubuntu", 
                        "os_string": "Ubuntu 12.04", 
                        "needs_reboot": "no", 
                        "host_name": ""
                    }
                ]
            }
        """
        count, data = self.fetch_agents.by_name(query)
        generic_status_code = GenericCodes.InformationRetrieved

        if count == 0:
            vfense_status_code = GenericFailureCodes.DataIsEmpty
            msg = 'dataset is empty'

        else:
            vfense_status_code = GenericCodes.InformationRetrieved
            msg = 'dataset retrieved'

        results = (
            self._set_results(
                generic_status_code, vfense_status_code,
                msg, count, data
            )
        )

        return(results)


    @time_it
    @results_message
    def all(self):
        """Retrieve all agents.
        Basic Usage:
            >>> from vFense.core.agent.search.search import RetrieveAgents
            >>> customer_name = 'default'
            >>> search_agents = RetrieveAgents(customer_name='default')
            >>> search_agents.all()

        Returns:
            List of dictionairies.
            [
                {
                    "display_name": null, 
                    "production_level": "Production", 
                    "tags": [
                        {
                            "tag_name": "Foo Bar", 
                            "tag_id": "6ef12d9d-a5a0-49c8-9890-206a7b362ce4"
                        }
                    ], 
                    "available_vulnerabilities": 8, 
                    "os_code": "linux", 
                    "available_updates": 17, 
                    "agent_status": "up", 
                    "agent_id": "d4119b36-fe3c-4973-84c7-e8e3d72a3e02", 
                    "computer_name": "ubuntu", 
                    "os_string": "Ubuntu 12.04", 
                    "needs_reboot": "no", 
                    "host_name": ""
                }
            ]
        """
        count, data = self.fetch_agents.all()
        generic_status_code = GenericCodes.InformationRetrieved

        if count == 0:
            vfense_status_code = GenericFailureCodes.DataIsEmpty
            msg = 'dataset is empty'

        else:
            vfense_status_code = GenericCodes.InformationRetrieved
            msg = 'dataset retrieved'

        results = (
            self._set_results(
                generic_status_code, vfense_status_code,
                msg, count, data
            )
        )

        return(results)


    @time_it
    @results_message
    def by_key_and_val(self, fkey, fval):
        """Filter agents by a key and value.
        Args:
        fkey (str): The key you are filtering on.
            fval (str): The value for the key you are filtering on.

        Basic Usage:
            >>> from vFense.core.agent.search.search import RetrieveAgents
            >>> customer_name = 'default'
            >>> fkey = 'os_code'
            >>> fval = 'linux'
            >>> search_agents = RetrieveAgents(customer_name='default')
            >>> search_agents.by_key_and_val(fkey, fval)

        Returns:
            List of dictionairies.
            [
                {
                    "display_name": null, 
                    "production_level": "Production", 
                    "tags": [
                        {
                            "tag_name": "Foo Bar", 
                            "tag_id": "6ef12d9d-a5a0-49c8-9890-206a7b362ce4"
                        }
                    ], 
                    "available_vulnerabilities": 8, 
                    "os_code": "linux", 
                    "available_updates": 17, 
                    "agent_status": "up", 
                    "agent_id": "d4119b36-fe3c-4973-84c7-e8e3d72a3e02", 
                    "computer_name": "ubuntu", 
                    "os_string": "Ubuntu 12.04", 
                    "needs_reboot": "no", 
                    "host_name": ""
                }
            ]
        """
        count = 0
        data = []

        if fkey in self.valid_keys_to_filter_by:
            count, data = self.fetch_agents.by_key_and_val(fkey, fval)

            if count == 0:
                generic_status_code = GenericCodes.InformationRetrieved
                vfense_status_code = GenericFailureCodes.DataIsEmpty
                msg = 'dataset is empty'

            else:
                generic_status_code = GenericCodes.InformationRetrieved
                vfense_status_code = GenericCodes.InformationRetrieved
                msg = 'dataset retrieved'

        else:
            generic_status_code = GenericFailureCodes.FailedToRetrieveObject
            vfense_status_code = GenericFailureCodes.InvalidFilterKeys

        results = (
            self._set_results(
                generic_status_code, vfense_status_code,
                msg, count, data
            )
        )

        return(results)


    @time_it
    @results_message
    def by_key_and_val_and_query(self, fkey, fval, query):
        """Filter agents based on a key and value, while
            searching by computer and display name.
        Args:
            fkey (str): The key you are filtering on.
            fval (str): The value for the key you are filtering on.

        Basic Usage:
            >>> from vFense.core.agent.search.search import RetrieveAgents
            >>> customer_name = 'default'
            >>> fkey = 'os_code'
            >>> fval = 'linux'
            >>> query = 'ubu'
            >>> search_agents = RetrieveAgents(customer_name='default')
            >>> search_agents.by_key_and_value_and_query(fkey, fval, query)

        Returns:
            List of dictionairies.
            [
                {
                    "display_name": null, 
                    "production_level": "Production", 
                    "tags": [
                        {
                            "tag_name": "Foo Bar", 
                            "tag_id": "6ef12d9d-a5a0-49c8-9890-206a7b362ce4"
                        }
                    ], 
                    "available_vulnerabilities": 8, 
                    "os_code": "linux", 
                    "available_updates": 17, 
                    "agent_status": "up", 
                    "agent_id": "d4119b36-fe3c-4973-84c7-e8e3d72a3e02", 
                    "computer_name": "ubuntu", 
                    "os_string": "Ubuntu 12.04", 
                    "needs_reboot": "no", 
                    "host_name": ""
                }
            ]
        """
        count = 0
        data = []

        if fkey in self.valid_keys_to_filter_by:
            count, data = (
                self.fetch_agents.by_key_and_val_and_query(
                    fkey, fval, query
                )
            )

            if count == 0:
                generic_status_code = GenericCodes.InformationRetrieved
                vfense_status_code = GenericFailureCodes.DataIsEmpty
                msg = 'dataset is empty'

            else:
                generic_status_code = GenericCodes.InformationRetrieved
                vfense_status_code = GenericCodes.InformationRetrieved
                msg = 'dataset retrieved'

        else:
            generic_status_code = GenericFailureCodes.FailedToRetrieveObject
            vfense_status_code = GenericFailureCodes.InvalidFilterKeys

        results = (
            self._set_results(
                generic_status_code, vfense_status_code,
                msg, count, data
            )
        )

        return(results)


    @time_it
    @results_message
    def by_ip(self, ip):
        """Search agents based on an ip address.
        Args:
            ip (str): The ip address you are searching for.

        Basic Usage:
            >>> from vFense.core.agent.search.search import RetrieveAgents
            >>> customer_name = 'default'
            >>> ip = '192.168.0.101'
            >>> search_agents = RetrieveAgents(customer_name='default')
            >>> search_agents.by_ip(ip)

        Returns:
            List of dictionairies.
            [
                {
                    "display_name": null, 
                    "production_level": "Production", 
                    "tags": [
                        {
                            "tag_name": "Foo Bar", 
                            "tag_id": "6ef12d9d-a5a0-49c8-9890-206a7b362ce4"
                        }
                    ], 
                    "available_vulnerabilities": 8, 
                    "os_code": "linux", 
                    "available_updates": 17, 
                    "agent_status": "up", 
                    "agent_id": "d4119b36-fe3c-4973-84c7-e8e3d72a3e02", 
                    "computer_name": "ubuntu", 
                    "os_string": "Ubuntu 12.04", 
                    "needs_reboot": "no", 
                    "host_name": ""
                }
            ]
        """
        count, data = self.fetch_agents.by_ip(ip)
        generic_status_code = GenericCodes.InformationRetrieved

        if count == 0:
            vfense_status_code = GenericFailureCodes.DataIsEmpty
            msg = 'dataset is empty'

        else:
            vfense_status_code = GenericCodes.InformationRetrieved
            msg = 'dataset retrieved'

        results = (
            self._set_results(
                generic_status_code, vfense_status_code,
                msg, count, data
            )
        )

        return(results)


    @time_it
    @results_message
    def by_ip_and_filter(self, ip, fkey, fval):
        """Search agents by ip address while filtering
            based on a key and value.
        Args:
            ip (str): The ip address you are searching for.
            fkey (str): The key you are filtering on.
            fval (str): The value for the key you are filtering on.

        Basic Usage:
            >>> from vFense.core.agent.search.search import RetrieveAgents
            >>> customer_name = 'default'
            >>> ip = '192.168'
            >>> fkey = 'os_code'
            >>> fval = 'linux'
            >>> search_agents = RetrieveAgents(customer_name='default')
            >>> search_agents.by_ip_and_filter(ip, fkey, fval)

        Returns:
            List of dictionairies.
            [
                {
                    "display_name": null, 
                    "production_level": "Production", 
                    "tags": [
                        {
                            "tag_name": "Foo Bar", 
                            "tag_id": "6ef12d9d-a5a0-49c8-9890-206a7b362ce4"
                        }
                    ], 
                    "available_vulnerabilities": 8, 
                    "os_code": "linux", 
                    "available_updates": 17, 
                    "agent_status": "up", 
                    "agent_id": "d4119b36-fe3c-4973-84c7-e8e3d72a3e02", 
                    "computer_name": "ubuntu", 
                    "os_string": "Ubuntu 12.04", 
                    "needs_reboot": "no", 
                    "host_name": ""
                }
            ]
        """
        count = 0
        data = []
        if fkey in self.valid_keys_to_filter_by:
            count, data = self.fetch_agents.by_ip_and_filter(ip, fkey, fval)

            if count == 0:
                generic_status_code = GenericCodes.InformationRetrieved
                vfense_status_code = GenericFailureCodes.DataIsEmpty
                msg = 'dataset is empty'

            else:
                generic_status_code = GenericCodes.InformationRetrieved
                vfense_status_code = GenericCodes.InformationRetrieved
                msg = 'dataset retrieved'

        else:
            generic_status_code = GenericFailureCodes.FailedToRetrieveObject
            vfense_status_code = GenericFailureCodes.InvalidFilterKeys

        results = (
            self._set_results(
                generic_status_code, vfense_status_code,
                msg, count, data
            )
        )

        return(results)


    @time_it
    @results_message
    def by_mac(self, mac):
        """Search agents based on an mac address.
        Args:
            mac (str): The mac address you are searching for.

        Basic Usage:
            >>> from vFense.core.agent.search.search import RetrieveAgents
            >>> customer_name = 'default'
            >>> mac = '000c292672d6'
            >>> search_agents = RetrieveAgents(customer_name='default')
            >>> search_agents.by_mac(mac)

        Returns:
            List of dictionairies.
            [
                {
                    "display_name": null, 
                    "production_level": "Production", 
                    "tags": [
                        {
                            "tag_name": "Foo Bar", 
                            "tag_id": "6ef12d9d-a5a0-49c8-9890-206a7b362ce4"
                        }
                    ], 
                    "available_vulnerabilities": 8, 
                    "os_code": "linux", 
                    "available_updates": 17, 
                    "agent_status": "up", 
                    "agent_id": "d4119b36-fe3c-4973-84c7-e8e3d72a3e02", 
                    "computer_name": "ubuntu", 
                    "os_string": "Ubuntu 12.04", 
                    "needs_reboot": "no", 
                    "host_name": ""
                }
            ]
        """

        count, data = self.fetch_agents.by_mac(mac)
        generic_status_code = GenericCodes.InformationRetrieved

        if count == 0:
            vfense_status_code = GenericFailureCodes.DataIsEmpty
            msg = 'dataset is empty'

        else:
            vfense_status_code = GenericCodes.InformationRetrieved
            msg = 'dataset retrieved'

        results = (
            self._set_results(
                generic_status_code, vfense_status_code,
                msg, count, data
            )
        )

        return(results)


    @time_it
    @results_message
    def by_mac_and_filter(self, mac, fkey, fval):
        """Search agents by mac address while filtering
            based on a key and value.
        Args:
            mac (str): The mac address you are searching for.
            fkey (str): The key you are filtering on.
            fval (str): The value for the key you are filtering on.

        Basic Usage:
            >>> from vFense.core.agent.search.search import RetrieveAgents
            >>> customer_name = 'default'
            >>> mac = '000c292672d6'
            >>> fkey = 'os_code'
            >>> fval = 'linux'
            >>> search_agents = RetrieveAgents(customer_name='default')
            >>> search_agents.by_mac_and_filter(mac, fkey, fval)

        Returns:
            List of dictionairies.
            [
                {
                    "display_name": null, 
                    "production_level": "Production", 
                    "tags": [
                        {
                            "tag_name": "Foo Bar", 
                            "tag_id": "6ef12d9d-a5a0-49c8-9890-206a7b362ce4"
                        }
                    ], 
                    "available_vulnerabilities": 8, 
                    "os_code": "linux", 
                    "available_updates": 17, 
                    "agent_status": "up", 
                    "agent_id": "d4119b36-fe3c-4973-84c7-e8e3d72a3e02", 
                    "computer_name": "ubuntu", 
                    "os_string": "Ubuntu 12.04", 
                    "needs_reboot": "no", 
                    "host_name": ""
                }
            ]
        """
        count = 0
        data = []
        if fkey in self.valid_keys_to_filter_by:
            count, data = self.fetch_agents.by_mac_and_filter(mac, fkey, fval)

            if count == 0:
                generic_status_code = GenericCodes.InformationRetrieved
                vfense_status_code = GenericFailureCodes.DataIsEmpty
                msg = 'dataset is empty'

            else:
                generic_status_code = GenericCodes.InformationRetrieved
                vfense_status_code = GenericCodes.InformationRetrieved
                msg = 'dataset retrieved'

        else:
            generic_status_code = GenericFailureCodes.FailedToRetrieveObject
            vfense_status_code = GenericFailureCodes.InvalidFilterKeys

        results = (
            self._set_results(
                generic_status_code, vfense_status_code,
                msg, count, data
            )
        )

        return(results)


    def _set_results(self, gen_status_code, vfense_status_code,
                     msg, count, data):

        results = {
            ApiResultKeys.GENERIC_STATUS_CODE: gen_status_code,
            ApiResultKeys.VFENSE_STATUS_CODE: vfense_status_code,
            ApiResultKeys.MESSAGE: msg,
            ApiResultKeys.COUNT: count,
            ApiResultKeys.DATA: data,
            ApiResultKeys.USERNAME: self.user_name,
            ApiResultKeys.URI: self.uri,
            ApiResultKeys.HTTP_METHOD: self.method
        }

        return(results)
