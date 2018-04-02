import logging

from vFense import VFENSE_LOGGING_CONFIG
from vFense.db.client import db_create_close, r
from vFense.core._constants import SortValues, DefaultQueryValues
from vFense.core.agent._constants import AgentCommonKeys
from vFense.core.agent import AgentKeys, AgentCollections, \
    HardwarePerAgentIndexes, HardwarePerAgentKeys
from vFense.core.tag import TagCollections, TagsKeys, TagsPerAgentKeys, \
    TagsPerAgentIndexes
from vFense.plugins.patching import AppCollections, AppsKeys, \
     AppsPerAgentIndexes
from vFense.plugins.patching import *
from vFense.plugins.patching._constants import CommonAppKeys
from vFense.core.decorators import time_it

logging.config.fileConfig(VFENSE_LOGGING_CONFIG)
logger = logging.getLogger('rvapi')


class FetchAgents(object):
    """Agent database queries"""
    def __init__(
        self, customer_name=None,
        count=DefaultQueryValues.COUNT,
        offset=DefaultQueryValues.OFFSET,
        sort=SortValues.ASC,
        sort_key=AgentKeys.ComputerName
        ):
        """
        Kwargs:
            customer_name (str): Fetch all agents in this customer.
            count (int): The number of results to return.
            offset (int): The next set of results beginning at offset.
            sort (str): asc or desc.
            sort_key (str): The key you are going to sort the results by.
        """

        self.customer_name = customer_name
        self.count = count
        self.offset = offset
        self.sort_key = sort_key

        self.keys_to_pluck = [
            AgentKeys.ComputerName, AgentKeys.HostName,
            AgentKeys.DisplayName, AgentKeys.OsCode, AgentKeys.Tags,
            AgentKeys.OsString, AgentKeys.AgentId, AgentKeys.AgentStatus,
            AgentKeys.NeedsReboot, AgentKeys.ProductionLevel,
            AgentCommonKeys.AVAIL_UPDATES, AgentCommonKeys.AVAIL_VULN,
            AgentKeys.LastAgentUpdate
        ]

        if sort == SortValues.ASC:
            self.sort = r.asc
        else:
            self.sort = r.desc


    @time_it
    @db_create_close
    def by_name(self, name, conn=None):
        """Query agents by computer and display name.
        Args:
            name (str): The regex you are searching by

        Basic Usage:
            >>> from vFense.core.agent.search._db import FetchAgents
            >>> customer_name = 'default'
            >>> search_agents = FetchAgents(customer_name='default')
            >>> search_agents.by_name('ubu')

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
        merge_query = self._set_merge_query()
        try:
            base_filter = self._set_agent_base_query()
            count = (
                base_filter
                .filter(
                    (r.row[AgentKeys.ComputerName].match("(?i)"+name))
                    |
                    (r.row[AgentKeys.DisplayName].match("(?i)"+name))
                )
                .count()
                .run(conn)
            )

            data = list(
                base_filter
                .filter(
                    (r.row[AgentKeys.ComputerName].match("(?i)"+name))
                    |
                    (r.row[AgentKeys.DisplayName].match("(?i)"+name))
                )
                .merge(merge_query)
                .pluck(self.keys_to_pluck)
                .order_by(self.sort(self.sort_key))
                .skip(self.offset)
                .limit(self.count)
                .run(conn)
            )

        except Exception as e:
            logger.exception(e)

        return(count, data)

    @time_it
    @db_create_close
    def all(self, conn=None):
        """Retrieve all agents.
        Basic Usage:
            >>> from vFense.core.agent.search._db import FetchAgents
            >>> customer_name = 'default'
            >>> search_agents = FetchAgents(customer_name='default')
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
        count = 0
        data = []
        try:
            base_filter = self._set_agent_base_query()
            query_merge = self._set_merge_query()
            count = (
                base_filter
                .count()
                .run(conn)
            )

            data = list(
                base_filter
                .merge(query_merge)
                .order_by(AgentKeys.ComputerName)
                .pluck(self.keys_to_pluck)
                .order_by(self.sort(self.sort_key))
                .skip(self.offset)
                .limit(self.count)
                .run(conn)
            )

        except Exception as e:
            logger.exception(e)

        return(count, data)

    @time_it
    @db_create_close
    def by_key_and_val(self, fkey, fval, conn=None):
        """Filter agents by a key and value.
        Args:
            fkey (str): The key you are filtering on.
            fval (str): The value for the key you are filtering on.

        Basic Usage:
            >>> from vFense.core.agent.search._db import FetchAgents
            >>> customer_name = 'default'
            >>> fkey = 'os_code'
            >>> fval = 'linux'
            >>> search_agents = FetchAgents(customer_name='default')
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
        try:
            base_filter = self._set_agent_base_query()
            query_merge = self._set_merge_query()
            count = (
                base_filter
                .filter({fkey: fval})
                .count()
                .run(conn)
            )

            data = list(
                base_filter
                .filter({fkey: fval})
                .merge(query_merge)
                .pluck(self.keys_to_pluck)
                .order_by(self.sort(self.sort_key))
                .skip(self.offset)
                .limit(self.count)
                .run(conn)
            )


        except Exception as e:
            logger.exception(e)

        return(count, data)
    
    @time_it
    @db_create_close
    def by_key_and_value_and_query(self, fkey, fval, query, conn=None):
        """Filter agents based on a key and value, while
            searching by computer and display name.
        Args:
            fkey (str): The key you are filtering on.
            fval (str): The value for the key you are filtering on.

        Basic Usage:
            >>> from vFense.core.agent.search._db import FetchAgents
            >>> customer_name = 'default'
            >>> fkey = 'os_code'
            >>> fval = 'linux'
            >>> query = 'ubu'
            >>> search_agents = FetchAgents(customer_name='default')
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
        try:
            base_filter = self._set_agent_base_query()
            query_merge = self._set_merge_query()
            count = (
                base_filter
                .filter({fkey: fval})
                .filter(
                    (r.row[AgentKeys.ComputerName].match("(?i)"+query))
                    |
                    (r.row[AgentKeys.DisplayName].match("(?i)"+query))
                )
                .count()
                .run(conn)
            )

            data = list(
                base_filter
                .filter({fkey: fval})
                .filter(
                    (r.row[AgentKeys.ComputerName].match("(?i)"+query))
                    |
                    (r.row[AgentKeys.DisplayName].match("(?i)"+query))
                )
                .merge(query_merge)
                .pluck(self.keys_to_pluck)
                .order_by(self.sort(self.sort_key))
                .skip(self.offset)
                .limit(self.count)
                .run(conn)
            )

        except Exception as e:
            logger.exception(e)

        return(count, data)

    @time_it
    @db_create_close
    def by_ip(self, ip, conn=None):
        """Search agents based on an ip address.
        Args:
            ip (str): The ip address you are searching for.

        Basic Usage:
            >>> from vFense.core.agent.search._db import FetchAgents
            >>> customer_name = 'default'
            >>> ip = '192.168.0.101'
            >>> search_agents = FetchAgents(customer_name='default')
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
        count = 0
        data = []
        try:
            base_count, base_filter = self._set_hw_base_query_by_nic()
            query_merge = self._set_merge_query()
            count = (
                base_count
                .filter(
                    r.row[HardwarePerAgentKeys.IpAddress].match("(?i)"+ip)
                )
                .pluck(self.keys_to_pluck)
                .distinct()
                .count()
                .run(conn)
            )

            data = list(
                base_filter
                .filter(
                    r.row[HardwarePerAgentKeys.IpAddress].match("(?i)"+ip)
                )
                .merge(query_merge)
                .pluck(self.keys_to_pluck)
                .distinct()
                .order_by(self.sort(self.sort_key))
                .skip(self.offset)
                .limit(self.count)
                .run(conn)
            )

        except Exception as e:
            logger.exception(e)

        return(count, data)

    @time_it
    @db_create_close
    def by_ip_and_filter(self, ip, fkey, fval, conn=None):
        """Search agents by ip address while filtering
            based on a key and value.
        Args:
            ip (str): The ip address you are searching for.
            fkey (str): The key you are filtering on.
            fval (str): The value for the key you are filtering on.

        Basic Usage:
            >>> from vFense.core.agent.search._db import FetchAgents
            >>> customer_name = 'default'
            >>> ip = '192.168'
            >>> fkey = 'os_code'
            >>> fval = 'linux'
            >>> search_agents = FetchAgents(customer_name='default')
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
        try:
            base_count, base_filter = self._set_hw_base_query_by_nic()
            query_merge = self._set_merge_query()
            count = (
                base_count
                .filter({fkey: fval})
                .filter(r.row[HardwarePerAgentKeys.IpAddress].match("(?i)"+ip))
                .pluck(self.keys_to_pluck)
                .distinct()
                .count()
                .run(conn)
            )

            data = list(
                base_filter
                .filter({fkey: fval})
                .filter(r.row[HardwarePerAgentKeys.IpAddress].match("(?i)"+ip))
                .merge(query_merge)
                .pluck(self.keys_to_pluck)
                .distinct()
                .order_by(self.sort(self.sort_key))
                .skip(self.offset)
                .limit(self.count)
                .run(conn)
            )

        except Exception as e:
            logger.exception(e)

        return(count, data)

    @time_it
    @db_create_close
    def by_mac(self, mac, conn=None):
        """Search agents based on an mac address.
        Args:
            mac (str): The mac address you are searching for.

        Basic Usage:
            >>> from vFense.core.agent.search._db import FetchAgents
            >>> customer_name = 'default'
            >>> mac = '000c292672d6'
            >>> search_agents = FetchAgents(customer_name='default')
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
        count = 0
        data = []
        try:
            base_count, base_filter = self._set_hw_base_query_by_nic()
            query_merge = self._set_merge_query()
            count = (
                base_count
                .filter(r.row[HardwarePerAgentKeys.Mac].match("(?i)"+mac))
                .pluck(self.keys_to_pluck)
                .distinct()
                .count()
                .run(conn)
            )

            data = list(
                base_filter
                .filter(r.row[HardwarePerAgentKeys.Mac].match("(?i)"+mac))
                .merge(query_merge)
                .pluck(self.keys_to_pluck)
                .distinct()
                .order_by(self.sort(self.sort_key))
                .skip(self.offset)
                .limit(self.count)
                .run(conn)
            )

        except Exception as e:
            logger.exception(e)

        return(count, data)

    @time_it
    @db_create_close
    def by_mac_and_filter(self, mac, fkey, fval, conn=None):
        """Search agents by mac address while filtering
            based on a key and value.
        Args:
            mac (str): The mac address you are searching for.
            fkey (str): The key you are filtering on.
            fval (str): The value for the key you are filtering on.

        Basic Usage:
            >>> from vFense.core.agent.search._db import FetchAgents
            >>> customer_name = 'default'
            >>> mac = '000c292672d6'
            >>> fkey = 'os_code'
            >>> fval = 'linux'
            >>> search_agents = FetchAgents(customer_name='default')
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
        try:
            base_count, base_filter = self._set_hw_base_query_by_nic()
            query_merge = self._set_merge_query()
            count = (
                base_count
                .filter({fkey: fval})
                .filter(r.row[HardwarePerAgentKeys.Mac].match("(?i)"+mac))
                .pluck(self.keys_to_pluck)
                .distinct()
                .count()
                .run(conn)
            )

            data = list(
                base_filter
                .filter({fkey: fval})
                .filter(r.row[HardwarePerAgentKeys.Mac].match("(?i)"+mac))
                .merge(query_merge)
                .pluck(self.keys_to_pluck)
                .distinct()
                .order_by(self.sort(self.sort_key))
                .skip(self.offset)
                .limit(self.count)
                .run(conn)
            )

        except Exception as e:
            logger.exception(e)

        return(count, data)

    def _set_merge_query(self):
        merge_query = (
            lambda x:
            {
                TagCollections.Tags: (
                    r
                    .table(TagCollections.TagsPerAgent)
                    .get_all(
                        x[TagsPerAgentKeys.AgentId],
                        index=TagsPerAgentIndexes.AgentId
                    )
                    .eq_join(
                        TagsKeys.TagId,
                        r.table(TagCollections.Tags)
                    )
                    .zip()
                    .pluck(
                        TagsPerAgentKeys.TagId,
                        TagsPerAgentKeys.TagName
                    )
                    .coerce_to('array')
                ),
                AgentCommonKeys.AVAIL_UPDATES: (
                    r
                    .table(AppCollections.AppsPerAgent)
                    .get_all(
                        [
                            CommonAppKeys.AVAILABLE,
                            x[AgentKeys.AgentId]
                        ],
                        index=AppsPerAgentIndexes.StatusAndAgentId
                    )
                    .count()
                ),
                AgentCommonKeys.AVAIL_VULN: (
                    r
                    .table(AppCollections.AppsPerAgent)
                    .get_all(
                        [
                            CommonAppKeys.AVAILABLE,
                            x[AgentKeys.AgentId]
                        ],
                        index=AppsPerAgentIndexes.StatusAndAgentId
                    )
                    .eq_join(
                        lambda y:
                        y[AppsKeys.AppId], 
                        r.table(AppCollections.UniqueApplications)
                    )
                    .zip()
                    .filter(
                        lambda z:
                        z[AppsKeys.VulnerabilityId] != ''
                    )
                    .count()
                ),
                AgentKeys.LastAgentUpdate: (
                    x[AgentKeys.LastAgentUpdate].to_epoch_time()
                )
            }
        )

        return(merge_query)

    def _set_agent_base_query(self):
        base_filter = (
            r
            .table(AgentCollections.Agents)
        )
        if self.customer_name:
            base_filter = (
                r
                .table(AgentCollections.Agents)
                .get_all(
                    self.customer_name,
                    index=AgentKeys.CustomerName
                )
            )

        return(base_filter)

    def _set_hw_base_query_by_nic(self):
        base_filter = (
            r
            .table(AgentCollections.Hardware)
            .eq_join(
                HardwarePerAgentKeys.AgentId,
                r.table(AgentCollections.Agent)
            )
            .zip()
        )
        base_count = (
            r
            .table(AgentCollections.Hardware)
        )
        if self.customer_name:
            base_count = (
                r
                .table(AgentCollections.Hardware)
                .get_all(
                    HardwarePerAgentKeys.Nic,
                    index=HardwarePerAgentIndexes.Type
                )
            )

            base_filter = (
                r
                .table(AgentCollections.Hardware)
                .get_all(
                    HardwarePerAgentKeys.Nic,
                    index=HardwarePerAgentIndexes.Type
                )
                .eq_join(
                    HardwarePerAgentKeys.AgentId,
                    r.table(AgentCollections.Agents)
                )
                .zip()
            )

        return(base_count, base_filter)
