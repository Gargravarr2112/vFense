import logging

from vFense import VFENSE_LOGGING_CONFIG
from vFense.core._constants import CommonKeys
from vFense.core._db import insert_data_in_table, \
    update_data_in_table
from vFense.core.decorators import return_status_tuple, time_it
from vFense.plugins.patching._db_sub_queries import AppsMerge
from vFense.plugins.patching._constants import CommonFileKeys
from vFense.plugins.patching import (
    AppCollections, FileCollections, AppsKeys,
    DbCommonAppKeys, DbCommonAppPerAgentKeys,
    DbCommonAppIndexes, DbCommonAppPerAgentIndexes, FilesKeys,
    FileServerIndexes, FileServerKeys
)

from vFense.db.client import db_create_close, r

logging.config.fileConfig(VFENSE_LOGGING_CONFIG)
logger = logging.getLogger('rvapi')

@time_it
@db_create_close
def fetch_file_servers_addresses(customer_name, conn=None):
    """Fetch file servers for customer name. This will
        retrieve a list of addresses (ip_addresses or hostnames)
    Args:
        customer_name (str): The name of the customer

    Basic Usage:
        >>> from vFense.plugins.patching._db import fetch_file_servers_addresses
        >>> customer_name = 'default'
        >>> fetch_file_servers_addresses(customer_name)

    Returns:
        List of addresses
    """
    data = []
    try:
        data = list(
            r
            .table(FileCollections.FileServers)
            .get_all(customer_name, index=FileServerIndexes.CustomerName)
            .map(lambda x: x[FileServerKeys.Customers])
            .run(conn)
        )

    except Exception as e:
        logger.exception(e)

    return data

@db_create_close
def fetch_app_data(
        app_id, collection=AppCollections.UniqueApplications,
        fields_to_pluck=None, conn=None
    ):
    """Fetch application data by app id
    Args:
        app_id (str): 64 character ID of the application.

    Kwargs:
        collection (str): The name of the apps per agent collection,
            that will be used when updating the application data.
            default = unique_applications

    Basic Usage:
        >>> from vFense.plugins.patching._db import fetch_app_data
        >>> app_id = '15fa819554aca425d7f699e81a2097898b06f00a0f2dd6e8d51a18405360a6eb'
        >>> collection = 'unique_applications'
        >>> fetch_app_data(app_id, collection)

    Returns:
        Dictionary
    """
    data = {}
    merge = AppsMerge.RELEASE_DATE
    try:
        if fields_to_pluck:
            data = (
                r
                .table(collection)
                .get(app_id)
                .merge(merge)
                .pluck(fields_to_pluck)
                .run(conn)
            )

        else:
            data = (
                r
                .table(collection)
                .get(app_id)
                .merge(merge)
                .run(conn)
            )

    except Exception as e:
        logger.exception(e)

    return data

@db_create_close
def fetch_app_data_by_appids(
        app_ids, collection=AppCollections.UniqueApplications,
        fields_to_pluck=None, conn=None
    ):
    """Fetch application data by application ids
    Args:
        app_ids (str): List of application ids.

    Kwargs:
        collection (str): The name of the apps per agent collection,
            that will be used when searching for the application data.
            default = unique_applications

    Basic Usage:
        >>> from vFense.plugins.patching._db import fetch_app_data_by_appids
        >>> app_ids = ['15fa819554aca425d7f699e81a2097898b06f00a0f2dd6e8d51a18405360a6eb']
        >>> collection = 'unique_applications'
        >>> fetch_app_data_by_appids(app_ids, collection)

    Returns:
        Dictionary
    """
    data = {}
    try:
        if fields_to_pluck:
            data = list(
                r
                .expr(app_ids)
                .map(
                    lambda app_id:
                    r
                    .table(collection)
                    .get(app_id)
                    .merge(
                        lambda x: 
                        {
                            DbCommonAppKeys.ReleaseDate: (
                                x[DbCommonAppKeys.ReleaseDate].to_epoch_time()
                            )
                        }
                    )
                    .pluck(fields_to_pluck)
                )
                .run(conn)
            )

        else:
            data = list(
                r
                .expr(app_ids)
                .map(
                    lambda app_id:
                    r
                    .table(collection)
                    .get(app_id)
                    .merge(
                        lambda x:
                        {
                            DbCommonAppKeys.ReleaseDate: (
                                x[DbCommonAppKeys.ReleaseDate].to_epoch_time()
                            )
                        }
                    )
                )
                .run(conn)
            )

    except Exception as e:
        logger.exception(e)

    return data

@db_create_close
def fetch_app_data_by_appid_and_agentid(
        app_id, agent_id, collection=AppCollections.AppsPerAgent,
        fields_to_pluck=None, conn=None
    ):
    """Fetch application data by app id
    Args:
        app_id (str): 64 character ID of the application.
        agent_id (str): 36 character UUID of the agent.

    Kwargs:
        collection (str): The name of the apps per agent collection,
            that will be used when updating the application data.

    Basic Usage:
        >>> from vFense.plugins.patching._db import fetch_app_data
        >>> app_id = '15fa819554aca425d7f699e81a2097898b06f00a0f2dd6e8d51a18405360a6eb'
        >>> agent_id = '7f242ab8-a9d7-418f-9ce2-7bcba6c2d9dc'
        >>> collection = 'unique_applications'
        >>> fetch_app_data_by_agentid(app_id, agent_id, collection)

    Returns:
        Dictionary
        {
            "kb": "",
            "customers": [
                "default"
            ],
            "vendor_name": "",
            "description": "Facebook plugin for Gwibber\n Gwibber is a social networking client for GNOME. It supports Facebook,\n Twitter, Identi.ca, StatusNet, FriendFeed, Qaiku, Flickr, and Digg.\n .",
            "vulnerability_categories": [],
            "files_download_status": 5004,
            "release_date": 1394769600,
            "vendor_severity": "recommended",
            "app_id": "922bcb88f6bd75c1e40fcc0c571f603cd59cf7e05b4a192bd5d69c974acc1457",
            "reboot_required": "no",
            "os_code": "linux",
            "repo": "precise-updates/main",
            "support_url": "",
            "version": "3.4.2-0ubuntu2.4",
            "cve_ids": [],
            "rv_severity": "Recommended",
            "hidden": "no",
            "uninstallable": "yes",
            "vulnerability_id": "",
            "name": "gwibber-service-facebook"
        }
    """

    data = {}
    index_to_use = DbCommonAppPerAgentIndexes.AgentIdAndAppId
    try:
        if fields_to_pluck:
            data = list(
                r
                .table(collection)
                .get_all([agent_id, app_id], index=index_to_use)
                .pluck(fields_to_pluck)
                .run(conn)
            )
            if data:
                data = data[0]

        else:
            data = list(
                r
                .table(collection)
                .get_all([agent_id, app_id], index=index_to_use)
                .run(conn)
            )
            if data:
                data = data[0]

    except Exception as e:
        logger.exception(e)

    return data

@db_create_close
def fetch_apps_data_by_os_code(
        os_code, customer_name=None,
        collection=AppCollections.UniqueApplications,
        fields_to_pluck=None, conn=None
    ):
    """Fetch application data by app id
    Args:
        os_code (str): linux or darwin or windows

    Kwargs:
        customer_name (str, optional): The name of the customer
            you are searching on.
        collection (str, optional): The name of the collection,
            default = unique_applications.
        fields_to_pluck (list, optional): Fields you want to pluck from
            the database.

    Basic Usage:
        >>> from vFense.plugins.patching._db import fetch_apps_data_by_os_code
        >>> collection = 'unique_applications'
        >>> os_code = 'linux'
        >>> customer_name = 'default'
        >>> fetch_apps_data_by_os_code(os_code, customer_name. collection)

    Returns:
        List of dictionaries.
        [
            {
                "kb": "",
                "customers": [
                    "default"
                ],
                "vendor_name": "",
                "description": "Facebook plugin for Gwibber\n Gwibber is a social networking client for GNOME. It supports Facebook,\n Twitter, Identi.ca, StatusNet, FriendFeed, Qaiku, Flickr, and Digg.\n .",
                "vulnerability_categories": [],
                "files_download_status": 5004,
                "release_date": 1394769600,
                "vendor_severity": "recommended",
                "app_id": "922bcb88f6bd75c1e40fcc0c571f603cd59cf7e05b4a192bd5d69c974acc1457",
                "reboot_required": "no",
                "os_code": "linux",
                "repo": "precise-updates/main",
                "support_url": "",
                "version": "3.4.2-0ubuntu2.4",
                "cve_ids": [],
                "rv_severity": "Recommended",
                "hidden": "no",
                "uninstallable": "yes",
                "vulnerability_id": "",
                "name": "gwibber-service-facebook"
            }
        ]
    """

    data = {}
    index_to_use = DbCommonAppIndexes.Customers
    merge = AppsMerge.RELEASE_DATE
    try:
        if customer_name and fields_to_pluck:
            data = list(
                r
                .table(collection)
                .get_all(customer_name, index=index_to_use)
                .filter({AppsKeys.OsCode: os_code})
                .merge(merge)
                .pluck(fields_to_pluck)
                .run(conn)
            )

        elif customer_name and not fields_to_pluck:
            data = list(
                r
                .table(collection)
                .get_all(customer_name, index=index_to_use)
                .filter({AppsKeys.OsCode: os_code})
                .merge(merge)
                .run(conn)
            )

        elif not customer_name and fields_to_pluck:
            data = list(
                r
                .table(collection)
                .filter({AppsKeys.OsCode: os_code})
                .merge(merge)
                .pluck(fields_to_pluck)
                .run(conn)
            )

        else:
            data = list(
                r
                .table(collection)
                .filter({AppsKeys.OsCode: os_code})
                .merge(merge)
                .run(conn)
            )

    except Exception as e:
        logger.exception(e)

    return data


@time_it
@db_create_close
def fetch_app_data_to_send_to_agent(
        app_id, agent_id,
        collection=AppCollections.UniqueApplications,
        conn=None
    ):
    """Fetch application data by app id
    Args:
        app_id (str): 64 character ID of the application.
        agent_id (str): 36 character UUID of the agent.

    Kwargs:
        collection (str): The name of the apps per agent collection,
            that will be used when updating the application data.

    Basic Usage:
        >>> from vFense.plugins.patching._db import fetch_app_data
        >>> app_id = 'c726edf62d1d17ca8b420f24bbdc9c8fa58d000b51d31614e3826c2fb37a2929'
        >>> agent_id = '33ba8521-b2e5-47dc-9bdc-0f1e3384049d'
        >>> collection = 'unique_applications'
        >>> fetch_app_data_by_agentid(app_id, agent_id, collection)

    Returns:
        Dictionary
        {
            "file_data": [
                {
                    "file_hash": "47dc1daa42e6d53e1a881f4ed9c5472f6732665af2cba082f8fa3931199fb746",
                    "file_name": "gpgv_1.4.11-3ubuntu2.5_amd64.deb",
                    "file_uri": "http://us.archive.ubuntu.com/ubuntu/pool/main/g/gnupg/gpgv_1.4.11-3ubuntu2.5_amd64.deb",
                    "file_size": 185400
                }
            ],
            "cli_options": "",
            "version": "1.4.11-3ubuntu2.5",
            "name": "gpgv"
        }
    """

    data = {}
    try:
        data = list(
            r
            .table(collection)
            .get_all(app_id)
            .map(
                lambda app:
                {
                    DbCommonAppKeys.Name: app[DbCommonAppKeys.Name],
                    DbCommonAppKeys.Version: app[DbCommonAppKeys.Version],
                    DbCommonAppKeys.CliOptions: (
                        r.branch(
                            app.has_fields(DbCommonAppKeys.CliOptions) == False,
                            '',
                            app[DbCommonAppKeys.CliOptions]
                        )
                    ),
                    CommonFileKeys.PKG_FILEDATA: (
                        r
                        .table(FileCollections.Files)
                        .filter(
                            lambda x: (
                                x[FilesKeys.AppIds].contains(app_id)
                                &
                                x[FilesKeys.AgentIds].contains(agent_id)
                            )
                        )
                        .coerce_to('array')
                        .without(FilesKeys.AppIds, FilesKeys.AgentIds)
                    )
                }
            )
            .run(conn)
        )
        if data:
            data = data[0]

    except Exception as e:
        logger.exception(e)

    return data

@db_create_close
def fetch_appids_by_agentid_and_status(agent_id, status, sev=None,
        collection=AppCollections.AppsPerAgent, conn=None):

    if collection == AppCollections.AppsPerAgent:
        join_table = AppCollections.UniqueApplications

    elif collection == AppCollections.CustomAppsPerAgent:
        join_table = AppCollections.CustomApps

    elif collection == AppCollections.SupportedAppsPerAgent:
        join_table = AppCollections.SupportedApps

    elif collection == AppCollections.vFenseAppsPerAgent:
        join_table = AppCollections.vFenseApps


    if sev:
        appids = list(
            r
            .table(collection)
            .get_all(
                [
                    status, agent_id
                ],
                index=DbCommonAppPerAgentIndexes.StatusAndAgentId
            )
            .eq_join(
                lambda x:
                [
                    x[DbCommonAppKeys.AppId],
                    sev
                ],
                r.table(join_table),
                index=DbCommonAppIndexes.AppIdAndRvSeverity
            )
            .map(
                lambda y: y['right'][DbCommonAppKeys.AppId]
            )
            .run(conn)
        )

    else:
        appids = list(
            r
            .table(collection)
            .get_all(
                [
                    status, agent_id
                ],
                index=DbCommonAppPerAgentIndexes.StatusAndAgentId
            )
            .map(
                lambda y: y[DbCommonAppPerAgentKeys.AppId]
            )
            .run(conn)
        )

    return appids


@time_it
@db_create_close
def fetch_app_id_by_name_and_version(app_name, app_version,
        collection=AppCollections.UniqueApplications, conn=None):

    """Fetch app_id by searching for the app name and version.
    Args:
        app_name (str): Name of the application you are removing
            from this agent.
        app_version (str): The exact verision of the application
            you are removing.

    Kwargs:
        collection (str): The name of the collection you are perfoming the delete on.
            default = 'unique_applications'

    Basic Usage:
        >>> from vFense.plugins.patching._db import fetch_app_id_by_name_and_version
        >>> app_name = 'libpangoxft-1.0-0'
        >>> app_version = '1.36.3-1ubuntu1'
        >>> collection = 'apps_per_agent'
        >>> fetch_app_id_by_name_and_version(name, version, collection)

    Returns:
        String
    """
    app_id = None
    try:
        app_ids = list(
            r
            .table(collection)
            .get_all(
                [app_name, app_version],
                index=DbCommonAppIndexes.NameAndVersion
            )
            .map(lambda app: app[DbCommonAppKeys.AppId])
            .run(conn)
        )
        if app_ids:
            app_id = app_ids[0]

    except Exception as e:
        logger.exception(e)

    return app_id

@time_it
@db_create_close
def return_valid_appids_for_agent(app_ids, agent_id,
        collection=AppCollections.AppsPerAgent, conn=None):

    """Return the valid application ids, from the list of application ids
        that were passed into this function
    Args:
        app_ids (list): List of application ids
        agent_id (str): The 36 character UUID of the agent.

    Kwargs:
        table (str): The name of the collection that will be queried.
            default = 'apps_per_agent'

    Basic Usage:
        >>> from vFense.plugins.patching._db import return_valid_appids_for_agent
        >>> app_ids = ['c726edf62d1d17ca8b420f24bbdc9c8fa58d000b51d31614e3826c2fb37a2929', 'foo']
        >>> agent_id = '33ba8521-b2e5-47dc-9bdc-0f1e3384049d'
        >>> collection = 'apps_per_agent'
        >>> return_valid_appids_for_agent(app_ids, agent_id, collection)

    Returns:
        List
        [
            "c726edf62d1d17ca8b420f24bbdc9c8fa58d000b51d31614e3826c2fb37a2929"
        ]
    """
    data = []
    try:
        data = (
            r
            .expr(app_ids)
            .map(
                lambda app_id:
                r
                .table(collection)
                .get_all(
                    [agent_id, app_id],
                    index=DbCommonAppPerAgentIndexes.AgentIdAndAppId
                )
                .coerce_to('array')
            )
            .concat_map(lambda app_id: app_id[DbCommonAppKeys.AppId])
            .run(conn)
        )

    except Exception as e:
        logger.exception(e)

    return data


@time_it
def insert_app_data(app_data, collection=AppCollections.UniqueApplications):
    """Insert application data in the unique_applications collection.
        This function should not be called directly.
    Args:
        app_data(list|dict): List of dictionaires or a
            dictionary of the application data.
    Kwargs:
        collection (str): The name of the apps per agent collection,
            that will be used when updating the application data.
            default = unique_applications

    Basic Usage:
        >>> from vFense.plugins.patching._db import insert_app_data
        >>> app_data = {
                "kb": "", "customers": ["default"],
                "vendor_name": "",
                "description": "Facebook plugin for Gwibber\n Gwibber is a social networking client for GNOME. It supports Facebook,\n Twitter, Identi.ca, StatusNet, FriendFeed, Qaiku, Flickr, and Digg.\n .",
                "vulnerability_categories": [], "files_download_status": 5004,
                "release_date": 1394769600,
                "vendor_severity": "recommended",
                "app_id": "922bcb88f6bd75c1e40fcc0c571f603cd59cf7e05b4a192bd5d69c974acc1457",
                "reboot_required": "no", "os_code": "linux",
                "repo": "precise-updates/main", "support_url": "",
                "version": "3.4.2-0ubuntu2.4", "cve_ids": [],
                "rv_severity": "Recommended", "hidden": "no",
                "uninstallable": "yes", "vulnerability_id": "",
                "name": "gwibber-service-facebook"
            }
        >>> insert_app_data(app_data, collection)

    Returns:
        Tuple (status_code, count, error, generated ids)
        >>> (2001, 1, None, [])
    """
    return insert_data_in_table(app_data, collection)


@time_it
@db_create_close
@return_status_tuple
def update_customers_in_apps_by_customer(current_customer, new_customer,
        remove_customer=False, collection=AppCollections.UniqueApplications,
        conn=None):

    """ Update the customers list of all applications for the current customer.
    Args:
        current_customer (str): Name of the current customer.
        new_customer (str): Name of the new customer.

    Kwargs:
        remove_customer (bool): True or False
            default = False
        collection (str): The Application Collection that is going to be used.
            default = unique_applications

    Basic Usage:
        >>> from vFense.plugins.patching._db import update_customers_in_apps
        >>> current_customer = 'default'
        >>> new_customer = 'test'
        >>> remove_customer = True
        >>> collection = 'apps_per_agent'
        >>> update_customers_in_apps(
                current_customer, new_customer,
                remove_customer, collection
            )

    Returns:
        Tuple (status_code, count, error, generated ids)
        >>> (2001, 1, None, [])
    """

    index_name = DbCommonAppIndexes.Customers
    data = {}
    try:
        if remove_customer:
            data = (
                r
                .table(collection)
                .get_all(
                    current_customer, index=index_name
                )
                .update(
                    {
                        DbCommonAppKeys.Customers: (
                            r.row[DbCommonAppKeys.Customers]
                            .difference([current_customer])
                            .set_insert(new_customer)
                        )
                    }
                )
                .run(conn)
            )

        else:
            data = (
                r
                .table(collection)
                .get_all(
                    current_customer, index=index_name
                )
                .update(
                    {
                        DbCommonAppKeys.Customers: (
                            r.row[DbCommonAppKeys.Customers]
                            .set_insert(new_customer)
                        )
                    }
                )
                .run(conn)
            )

    except Exception as e:
        logger.exception(e)

    return data


@time_it
@db_create_close
@return_status_tuple
def update_apps_per_agent_by_customer(
        customer_name, app_data,
        collection=AppCollections.AppsPerAgent,
        conn=None
    ):
    """ Update any keys for any apps collection by customer name
        This function should not be called directly.
    Args:
        customer_name (str): Name of the customer.
        app_data (dict): Dictionary of the key and values that you are updating.

    Kwargs:
        collection (str): The Application Collection that is going to be used.

    Basic Usage:
        >>> from vFense.plugins.patching._db import update_apps_per_agent_by_customer
        >>> customer_name = 'vFense'
        >>> app_data = {'customer_name': 'vFense'}
        >>> collection = 'apps_per_agent'
        >>> update_apps_per_agent_by_customer(customer_name,_app_data, collection)

    Returns:
        Tuple (status_code, count, error, generated ids)
        >>> (2001, 1, None, [])
    """

    index_name = DbCommonAppPerAgentIndexes.CustomerName
    data = {}
    try:
        data = (
            r
            .table(collection)
            .get_all(
                customer_name, index=index_name
            )
            .update(app_data)
            .run(conn)
        )

    except Exception as e:
        logger.exception(e)

    return data

@time_it
@db_create_close
@return_status_tuple
def update_apps_per_agent_by_agentids(
        agent_ids, app_data,
        collection=AppCollections.AppsPerAgent,
        conn=None
    ):
    """ Update any keys for any apps collection by customer name
        This function should not be called directly.
    Args:
        agent_ids (list): List of agent ids.
        app_data (dict): Dictionary of the key and values that you are updating.

    Kwargs:
        collection (str): The Application Collection that is going to be used.

    Basic Usage:
        >>> from vFense.plugins.patching._db import update_apps_per_agent_by_agentids
        >>> agent_ids = ['7f242ab8-a9d7-418f-9ce2-7bcba6c2d9dc']
        >>> app_data = {'customer_name': 'vFense'}
        >>> collection = 'apps_per_agent'
        >>> update_apps_per_agent_by_agentids(agent_ids,_app_data, collection)

    Returns:
        Tuple (status_code, count, error, generated ids)
        >>> (2001, 1, None, [])
    """

    index_name = DbCommonAppPerAgentIndexes.AgentId
    data = {}
    try:
        data = (
            r
            .expr(agent_ids)
            .for_each(
                lambda agent_id:
                r
                .table(collection)
                .get_all(
                    agent_id, index=index_name
                )
                .update(app_data)
            )
            .run(conn)
        )

    except Exception as e:
        logger.exception(e)

    return data


@time_it
@db_create_close
@return_status_tuple
def delete_apps_by_customer(
        customer_name,
        collection=AppCollections.AppsPerAgent,
        conn=None
    ):
    """Delete all apps for all agents by customer and app type
        This function should not be called directly.
    Args:
        customer_name (str): Name of the customer.

    Kwargs:
        collection (str): The Application Collection that is going to be used.
        index_name (str): The name of the index that will be used during the search.

    Basic Usage:
        >>> from vFense.plugins.patching._db import delete_apps_by_customer
        >>> customer_name = 'vFense'
        >>> collection = 'apps_per_agent'
        >>> index_name = 'customer_name'
        >>> delete_apps_by_customer(customer_name,_collection, index_name)

    Returns:
        Tuple (status_code, count, error, generated ids)
        >>> (2001, 1, None, [])
    """
    index_name = DbCommonAppPerAgentIndexes.CustomerName
    data = {}
    try:
        data = (
            r
            .table(collection)
            .get_all(
                customer_name, index=index_name
            )
            .delete()
            .run(conn)
        )
    except Exception as e:
        logger.exception(e)

    return data


@time_it
@db_create_close
@return_status_tuple
def update_app_data_by_agentid(
        agent_id, app_data,
        collection=AppCollections.AppsPerAgent,
        conn=None
    ):
    """Update app data for an agent.
        This function should not be called directly.
    Args:
        agent_id (str): 36 character UUID of the agent.
        data(dict): Dictionary of the application data that
            is being updated for the agent.
    Kwargs:
        collection (str): The name of the apps per agent collection,
            that will be used when updating the application data.

    Basic Usage:
        >>> from vFense.plugins.patching._db import update_app_data_by_agentid
        >>> agent_id = '7f242ab8-a9d7-418f-9ce2-7bcba6c2d9dc'
        >>> data = {'status': 'pending'}
        >>> collection = 'apps_per_agent'
        >>> update_app_data_by_agentid(agent_id, data, collection)

    Returns:
        Tuple (status_code, count, error, generated ids)
        >>> (2001, 1, None, [])
    """
    data = {}
    index_to_use = DbCommonAppPerAgentIndexes.AgentId
    try:
        data = (
            r
            .table(collection)
            .get_all(agent_id, index=index_to_use)
            .update(app_data)
            .run(conn)
        )

    except Exception as e:
        logger.exception(e)

    return data

@time_it
@db_create_close
@return_status_tuple
def update_app_data_by_agentid_and_appid(
        agent_id, app_id, app_data,
        collection=AppCollections.AppsPerAgent,
        conn=None
    ):
    """Update app data for an agent.
        This function should not be called directly.
    Args:
        agent_id (str): 36 character UUID of the agent.
        app_id (str): 64 character ID of the application.
        data(dict): Dictionary of the application data that
            is being updated for the agent.
    Kwargs:
        collection (str): The name of the apps per agent collection,
            that will be used when updating the application data.

    Basic Usage:
        >>> from vFense.plugins.patching._db import update_app_data_by_agentid_and_appid
        >>> agent_id = '7f242ab8-a9d7-418f-9ce2-7bcba6c2d9dc'
        >>> app_id = '15fa819554aca425d7f699e81a2097898b06f00a0f2dd6e8d51a18405360a6eb'
        >>> data = {'status': 'pending'}
        >>> collection = 'apps_per_agent'
        >>> update_app_data_by_agentid_and_appid(agent_id, app_id, data, collection)

    Returns:
        Tuple (status_code, count, error, generated ids)
        >>> (2001, 1, None, [])
    """
    data = {}
    index_to_use = DbCommonAppPerAgentIndexes.AgentIdAndAppId
    try:
        data = (
            r
            .table(collection)
            .get_all([agent_id, app_id], index=index_to_use)
            .update(app_data)
            .run(conn)
        )

    except Exception as e:
        logger.exception(e)

    return data

@time_it
@db_create_close
@return_status_tuple
def delete_app_data_for_agentid(
        agent_id,
        collection=AppCollections.AppsPerAgent,
        conn=None
    ):
    """Delete all apps for an agent_id.
    Args:
        agent_id (str): The 36 character UUID of the agent

    Kwargs:
        collection (str): The name of the collection.
            default = apps_per_agent

    Basic Usage:
        >>> from vFense.plugins.patching._db import delete_app_data_for_agentid
        >>> agent_id = '7f242ab8-a9d7-418f-9ce2-7bcba6c2d9dc'
        >>> delete_app_data_for_agentid(agent_id)

    Returns:
        Tuple (status_code, count, error, generated ids)
        >>> (2001, 1, None, [])
    """
    data = {}
    try:
        data = (
            r
            .table(collection)
            .get_all(agent_id, index=DbCommonAppPerAgentIndexes.AgentId)
            .delete()
            .run(conn)
        )

    except Exception as e:
        logger.exception(e)

    return data

@time_it
@db_create_close
@return_status_tuple
def update_customers_in_app_by_app_id(
        customer_name, app_id,
        collection=AppCollections.UniqueApplications,
        conn=None
    ):
    """Update the list of customers that require this application id.
    Args:
        customer_name (str): The name of the customer you are adding to the app.
        app_id (str): The 64 character application id.

    Kwargs:
        collection (str): The name of the collection.
            default = unique_applications

    Basic Usage:
        >>> from vFense.plugins.patching._db import update_customers_in_app_by_app_id
        >>> customer_name = 'default'
        >>> app_id = '15fa819554aca425d7f699e81a2097898b06f00a0f2dd6e8d51a18405360a6eb'
        >>> collection = 'unique_applications'
        >>> update_customers_in_app_by_app_id(customer_name, app_id)

    Returns:
        Tuple (status_code, count, error, generated ids)
        >>> (2001, 1, None, [])
    """
    data = {}
    try:
        data = (
            r
            .table(collection)
            .get(app_id)
            .update(
                {
                    DbCommonAppKeys.Customers: (
                        r.row[DbCommonAppKeys.Customers]
                        .set_insert(customer_name)
                    ),
                }
            )
            .run(conn)
        )

    except Exception as e:
        logger.exception(e)

    return data


@time_it
def update_app_data_by_app_id(app_id, app_data,
        collection=AppCollections.UniqueApplications):

    """Update the data of an application.

    Args:
        app_id (str): The 64 character hex digest of the application.
        app_data (dict): Dictionary of the data you are updateing.

    Kwargs:
        collection (str): The name of the collection you are updating

    Returns:
        Tuple (status_code, count, error, generated ids)
        >>> (2001, 1, None, [])

    """
    data = {}
    try:
        data = update_data_in_table(app_id, app_data, collection)

    except Exception as e:
        logger.exception(e)

    return data


@time_it
@db_create_close
@return_status_tuple
def delete_apps_per_agent_older_than(
        agent_id, now,
        collection=AppCollections.AppsPerAgent,
        conn=None
    ):
    """Delete all apps_per_agent that are older than now,
    Args:
        agent_id (str): The 36 character UUID of the agent.
        now (rethinkdb.ast.EpochTime): RQL epoch time object.

    Kwargs:
        collection (str): The name of the collection you are perfoming the delete on.

    Basic Usage:
        >>> from vFense.plugins.patching._db import delete_apps_per_agent_older_than
        >>> from vFense.core._db_constants import DbTime
        >>> now = DbTime.time_now()
        >>> collection = 'apps_per_agent'
        >>> agent_id = '7f242ab8-a9d7-418f-9ce2-7bcba6c2d9dc'
        >>> delete_apps_per_agent_older_than(now, collection)

    Returns:
        Tuple (status_code, count, error, generated ids)
        >>> (2001, 1, None, [])
    """
    data = {}
    try:
        data = (
            r
            .table(collection)
            .get_all(
                agent_id,
                index=DbCommonAppPerAgentIndexes.AgentId
            )
            .filter(
                r.row[DbCommonAppPerAgentKeys.LastModifiedTime] < now
            )
            .delete()
            .run(conn)
        )

    except Exception as e:
        logger.exception(e)

    return data

@time_it
def update_apps_per_agent(
        pkg_list,
        collection=AppCollections.AppsPerAgent
    ):
    """Insert or Update into the apps_per_agent collection
    Args:
        pkg_list (list): List of all the applications you want to insert
            or update into the database.

    Kwargs:
        collection (str, optional): The name of the collection you want to update.
            default = apps_per_agent

    Basic Usage:
        >>> from vFense.plugins.patching._db import update_apps_per_agent
        >>> collection = 'apps_per_agent'
        >>> pkg_list = [
                {
                    "status": "installed",
                    "install_date": 1397697799,
                    "app_id": "c71c32209119ad585dd77e67c082f57f1d18395763a5fb5728c02631d511df5c",
                    "update": 5014,
                    "dependencies": [],
                    "agent_id": "78211125-3c1e-476a-98b6-ea7f683142b3",
                    "last_modified_time": 1398997520,
                    "id": "000182347981c7b54577817fd93aa6cab39477c6dc59fd2dd8ba32e15914b28f",
                    "customer_name": "default"
                }
            ]
        >>> update_apps_per_agent(pkg_list, collection)

    Returns:
        Tuple (status_code, count, error, generated ids)
        >>> (2001, 1, None, [])
    """
    data = insert_data_in_table(pkg_list, collection)
    return data

@time_it
@db_create_close
@return_status_tuple
def update_hidden_status(
        app_ids, hidden=CommonKeys.TOGGLE,
        collection=AppCollections.UniqueApplications,
        conn=None
    ):
    """Update the global hidden status of an application
    Args:
        app_ids (list): List of application ids.

    Kwargs:
        hidden (str, optional): yes, no, or toggle
            default = toggle
        collection (str, optional): The collection you are updating for.
            collection = unique_applications

    Basic Usage:
        >>> from vFense.plugins.patching._db import update_hidden_status
        >>> hidden = 'toggle'
        >>> app_ids = ['c71c32209119ad585dd77e67c082f57f1d18395763a5fb5728c02631d511df5c']
        >>> update_hidden_status(app_ids, hidden)

    Returns:
        Tuple (status_code, count, error, generated ids)
        >>> (2001, 1, None, [])
    """
    data = {}
    try:
        if hidden == CommonKeys.YES or hidden == CommonKeys.NO:
            data = (
                r
                .expr(app_ids)
                .for_each(
                    lambda app_id:
                    r
                    .table(collection)
                    .get(app_id)
                    .update(
                        {
                            DbCommonAppKeys.Hidden: hidden
                        }
                    )
                )
                .run(conn)
            )

        elif hidden == CommonKeys.TOGGLE:
            for app_id in app_ids:
                data = (
                    r
                    .table(collection)
                    .get(app_id)
                    .update(
                        {
                            DbCommonAppKeys.Hidden: (
                                r.branch(
                                    r.row[DbCommonAppKeys.Hidden] == CommonKeys.YES,
                                    CommonKeys.NO,
                                    CommonKeys.YES
                                )
                            )
                        }
                    )
                    .run(conn)
                )

    except Exception as e:
        logger.exception(e)

    return data


@time_it
@db_create_close
def delete_app_from_vfense(
        app_id, collection=AppCollections.UniqueApplications,
        per_agent_collection=AppCollections.AppsPerAgent, conn=None
    ):
    """Delete the application from vFense.
    Args:
        app_id (str): The application id.

    Kwargs:
        collection (str, optional): The collection you are deleteing from.
            collection = unique_applications
        per_agent_collection (str, optional): The apps_per_agent collection
            you are deleteing from.
            per_agent_collection = apps_per_agent

    Basic Usage:
        >>> from vFense.plugins.patching._db import delete_app_from_vfense
        >>> app_id = 'c71c32209119ad585dd77e67c082f57f1d18395763a5fb5728c02631d511df5c'
        >>> collection = 'unique_applications'
        >>> per_agent_collection = 'apps_per_agent'
        >>> delete_app_from_vfense(app_ids, collection, per_agent_collection)

    Returns:
        Boolean
        >>> True
    """

    completed = False
    try:
        (
            r
            .table(collection)
            .filter({DbCommonAppKeys.AppId: app_id})
            .delete()
            .run(conn)
        )
        (
            r
            .table(per_agent_collection)
            .filter({DbCommonAppKeys.AppId: app_id})
            .delete()
            .run(conn)
        )
        (
            r
            .table(FileCollections.Files)
            .filter(lambda x: x[FilesKeys.AppIds].contains(app_id))
            .delete()
            .run(conn)
        )
        completed = True

    except Exception as e:
        logger.exception(e)

    return(completed)
