import os
import re
import logging
import urllib.request, urllib.parse, urllib.error

from vFense import VFENSE_LOGGING_CONFIG
from vFense.core._constants import CommonKeys
from vFense.core.agent._db import total_agents_in_customer
from vFense.core._db_constants import DbTime
from vFense.core._db import object_exist, insert_data_in_table, \
    delete_data_in_table

from vFense.errorz._constants import ApiResultKeys
from vFense.errorz.status_codes import DbCodes, GenericCodes, \
    GenericFailureCodes, PackageCodes, PackageFailureCodes

from vFense.plugins.patching.file_data import add_file_data
from vFense.plugins.patching.utils import build_agent_app_id
from vFense.plugins.patching import AppsKeys, AppCollections, \
        DbCommonAppsKeys, DbCommonAppsPerAgentKeys, FileServerKeys
from vFense.plugins.patching._constants import CommonAppKeys, \
    FileLocationUris, CommonFileKeys
from vFense.plugins.patching._db import (fetch_file_servers_addresses,
    delete_app_data_for_agentid, update_apps_per_agent_by_customer,
    update_app_data_by_agentid, update_app_data_by_agentid_and_appid,
    update_customers_in_apps_by_customer, update_apps_per_agent,
    delete_apps_per_agent_older_than, update_hidden_status,
    fetch_app_id_by_name_and_version, update_customers_in_app_by_app_id,
    update_app_data_by_app_id, delete_apps_by_customer)


from vFense.core.decorators import time_it, results_message
from vFense.core.customer import CustomerKeys
from vFense.core.customer.customers import get_customer_property
from vFense.plugins.vuln import SecurityBulletinKeys
import vFense.plugins.vuln.windows.ms as ms
import vFense.plugins.vuln.ubuntu.usn as usn
import vFense.plugins.vuln.cve.cve as cve

logging.config.fileConfig(VFENSE_LOGGING_CONFIG)
logger = logging.getLogger('rvapi')


def get_remote_file_size(url):
    """If the agent does not provide us with the size of the file,
        we will go and make a connection to the url provided and
        retrieve the size from the Content-Length

    Args:
        url (str): The url, where the vendor hosts the file.

    Returns:
        String (The size of the file)

    """
    remote_size = None

    if url:
        try:
            remote_size = (
                urllib.request
                .urlopen(url)
                .info()
                .getheaders("Content-Length")[0]
            )

        except Exception as e:
            logger.exception(e)

    return str(remote_size)


def get_base_url(customer_name):
    """Retrieve the base url for downloading packages
    Args:
        customer_name (str): The name of the customer

    Basic Usage:
        >>> vFense.plugins.patching.patching import get_base_url
        >>> customer_name = 'default'
        >>> get_base_url(customer_name)

    Returns:
        String
    """
    return(
        get_customer_property(
            customer_name, CustomerKeys.PackageUrl
        )
    )

def get_download_urls(customer_name, app_id, file_data):
    """Replace the vendor supplied url with the vFense Server urls
    Args:
        customer_name (str): The name of the customer
        app_id (str): The 64 character ID of the app
        file_data (list): List of the file_data that will be manipulated

    Basic Usage:
        >>> from vFense.plugins.patching._db_files import fetch_file_data
        >>> from vFense.plugins.patching.patching import get_download_urls
        >>> customer_name = 'default'
        >>> app_id = 'c726edf62d1d17ca8b420f24bbdc9c8fa58d000b51d31614e3826c2fb37a2929'
        >>> file_data = fetch_file_data(app_id)
        >>> get_download_urls(customer_name, app_id, file_data)

    Returns:
        List of dictionaries
        [
            {
                "file_uris": [
                    "https://10.0.0.15/packages/c726edf62d1d17ca8b420f24bbdc9c8fa58d000b51d31614e3826c2fb37a2929/gpgv_1.4.11-3ubuntu2.5_amd64.deb"
                ],
                "file_name": "gpgv_1.4.11-3ubuntu2.5_amd64.deb",
                "file_hash": "47dc1daa42e6d53e1a881f4ed9c5472f6732665af2cba082f8fa3931199fb746",
                "file_size": 185400,
                "file_uri": "https://10.0.0.15/packages/c726edf62d1d17ca8b420f24bbdc9c8fa58d000b51d31614e3826c2fb37a2929/gpgv_1.4.11-3ubuntu2.5_amd64.deb"
            }
        ]
    """
    uris = []
    url_base = get_base_url(customer_name)
    file_uris_base = None
    url_base = os.path.join(url_base, app_id)
    file_uris_base = os.path.join(FileLocationUris.PACKAGES, app_id)

    for pkg in file_data:
        file_servers = fetch_file_servers_addresses(customer_name)
        file_uris = []

        # If customer defined file_servers exist then add those to the
        # beginning of the file_uris list.
        if file_servers:
            for server in file_servers:
                file_uris.append(
                    os.path.join(
                        'http://', server[FileServerKeys.Address],
                        file_uris_base, pkg[CommonFileKeys.PKG_NAME]
                    )
                )

        # Finally, make sure to add the vFense address
        file_uris.append(os.path.join(url_base, pkg[CommonFileKeys.PKG_NAME]))

        uris.append(
            {
                CommonFileKeys.PKG_NAME: pkg[CommonFileKeys.PKG_NAME],
                CommonFileKeys.PKG_URI: (
                    os.path.join(url_base, pkg[CommonFileKeys.PKG_NAME])
                ),
                CommonFileKeys.FILE_URIS: file_uris,
                CommonFileKeys.PKG_SIZE: pkg[CommonFileKeys.PKG_SIZE],
                CommonFileKeys.PKG_HASH: pkg[CommonFileKeys.PKG_HASH]
            }
        )

    return uris

@time_it
def update_custom_app_data_by_agentid_and_appid(agent_id, app_id, app_data):
    """Update the custom_apps_per_agent collection by agent_id and app_id.
        This function should not be called directly.
    Args:
        agent_id (str): 36 character UUID of the agent.
        app_id (str): 64 character ID of the application.
        app_data(dict): Dictionary of the application data that
            is being updated for the agent.

    Basic Usage:
        >>> from vFense.plugins.patching.patching import update_custom_app_data_by_agentid_and_appid
        >>> agent_id = '7f242ab8-a9d7-418f-9ce2-7bcba6c2d9dc'
        >>> app_id = '15fa819554aca425d7f699e81a2097898b06f00a0f2dd6e8d51a18405360a6eb'
        >>> app_data = {'status': 'pending'}
        >>> update_custom_app_data_by_agentid_and_appid(agent_id, app_id, app_data)

    Return:
        Tuple (status_code, count, error, generated ids)
        >>> (2001, 1, None, [])
    """
    collection = AppCollections.CustomAppsPerAgent
    data = update_app_data_by_agentid_and_appid(
        agent_id, app_id, app_data, collection=collection
    )

    return data

@time_it
def update_supported_app_data_by_agentid_and_appid(agent_id, app_id, app_data):
    """Update the supported_apps_per_agent collection by agent_id and app_id.
        This function should not be called directly.
    Args:
        agent_id (str): 36 character UUID of the agent.
        app_id (str): 64 character ID of the application.
        app_data(dict): Dictionary of the application data that
            is being updated for the agent.

    Basic Usage:
        >>> from vFense.plugins.patching.patching import update_supported_app_data_by_agentid_and_appid
        >>> agent_id = '7f242ab8-a9d7-418f-9ce2-7bcba6c2d9dc'
        >>> app_id = '15fa819554aca425d7f699e81a2097898b06f00a0f2dd6e8d51a18405360a6eb'
        >>> app_data = {'status': 'pending'}
        >>> update_supported_app_data_by_agentid_and_appid(agent_id, app_id, app_data)

    Return:
        Tuple (status_code, count, error, generated ids)
        >>> (2001, 1, None, [])
    """
    collection = AppCollections.SupportedAppsPerAgent
    data = update_app_data_by_agentid_and_appid(
        agent_id, app_id, app_data, collection=collection
    )

    return data

@time_it
def remove_os_apps_for_agent_by_customer(customer_name):
    """Delete all apps for all agents by customer for
    Args:
        customer_name (str): Name of the customer.

    Basic Usage:
        >>> from vFense.plugins.patching.patching import remove_os_apps_for_agent_by_customer
        >>> customer_name = 'vFense'
        >>> remove_os_apps_for_agent_by_customer(customer_name)

    Return:
        Tuple (status_code, count, error, generated ids)
        >>> (2001, 1, None, [])
    """
    collection_name = AppCollections.AppsPerAgent
    return(
        delete_apps_by_customer(
            customer_name,
            collection_name,
        )
    )

@time_it
def remove_supported_apps_for_agent_by_customer(customer_name):
    """Delete all apps for all agents by customer.
    Args:
        customer_name (str): Name of the customer.

    Basic Usage:
        >>> from vFense.plugins.patching.patching import remove_supported_apps_for_agent_by_customer
        >>> customer_name = 'vFense'
        >>> remove_supported_apps_for_agent_by_customer(customer_name)

    Return:
        Tuple (status_code, count, error, generated ids)
        >>> (2001, 1, None, [])
    """
    collection_name = AppCollections.SupportedAppsPerAgent
    return(
        delete_apps_by_customer(
            customer_name,
            collection_name,
        )
    )

@time_it
def remove_custom_apps_for_agent_by_customer(customer_name):
    """Delete all apps for all agents by customer.
    Args:
        customer_name (str): Name of the customer.

    Basic Usage:
        >>> from vFense.plugins.patching.patching import remove_custom_apps_for_agent_by_customer
        >>> customer_name = 'vFense'
        >>> remove_custom_apps_for_agent_by_customer(customer_name)

    Return:
        Tuple (status_code, count, error, generated ids)
        >>> (2001, 1, None, [])
    """
    collection_name = AppCollections.CustomAppsPerAgent
    return(
        delete_apps_by_customer(
            customer_name,
            collection_name,
        )
    )

@time_it
def remove_vfense_apps_for_agent_by_customer(customer_name):
    """Delete all apps for all agents by customer.
    Args:
        customer_name (str): Name of the customer.

    Basic Usage:
        >>> from vFense.plugins.patching.patching import remove_vfense_apps_for_agent_by_customer
        >>> customer_name = 'vFense'
        >>> remove_vfense_apps_for_agent_by_customer(customer_name)

    Return:
        Tuple (status_code, count, error, generated ids)
        >>> (2001, 1, None, [])
    """
    collection_name = AppCollections.vFenseAppsPerAgent
    return(
        delete_apps_by_customer(
            customer_name,
            collection_name,
        )
    )

@time_it
def update_os_apps_for_agent_by_customer(customer_name, app_data):
    """Update all apps for all agents by customer name.
    Args:
        customer_name (str): Name of the customer.
        app_data (dict): The data that you are updating.

    Basic Usage:
        >>> from vFense.plugins.patching.patching import update_os_apps_for_agent_by_customer
        >>> customer_name = 'vFense'
        >>> app_data = {'customer_name': 'vFense'}
        >>> update_os_apps_for_agent_by_customer(customer_name, app_data)

    Return:
        Tuple (status_code, count, error, generated ids)
        >>> (2001, 1, None, [])
    """
    collection_name = AppCollections.AppsPerAgent
    return(
        update_apps_per_agent_by_customer(
            customer_name, app_data, collection_name
        )
    )

@time_it
def update_supported_apps_for_agent_by_customer(customer_name, app_data):
    """Update all apps for all agents by customer name.
    Args:
        customer_name (str): Name of the customer.
        app_data (dict): The data that you are updating.

    Basic Usage:
        >>> from vFense.plugins.patching.patching import update_supported_apps_for_agent_by_customer
        >>> customer_name = 'vFense'
        >>> app_data = {'customer_name': 'vFense'}
        >>> update_supported_apps_for_agent_by_customer(customer_name, app_data)

    Return:
        Tuple (status_code, count, error, generated ids)
        >>> (2001, 1, None, [])
    """
    collection_name = AppCollections.SupportedAppsPerAgent
    return(
        update_apps_per_agent_by_customer(
            customer_name, app_data, collection_name
        )
    )

@time_it
def update_custom_apps_for_agent_by_customer(customer_name, app_data):
    """Update all apps for all agents by customer name.
    Args:
        customer_name (str): Name of the customer.
        app_data (dict): The data that you are updating.

    Basic Usage:
        >>> from vFense.plugins.patching.patching import update_custom_apps_for_agent_by_customer
        >>> customer_name = 'vFense'
        >>> app_data = {'customer_name': 'vFense'}
        >>> update_custom_apps_for_agent_by_customer(customer_name, app_data)

    Return:
        Tuple (status_code, count, error, generated ids)
        >>> (2001, 1, None, [])
    """
    collection_name = AppCollections.CustomAppsPerAgent
    return(
        update_apps_per_agent_by_customer(
            customer_name, app_data, collection_name
        )
    )

@time_it
def update_vfense_apps_for_agent_by_customer(customer_name, app_data):
    """Update all apps for all agents by customer name.
    Args:
        customer_name (str): Name of the customer.
        app_data (dict): The data that you are updating.

    Basic Usage:
        >>> from vFense.plugins.patching.patching import update_agent_apps_for_agent_by_customer
        >>> customer_name = 'vFense'
        >>> app_data = {'customer_name': 'vFense'}
        >>> update_agent_apps_for_agent_by_customer(customer_name, app_data)

    Return:
        Tuple (status_code, count, error, generated ids)
        >>> (2001, 1, None, [])
    """
    collection_name = AppCollections.CustomAppsPerAgent
    return(
        update_apps_per_agent_by_customer(
            customer_name, app_data, collection_name
        )
    )


@time_it
def update_customers_in_supported_apps(
        current_customer, new_customer,
        remove_customer=False,
        conn=None
    ):
    """ Update the customers list of all applications for the current customer.
    Args:
        current_customer (str): Name of the current customer.
        new_customer (str): Name of the new customer.

    Kwargs:
        remove_customer (bool): True or False
            default = False

    Basic Usage:
        >>> from vFense.plugins.patching.patching import update_customers_in_supported_apps
        >>> current_customer = 'default'
        >>> new_customer = 'test'
        >>> remove_customer = True
        >>> update_customers_in_supported_apps(
                current_customer, new_customer, remove_customer
            )

    Returns:
        Tuple (status_code, count, error, generated ids)
        >>> (2001, 1, None, [])
    """
    collection = AppCollections.SupportedApps
    return(
        update_customers_in_apps_by_customer(
            current_customer, new_customer,
            remove_customer, collection
        )
    )


@time_it
def update_customers_in_custom_apps(
        current_customer, new_customer,
        remove_customer=False,
        conn=None
    ):
    """ Update the customers list of all applications for the current customer.
    Args:
        current_customer (str): Name of the current customer.
        new_customer (str): Name of the new customer.

    Kwargs:
        remove_customer (bool): True or False
            default = False

    Basic Usage:
        >>> from vFense.plugins.patching.patching import update_customers_in_custom_apps
        >>> current_customer = 'default'
        >>> new_customer = 'test'
        >>> remove_customer = True
        >>> update_customers_in_custom_apps(
                current_customer, new_customer, remove_customer
            )

    Returns:
        Tuple (status_code, count, error, generated ids)
        >>> (2001, 1, None, [])
    """
    collection = AppCollections.CustomApps
    return(
        update_customers_in_apps_by_customer(
            current_customer, new_customer,
            remove_customer, collection
        )
    )


@time_it
def update_customers_in_vfense_apps(
        current_customer, new_customer,
        remove_customer=False,
    ):
    """ Update the customers list of all applications for the current customer.
    Args:
        current_customer (str): Name of the current customer.
        new_customer (str): Name of the new customer.

    Kwargs:
        remove_customer (bool): True or False
            default = False

    Basic Usage:
        >>> from vFense.plugins.patching.patching import update_customers_in_vfense_apps
        >>> current_customer = 'default'
        >>> new_customer = 'test'
        >>> remove_customer = True
        >>> update_customers_in_vfense_apps(
                current_customer, new_customer, remove_customer
            )

    Returns:
        Tuple (status_code, count, error, generated ids)
        >>> (2001, 1, None, [])
    """
    collection = AppCollections.vFenseApps
    return(
        update_customers_in_apps_by_customer(
            current_customer, new_customer,
            remove_customer, collection
        )
    )


@time_it
def remove_all_app_data_for_agent(agent_id):
    """Remove all apps for agent id.
    Args:
        agent_id (str): The 36 character UUID of the agent.

    Basic Usage:
        >>> from vFense.plugins.patching.patching import remove_all_app_data_for_agent
        >>> agent_id = '7f242ab8-a9d7-418f-9ce2-7bcba6c2d9dc'
        >>> remove_all_app_data_for_agent(agent_id)
    """
    delete_app_data_for_agentid(agent_id)
    delete_app_data_for_agentid(
        agent_id, collection=AppCollections.CustomAppsPerAgent
    )
    delete_app_data_for_agentid(
        agent_id, collection=AppCollections.SupportedAppsPerAgent
    )
    delete_app_data_for_agentid(
        agent_id, collection=AppCollections.vFenseAppsPerAgent
    )


@time_it
def remove_all_apps_for_customer(customer_name):
    """Remove all apps for customer.
    Args:
        customer_name (str): The name of the customer

    Basic Usage:
        >>> from vFense.plugins.patching.patching import remove_all_apps_for_customer
        >>> customer_name = 'default'
        >>> remove_all_apps_for_customer(customer_name)
    """
    remove_os_apps_for_agent_by_customer(customer_name)
    remove_supported_apps_for_agent_by_customer(customer_name)
    remove_custom_apps_for_agent_by_customer(customer_name)
    remove_vfense_apps_for_agent_by_customer(customer_name)


@time_it
def remove_all_apps_for_customer(customer_name):
    """Remove all apps for customer.
    Args:
        customer_name (str): The name of the customer

    Basic Usage:
        >>> from vFense.plugins.patching.patching import remove_all_apps_for_customer
        >>> customer_name = 'default'
        >>> remove_all_apps_for_customer(customer_name)
    """
    remove_os_apps_for_agent_by_customer(customer_name)
    remove_supported_apps_for_agent_by_customer(customer_name)
    remove_custom_apps_for_agent_by_customer(customer_name)
    remove_vfense_apps_for_agent_by_customer(customer_name)



@time_it
def change_customer_for_apps_in_customer(
        original_customer, new_customer
    ):
    """Update the customer name for all apps in original customer.
    Args:
        current_customer (str): The name of the current customer.
        new_customer (str): The name of the new customer.

    Basic Usage:
        >>> from vFense.plugins.patching.patching import update_all_apps_for_customer
        >>> original_customer = 'default'
        >>> new_customer = 'test'
        >>> app_data = {'customer_name': 'test'}
        >>> update_all_apps_for_customer(
                original_customer, new_customer, app_data
            )
    """
    remove_customer = False
    agent_count = total_agents_in_customer(original_customer)
    if agent_count == 0:
        remove_customer = True

    app_data = {CommonAppKeys.CustomerName: new_customer}

    update_os_apps_for_agent_by_customer(
        original_customer, app_data
    )

    update_customers_in_apps_by_customer(
        original_customer, new_customer, remove_customer
    )

    update_supported_apps_for_agent_by_customer(
        original_customer, app_data
    )

    update_customers_in_supported_apps(
        original_customer, new_customer, remove_customer
    )

    update_custom_apps_for_agent_by_customer(
        original_customer, app_data
    )

    update_customers_in_custom_apps(
        original_customer, new_customer, remove_customer
    )

    update_vfense_apps_for_agent_by_customer(
        original_customer, app_data
    )

    update_customers_in_vfense_apps(
        original_customer, new_customer, remove_customer
    )


@time_it
def update_all_app_data_for_agent(agent_id, app_data):
    """Update application data for an agent id.
    Args:
        agent_id (str): The 36 character UUID of the agent.
        app_data (dict): Dictionary of the data you want to update.

    Basic Usage:
        >>> from vFense.plugins.patching.patching import update_all_app_data_for_agent
        >>> agent_id = '7f242ab8-a9d7-418f-9ce2-7bcba6c2d9dc'
        >>> app_data = {'customer_name': 'default'}
        >>> update_all_app_data_for_agent(agent_id, app_data)
    """
    collections = [
        AppCollections.AppsPerAgent,
        AppCollections.CustomAppsPerAgent,
        AppCollections.SupportedAppsPerAgent,
        AppCollections.vFenseAppsPerAgent
    ]

    for collection in collections:
        update_app_data_by_agentid(agent_id, app_data, collection)

@time_it
def update_app_status_by_agentid_and_appid(
        agent_id, app_id, status, collection=AppCollections.AppsPerAgent
    ):

    """Update the application status for an agent

    Args:
        agent_id (str): 36 character UUID of the agent.
        app_id (str): 64 character ID of the application.
        status (str): The new status for the application.

    Kwargs:
        collection (str): Collection where the status update is done.

    Basic Usage:
        >>> from vFense.plugins.patching.patching import update_app_status_by_agentid_and_appid
        >>> agent_id = '7f242ab8-a9d7-418f-9ce2-7bcba6c2d9dc'
        >>> app_id = '15fa819554aca425d7f699e81a2097898b06f00a0f2dd6e8d51a18405360a6eb'
        >>> status = 'pending'
        >>> update_app_status_by_agentid_and_appid(agent_id, app_id, status)

    Returns:
        Boolean
    """
    updated = False

    if status in CommonAppKeys.ValidPackageStatuses:
        app_status = {DbCommonAppsPerAgentKeys.Status: status}

        status_code, _, _, _ = update_app_data_by_agentid_and_appid(
            agent_id, app_id, app_status, collection
        )

        if status_code == DbCodes.Replaced:
            updated = True

    return updated

def get_vulnerability_info_for_app(
        os_string, app_name=None,
        app_version=None, kb=''
    ):
    """Retrieve the relevant vulnerability for an application if
        it exist. We search by using the kb for Windows and by using the name
        and version for Ubuntu.

    Args:
        os_string (str): The operating system string.. example Ubuntu 12.0.4

    Kwargs:
        app_name (str, optional): The name of the application we are
            searching for.
            default = None
        app_version (str, optional): The version of the application we are
            searching for.
            default = None
        kb (str, optional): The knowledge base id of this application.
            default = ''

    Basic Usage:
        >>> from vFense.plugins.patching.patching import get_vulnerability_info_for_app

    Returns:
        Dictionary
    """

    vuln_data = {}
    vuln_info = {}
    vuln_data[AppsKeys.CveIds] = []
    vuln_data[AppsKeys.VulnerabilityId] = ""
    vuln_data[AppsKeys.VulnerabilityCategories] = []

    if kb != "" and re.search(r'Windows', os_string, re.IGNORECASE):
        vuln_info = ms.get_vuln_ids(kb)

    elif (
            re.search(r'Ubuntu|Mint', os_string, re.IGNORECASE)
            and app_name and app_version
         ):
        vuln_info = (
            usn.get_vuln_ids(
                app_name, app_version, os_string
            )
        )

    if vuln_info:
        vuln_data[AppsKeys.CveIds] = vuln_info[SecurityBulletinKeys.CveIds]
        vuln_data[AppsKeys.VulnerabilityId] = (
            vuln_info[SecurityBulletinKeys.BulletinId]
        )
        for cve_id in vuln_data[AppsKeys.CveIds]:
            vuln_data[AppsKeys.VulnerabilityCategories] += (
                cve.get_vulnerability_categories(cve_id)
            )

        vuln_data[AppsKeys.VulnerabilityCategories] = (
            list(set(vuln_data[AppsKeys.VulnerabilityCategories]))
        )

    return vuln_data

@time_it
def application_updater(customer_name, app_data, os_string,
        collection=AppCollections.UniqueApplications):
    """Insert or update an existing application in the provided collection.

    Args:
        customer_name (str): The name of the customer, this application
            is a part of.
        app_data (dict): Dictionary of the application data.
        os_string (str): The name of the operating system... Ubuntu 12.04

    Kwargs:
        collection (str): The collection where app_data should be inserted or
            updated

    Basic Usage:
        >>> from vFense.plugins.patching.patching import application_updater
        >>> customer_name = 'default'
        >>> app_data = {
                "kb": "",
                "vendor_name": "",
                "description": "Facebook plugin for Gwibber\n Gwibber is a social networking client for GNOME. It supports Facebook,\n Twitter, Identi.ca, StatusNet, FriendFeed, Qaiku, Flickr, and Digg.\n .",
                "release_date": 1394769600,
                "vendor_severity": "recommended",
                "app_id": "922bcb88f6bd75c1e40fcc0c571f603cd59cf7e05b4a192bd5d69c974acc1457",
                "reboot_required": "no",
                "os_code": "linux",
                "repo": "precise-updates/main",
                "support_url": "",
                "version": "3.4.2-0ubuntu2.4",
                "rv_severity": "Recommended",
                "uninstallable": "yes",
                "name": "gwibber-service-facebook"
            }
        >>> os_string = 'Ubuntu 12.04 '
        >>> application_updater(customer_name, app_data, os_string[ ,'unique_applications'])

    Returns:
        Tuple (inserted_count, updated_count)
    """
    updated_count = 0
    inserted_count = 0

    status = app_data.pop(DbCommonAppsPerAgentKeys.Status, None)
    agent_id = app_data.pop(DbCommonAppsPerAgentKeys.AgentId, None)
    app_data.pop(DbCommonAppsPerAgentKeys.InstallDate, None)
    file_data = app_data.pop(DbCommonAppsKeys.FileData)
    app_name = app_data.get(DbCommonAppsKeys.Name, None)
    app_version = app_data.get(DbCommonAppsKeys.Version, None)
    app_kb = app_data.get(DbCommonAppsKeys.Kb, '')
    app_id = app_data.get(DbCommonAppsKeys.AppId)
    exists = object_exist(app_id, collection)

    if exists:
        add_file_data(app_id, file_data, agent_id)
        update_customers_in_app_by_app_id(customer_name, app_id)
        vuln_data = get_vulnerability_info_for_app(
            os_string, app_name, app_version, app_kb
        )
        data_updated = update_app_data_by_app_id(
            app_id,
            vuln_data,
            collection
        )
        if data_updated[0] == DbCodes.Replaced:
            updated_count = data_updated[1]

    else:
        add_file_data(app_id, file_data, agent_id)
        app_data[AppsKeys.Customers] = [customer_name]
        app_data[AppsKeys.Hidden] = CommonKeys.NO

        if (len(file_data) > 0 and status == CommonAppKeys.AVAILABLE or
                len(file_data) > 0 and status == CommonAppKeys.INSTALLED):
            app_data[AppsKeys.FilesDownloadStatus] = (
                PackageCodes.FilePendingDownload
            )

        elif len(file_data) == 0 and status == CommonAppKeys.AVAILABLE:
            app_data[AppsKeys.FilesDownloadStatus] = PackageCodes.MissingUri

        elif len(file_data) == 0 and status == CommonAppKeys.INSTALLED:
            app_data[AppsKeys.FilesDownloadStatus] = PackageCodes.FileNotRequired

        vuln_data = get_vulnerability_info_for_app(
            os_string, app_name, app_version, app_kb
        )

        app_data = dict(list(app_data.items()) + list(vuln_data.items()))

        data_inserted = insert_data_in_table(app_data, collection)

        if data_inserted[0] == DbCodes.Inserted:
            inserted_count = data_inserted[1]

    return(inserted_count, updated_count)

@time_it
def add_or_update_apps_per_agent(agent_id, app_dict_list, now=None,
        delete_afterwards=True, collection=AppCollections.AppsPerAgent):

    """Add or update apps for an agent.

    Args:
        agent_id (str): The 36 character UUID of the agent.
        app_dict_list (list): List of dictionaries.

    Kwargs:
        now (float|int): The time in epoch
            default = None
        collection (str): The name of the collection this is applied too.
            default = apps_per_agent

    Basic Usage:
        >>> from vFense.plugins.patching._db import add_or_update_apps_per_agent
        >>> collection = 'apps_per_agent'
        >>> now = 1399075090.83746
        >>> agent_id = '78211125-3c1e-476a-98b6-ea7f683142b3'
        >>> delete_unused_apps = True
        >>> app_dict_list = [
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
        >>> add_or_update_apps_per_agent(
                app_dict_list, now,
                delete_unused_apps,
                collection
            )

    Returns:
        Tuple
        >>> (insert_count, updated_count, deleted_count)

    """
    updated = 0
    inserted = 0
    deleted = 0

    status_code, count, _, _ = (
        update_apps_per_agent(app_dict_list, collection)
    )

    if isinstance(count, list):
        if len(count) > 1:
            inserted = count[0]
            updated = count[1]

    else:
        if status_code == DbCodes.Replaced:
            updated = count
        elif status_code == DbCodes.Inserted:
            inserted = count

    if delete_afterwards:
        if not now:
            now = DbTime.time_now()
        else:
            if isinstance(now, float) or isinstance(now, int):
                now = DbTime.epoch_time_to_db_time(now)

        status_code, count, _, _ = (
            delete_apps_per_agent_older_than(agent_id, now, collection)
        )

        deleted = count

    return inserted, updated, deleted

@time_it
def delete_apps_from_agent_by_name_and_version(
        agent_id, app_name, app_version,
        collection=AppCollections.UniqueApplications
    ):
    """Delete apps from an agent that contain this name and version.
    Args:
        agent_id (str): The 36 character UUID of the agent.
        app_name (str): Name of the application you are removing
            from this agent.
        app_version (str): The exact verision of the application
            you are removing.

    Kwargs:
        collection (str): The name of the collection you are perfoming the delete on.
            default = 'unique_applications'

    Basic Usage:
        >>> from vFense.plugins.patching._db import delete_apps_from_agent_by_name_and_version
        >>> agent_id = '78211125-3c1e-476a-98b6-ea7f683142b3'
        >>> app_name = 'libpangoxft-1.0-0'
        >>> app_version = '1.36.3-1ubuntu1'
        >>> collection = 'apps_per_agent'
        >>> delete_apps_from_agent_by_name_and_version(agent_id, name, version, collection)

    Returns:
        Boolean
        >>> True
    """

    completed = False
    app_id = fetch_app_id_by_name_and_version(app_name, app_version)

    if app_id:
        agent_app_id = build_agent_app_id(agent_id, app_id)
        status_code, count, error, generated_ids = (
            delete_data_in_table(agent_app_id, collection)
        )

        if status_code == DbCodes.Deleted:
            completed = True

    return completed

@time_it
@results_message
def toggle_hidden_status(
        app_ids, hidden=CommonKeys.TOGGLE,
        collection=AppCollections.UniqueApplications,
        username=None, uri=None, method=None
    ):
    """Toggle the hidden status of an application
    Args:
        app_ids (list): List of application ids.

    Kwargs:
        hidden (str, optional): yes, no, or toggle
            default = toggle
        collection (str, optional): The collection you are updating for.
            collection = unique_applications
        username (str): The name of the user who called this function.
        uri (str): The uri that was used to call this function.
        method (str): The HTTP methos that was used to call this function.

    Basic Usage:
        >>> from vFense.plugins.patching.patching import toggle_hidden_status
        >>> hidden = 'toggle'
        >>> app_ids = ['c71c32209119ad585dd77e67c082f57f1d18395763a5fb5728c02631d511df5c']
        >>> toggle_hidden_status(app_ids, hidden)

    Returns:
    """
    status = toggle_hidden_status.__name__ + ' - '
    results = {
        ApiResultKeys.DATA: [],
        ApiResultKeys.USERNAME: username,
        ApiResultKeys.URI: uri,
        ApiResultKeys.HTTP_METHOD: method,
    }
    status_code, count, error, generated_ids = update_hidden_status(
        app_ids, hidden, collection
    )

    if status_code == DbCodes.Replaced:
        msg = 'Hidden status updated'
        generic_status_code = GenericCodes.ObjectUpdated
        vfense_status_code = PackageCodes.ToggleHiddenSuccessful
        results[ApiResultKeys.UPDATED_IDS] = app_ids

    elif status_code == DbCodes.Skipped or status_code == DbCodes.Unchanged:
        msg = 'Hidden status could not be updated.'
        generic_status_code = GenericCodes.DoesNotExist
        vfense_status_code = PackageFailureCodes.ToggleHiddenFailed

    elif status_code == DbCodes.DoesNotExist:
        msg = (
            'Hidden status could not be updated: app_ids do not exist - %s.'
            % (','.join(app_ids))
        )
        generic_status_code = GenericCodes.DoesNotExist
        vfense_status_code = PackageFailureCodes.ApplicationDoesNotExist

    elif status_code == DbCodes.Errors:
        msg = (
            'Hidden status could not be updated: error occured - %s.'
            % (error)
        )
        generic_status_code = GenericFailureCodes.FailedToUpdateObject
        vfense_status_code = PackageFailureCodes.ToggleHiddenFailed

    results[ApiResultKeys.DB_STATUS_CODE] = status_code
    results[ApiResultKeys.GENERIC_STATUS_CODE] = generic_status_code
    results[ApiResultKeys.VFENSE_STATUS_CODE] = vfense_status_code
    results[ApiResultKeys.MESSAGE] = status + msg

    return results
