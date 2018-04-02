import logging
import logging.config
from vFense import VFENSE_LOGGING_CONFIG

from vFense.core.decorators import time_it
from vFense.plugins.vuln.windows import WindowsSecurityBulletinKeys
from vFense.plugins.vuln.windows._db import fetch_vuln_ids, \
    fetch_vuln_data

logging.config.fileConfig(VFENSE_LOGGING_CONFIG)
logger = logging.getLogger('cve')

@time_it
def get_vuln_ids(kb):
    """Retrieve Windows Bulletin IDS and CVE_IDS for an Application
    Args:
        kb (str): The KB number of the application (KB980436)

    Basic Usage:
        >>> from vFense.plugins.vuln.windows.ms import get_vuln_ids
        >>> kb = 'KB980436'
        >>> get_vuln_ids(kb)

    Returns:
        Dictionary
        {
            "cve_ids": [
                "CVE-2009-3555", 
                "CVE-2010-2566"
            ], 
            "bulletin_id": "MS10-049"
        }
    """

    info = {
        WindowsSecurityBulletinKeys.BulletinId: '',
        WindowsSecurityBulletinKeys.CveIds: []
    }

    data = fetch_vuln_ids(kb)
    if data:
        info = data[0]
        
    return(info)


@time_it
def get_vuln_data_by_vuln_id(vuln_id):
    """Retrieve Windows Bulletin data for an Application by bulletin id.
    Args:
        vuln_id (str): The vulnerability id aka (MS10-049)

    Basic Usage:
        >>> from vFense.plugins.vuln.windows.ms import get_vuln_data_by_vuln_id
        >>> vuln_id = 'MS10-049'
        >>> get_vuln_data_by_vuln_id(vuln_id)

    Returns:
    {
        "bulletin_details": "Vulnerabilities in SChannel could allow Remote Code Execution", 
        "supercedes": [
            {
                "supercedes_bulletin_kb": "KB960225", 
                "supercedes_bulletin_id": "MS09-007"
            }
        ], 
        "id": "03639df1f16464ef9defe6d1735fd032432befdbd325ab4bb24993fc58f287ea", 
        "cve_ids": [
            "CVE-2009-3555", 
            "CVE-2010-2566"
        ], 
        "bulletin_id": "MS10-049", 
        "date_posted": 1281423600
    }
    """

    info = {}

    data = fetch_vuln_data(vuln_id)
    if data:
        info = data[0]
        
    return(info)
