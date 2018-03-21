import sys
import logging
import logging.config
from vFense import VFENSE_LOGGING_CONFIG
from vFense.core.decorators import return_status_tuple, time_it

from vFense.plugins.vuln.ubuntu import *
from vFense.plugins.vuln.ubuntu._db import fetch_vuln_ids, \
    fetch_vuln_data

logging.config.fileConfig(VFENSE_LOGGING_CONFIG)
logger = logging.getLogger('cve')

@time_it
def get_vuln_ids(name, version, os_string):
    """Retrieve Ubuntu USN IDS and CVE_IDS for an Application
    Args:
        name (str): The name of the application
        version (str): The version of the application
        os_string (str): The Version of Ubuntu (Ubuntu 12.04 LTS)

    Basic Usage:
        >>> from vFense.plugins.vuln.ubuntu.usn.py import get_vuln_ids
        >>> name = 'nvidia-173'
        >>> version = '173.14.22-0ubuntu11.2'
        >>> os_string = 'Ubuntu 10.04 LTS'
        >>> get_vuln_ids(name, version, os_string)

    Returns:
        Dictionary
    """

    info = {
        UbuntuSecurityBulletinKeys.BulletinId: '',
        UbuntuSecurityBulletinKeys.CveIds: []
    }

    data = fetch_vuln_ids(name, version, os_string)
    if data:
        info = data[0]
        
    return(info)


@time_it
def get_vuln_data_by_vuln_id(vuln_id):
    """Retrieve Ubuntu Bulletin data for an Application by bulletin id.
    Args:
        vuln_id (str): The vulnerability id aka (USN-2161-1)

    Basic Usage:
        >>> from vFense.plugins.vuln.windows.ms import get_vuln_data_by_vuln_id
        >>> vuln_id = 'USN-2161-1'
        >>> get_vuln_data_by_vuln_id(vuln_id)

    Returns:
    {
        "bulletin_details": "Florian Weimer discovered that libyaml-libyaml-perl incorrectly handled\ncertain large YAML documents. An attacker could use this issue to cause\
            nlibyaml-libyaml-perl to crash, resulting in a denial of service, or\npossibly execute arbitrary code. (CVE-2013-6393)\n\nIvan Fratric discovered that libyaml-libyaml-per
            l incorrectly handled\ncertain malformed YAML documents. An attacker could use this issue to cause\nlibyaml-libyaml-perl to crash, resulting in a denial of service, or\np
            ossibly execute arbitrary code. (CVE-2014-2525)\n\n", 
        "supercedes": [], 
        "id": "f4a193df32583980884dbb846947ebff0f6f825e01e0416062f15b4676f4ba2b", 
        "cve_ids": [
            "CVE-2013-6393", 
            "CVE-2014-2525"
        ], 
        "bulletin_id": "USN-2161-1", 
        "date_posted": 1396508400
    }
    """

    info = {}

    data = fetch_vuln_data(vuln_id)
    if data:
        info = data[0]
        
    return(info)
