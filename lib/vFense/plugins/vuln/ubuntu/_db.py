import logging
import logging.config
from vFense import VFENSE_LOGGING_CONFIG
from vFense.core.decorators import return_status_tuple, time_it
from vFense.db.client import db_create_close, r
from vFense.plugins.vuln import *
from vFense.plugins.vuln._constants import *
from vFense.plugins.vuln.ubuntu import *
from vFense.plugins.vuln.ubuntu._constants import *

logging.config.fileConfig(VFENSE_LOGGING_CONFIG)
logger = logging.getLogger('cve')


@time_it
@db_create_close
def fetch_vuln_ids(name, version, os_string, conn=None):
    """Retrieve Ubuntu USN IDS and CVE_IDS for an Application
    Args:
        name (str): The name of the application
        version (str): The version of the application
        os_string (str): The Version of Ubuntu (Ubuntu 12.04 LTS)

    Basic Usage:
        >>> from vFense.plugins.vuln.ubuntu._db import fetch_ubuntu_vuln_ids
        >>> name = 'nvidia-173'
        >>> version = '173.14.22-0ubuntu11.2'
        >>> os_string = 'Ubuntu 10.04 LTS'
        >>> fetch_ubuntu_vuln_ids(name, version, os_string)

    Returns:
        Dictionary
        {
            "cve_ids": [], 
            "bulletin_id": "USN-1523-1"
        }
    """
    data = []
    try:
        data = list(
            r
            .table(UbuntuSecurityCollection.Bulletin)
            .get_all(
                [name, version],
                index=UbuntuSecurityBulletinIndexes.NameAndVersion
            )
            .pluck(UbuntuSecurityBulletinKeys.BulletinId, UbuntuSecurityBulletinKeys.CveIds)
            .run(conn)
        )

    except Exception as e:
        logger.exception(e)

    return(data)


@time_it
@db_create_close
def fetch_vuln_data(vuln_id, conn=None):
    """Retrieve Ubuntu Bulletin data for an Application by bulletin id.
    Args:
        vuln_id (str): The vulnerability id aka (USN-2161-1)

    Basic Usage:
        >>> from vFense.plugins.vuln.ubuntu._db import fetch_vuln_data
        >>> vuln_id = 'USN-2161-1'
        >>> fetch_vuln_data(vuln_id)

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

    data = []
    map_hash = (
        {
            UbuntuSecurityBulletinKeys.Id: r.row[UbuntuSecurityBulletinKeys.Id],
            UbuntuSecurityBulletinKeys.BulletinId: r.row[UbuntuSecurityBulletinKeys.BulletinId],
            UbuntuSecurityBulletinKeys.DatePosted: r.row[UbuntuSecurityBulletinKeys.DatePosted].to_epoch_time(),
            UbuntuSecurityBulletinKeys.Details: r.row[UbuntuSecurityBulletinKeys.Details],
            UbuntuSecurityBulletinKeys.CveIds: r.row[UbuntuSecurityBulletinKeys.CveIds],
            SecurityBulletinKeys.Supersedes: [],
        }
    )
    try:
        data = list(
            r
            .table(UbuntuSecurityCollection.Bulletin)
            .get_all(vuln_id, index=UbuntuSecurityBulletinIndexes.BulletinId)
            .map(map_hash)
            .run(conn)
        )

    except Exception as e:
        logger.exception(e)

    return(data)


@time_it
@db_create_close
@return_status_tuple
def insert_bulletin_data(bulletin_data, conn=None):
    """Insert Ubuntu Bulletin data into the Windows Security Bulletin Collection
        DO NOT CALL DIRECTLY
    Args:
        bulletin_data (list|dict): List or dictionary of vulnerability data

    Basic Usage:
        >>> from vFense.plugins.vuln.ubuntu._db insert_into_bulletin_collection
        >>> insert_into_bulletin_collection([{"bulletin_data goes in here"}])

    Returns:
        Tuple (status_code, count, error, generated ids)
        >>> (2001, 1, None, [])
    """

    data = {}
    try:
        data = (
            r
            .table(UbuntuSecurityCollection.Bulletin)
            .insert(bulletin_data, conflict="replace")
            .run(conn)
        )

    except Exception as e:
        logger.exception(e)

    return(data)
