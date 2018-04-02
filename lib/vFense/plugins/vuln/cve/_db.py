import logging
import logging.config
from vFense import VFENSE_LOGGING_CONFIG

from vFense.core.decorators import return_status_tuple, time_it
from vFense.db.client import db_create_close, r
from vFense.plugins.vuln.cve import CVECollections, CveKeys
from vFense.plugins.vuln.cve._constants import CVEStrings, CVECategories

logging.config.fileConfig(VFENSE_LOGGING_CONFIG)
logger = logging.getLogger('cve')

@time_it
@db_create_close
def fetch_vulnerability_categories(cve_id, conn=None):
    """Retrieve CVE Categories
    Args:
        cve_id (str): The CVE ID - CVE-2014-2525

    Basic Usage:
        >>> from vFense.plugins.vuln.cve._db import fetch_vulnerability_categories
        >>> fetch_vulnerability_categories('CVE-2014-2525')

    Returns:
        Dictionary
    """
    info = {}
    try:
        info = (
            r
            .table(CVECollections.CVE)
            .get(cve_id)
            .pluck(CveKeys.CveCategories)
            .run(conn)
        )

    except Exception as e:
        logger.exception(e)

    return(info)


@db_create_close
def fetch_cve_data(cve_id, conn=None):
    """Retrieve CVE vulnerability data for an Application by cve id.
    Args:
        cve_id (str): The cve id aka (CVE-2014-2525)

    Basic Usage:
        >>> from vFense.plugins.vuln.cve._db import fetch_cve_data
        >>> cve_id = 'USN-2161-1'
        >>> fetch_cve_data(cve_id)

    Returns:
    [
        {
            "cve_modified_date": 1391760000,
            "vulnerability_categories": [
                "Denial Of Service"
            ],  
            "cvss_vector": [
                {
                    "metric": "Access Vector",
                    "value": "Network"
                },  
                {
                    "metric": "Access Complexity",
                    "value": "Medium"
                },  
            ],  
            "cve_sev": "Medium",
            "cve_id": "CVE-2013-6393",
            "cvss_base_score": "6.8",
            "cve_refs": [
                {
                    "url": "https://bugzilla.redhat.com/show_bug.cgi?id=1033990",
                    "source": "CONFIRM",
                    "id": "https://bugzilla.redhat.com/show_bug.cgi?id=1033990"
                },
                {
                    "url": "https://bugzilla.redhat.com/attachment.cgi?id=847926&action=diff",
                    "source": "MISC",
                    "id": "https://bugzilla.redhat.com/attachment.cgi?id=847926&action=diff"
                },
            ]
            "cvss_impact_subscore": "6.4",
            "cve_published_date": 1391673600,
            "cvss_exploit_subscore": "8.6",
            "cvss_score": "6.8",
            "cve_descriptions": [
                {
                    "source": "cve",
                    "description": "The yaml_parser_scan_tag_uri function in scanner.c in LibYAML before 0.1.5 performs an incorrect cast, which allows remote attackers to cause a denial of service (application crash) and possibly execute arbitrary code via crafted tags in a YAML document, which triggers a heap-based buffer overflow."
                }
            ]
        }
    ]
    """
    data = []
    map_hash = (
        {
            CveKeys.CveId: r.row[CveKeys.CveId],
            CveKeys.CveCategories: r.row[CveKeys.CveCategories],
            CveKeys.CveDescriptions: r.row[CveKeys.CveDescriptions],
            CveKeys.CveRefs: r.row[CveKeys.CveRefs],
            CveKeys.CveSev: r.row[CveKeys.CveSev],
            CveKeys.CvssScore: r.row[CveKeys.CvssScore],
            CveKeys.CvssBaseScore: r.row[CveKeys.CvssBaseScore],
            CveKeys.CvssImpactSubScore: r.row[CveKeys.CvssImpactSubScore],
            CveKeys.CvssExploitSubScore: r.row[CveKeys.CvssExploitSubScore],
            CveKeys.CvssVector: r.row[CveKeys.CvssVector],
            CveKeys.CvePublishedDate: r.row[CveKeys.CvePublishedDate].to_epoch_time(),
            CveKeys.CveModifiedDate: r.row[CveKeys.CveModifiedDate].to_epoch_time(),
        }
    )
    try:
        data = (
            r
            .table(CVECollections.CVE)
            .get_all(cve_id)
            .map(map_hash)
            .run(conn)
        )

    except Exception as e:
        logger.exception(e)

    return(data)


@time_it
@db_create_close
@return_status_tuple
def insert_cve_data(cve_data, conn=None):
    """Insert CVE Data into the CVE Collection
        DO NOT CALL DIRECTLY
    Args:
        cve_data (list|dict): List or dictionary of cve data

    Basic Usage:
        >>> from vFense.plugins.vuln.cve._db insert_into_cve_collection
        >>> insert_into_cve_collection([{"cve_data goes in here"}])

    Returns:
        Tuple (status_code, count, error, generated ids)
        >>> (2001, 1, None, [])
    """
    data = {}
    try:
        data = (
            r
            .table(CVECollections.CVE)
            .insert(cve_data, conflict="replace")
            .run(conn)
        )

    except Exception as e:
        logger.exception(e)

    return(data)


@time_it
@db_create_close
@return_status_tuple
def update_cve_categories(conn=None):
    """Update CVE Categories in the CVE Collection
    Args:
        cve_data (list|dict): List or dictionary of cve data

    Basic Usage:
        >>> from vFense.plugins.vuln.cve._db update_cve_categories
        >>> update_cve_categories([{"cve_data goes in here"}])

    Returns:
        Tuple (status_code, count, error, generated ids)
        >>> (2004, 6730, None, [])
    """
    data = {}
    try:
        data = (
            r
            .expr(CVECategories.CATEGORIES)
            .for_each(
                lambda category:
                r
                .table(CVECollections.CVE)
                .filter(
                    lambda x:
                    x[CveKeys.CveDescriptions]
                    .contains(
                        lambda y:
                            y[CVEStrings.DESCRIPTION].match('(?i)'+category)
                    )
                ).update(
                    lambda y:
                    {
                        CveKeys.CveCategories:
                            y[CveKeys.CveCategories].set_insert(category)
                    }
                )
            )
            .run(conn)
        )

    except Exception as e:
        logger.exception(e)

    return(data)
