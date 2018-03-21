import logging
import logging.config
from vFense import VFENSE_LOGGING_CONFIG

from vFense.core.decorators import time_it
from vFense.plugins.vuln.cve import CveKeys
from vFense.plugins.vuln.cve._db import fetch_cve_data, \
    fetch_vulnerability_categories

logging.config.fileConfig(VFENSE_LOGGING_CONFIG)
logger = logging.getLogger('cve')


@time_it
def get_cve_data(cve_id):
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
    info = {}

    data = fetch_cve_data(cve_id)
    if data:
        info = data[0]

    return(info)


@time_it
def get_vulnerability_categories(cve_id):
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

    data = fetch_vulnerability_categories(cve_id)
    if data:
        info = data[CveKeys.CveCategories]

    return(info)
