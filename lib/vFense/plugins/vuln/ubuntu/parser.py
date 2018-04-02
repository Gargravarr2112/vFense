import json
import os
import glob
import logging
import logging.config
from vFense import VFENSE_LOGGING_CONFIG
from time import mktime
from datetime import datetime

from vFense.db.client import r

from vFense.utils.common import month_to_num_month
from vFense.plugins.vuln.common import build_bulletin_id
from vFense.plugins.vuln.ubuntu import *
from vFense.plugins.vuln.ubuntu._constants import *
from vFense.plugins.vuln.ubuntu._db import insert_bulletin_data

import requests
from mailbox import mbox, mboxMessage

logging.config.fileConfig(VFENSE_LOGGING_CONFIG)
logger = logging.getLogger('cve')
logger.setLevel(level=logging.DEBUG)

def format_data_to_insert_into_db(
    usn_id, details, cve_ids,
    apps_data, date_posted
    ):
    """Parse the ubuntu data and place it into a array
    Args:
        usn_id (str): The Ubuntu Bulletin Id.
        details (str): The description of the bulletin.
        cve_ids (list): List of cve ids.
        apps_data (list): List of dictionaries, containing
            the app name and version.
        date_posted (str) The time in epoch
    Returns:
        Dictionary inside of a list

    """

    data_to_insert = []
    logger.debug('Processing {0}'.format(apps_data))
    for data in apps_data:
        string_to_build_id = ''
        for app in data[UbuntuSecurityBulletinKeys.Apps]:
            string_to_build_id = (
                string_to_build_id +
                app['name'] +
                app['version']
            )

        string_to_build_id = (
            string_to_build_id +
            data[UbuntuSecurityBulletinKeys.OsString]
        )

        bulletin_id = build_bulletin_id(string_to_build_id) #Actually just a SHA256 hash of the title
        try:
            if isinstance(details, unicode):
                details = details.decode('utf-8')
            elif isinstance(details, basestring):
                details = unicode(details.decode('utf-8'))
        except Exception as e:
            logger.exception(e)
            details = details.encode('utf-8').decode('utf-8')

        data_to_insert.append(
            {
                UbuntuSecurityBulletinKeys.Id: bulletin_id,
                UbuntuSecurityBulletinKeys.BulletinId: usn_id,
                UbuntuSecurityBulletinKeys.Details: details,
                UbuntuSecurityBulletinKeys.DatePosted: date_posted,
                UbuntuSecurityBulletinKeys.Apps: data[UbuntuSecurityBulletinKeys.Apps],
                UbuntuSecurityBulletinKeys.OsString: data[UbuntuSecurityBulletinKeys.OsString],
                UbuntuSecurityBulletinKeys.CveIds: cve_ids
            }
        )

    return(data_to_insert)


def process_usn_json(usn_json, os_string):
    """Process the USN as a JSON string, extracting the various data we want to store in the DB.

    Args:
        usn_uri (mboxMessage):

    """
    logger.debug("Processing USN message {0}".format(usn_json['info']))
    details = ''
    date_posted = ''
    bulletin_id = ''
    app_info = []
    data = []
    cve_references = []

    date_posted = usn_json['date']

    bulletin_id = usn_json['info']

    if usn_json['threat']:
        usn_json['threat'].sort()
        details = ''.join(list(set(usn_json['threat']))) #Threats may be duplicated. Casting to a set leaves only unique values. Cast back to a list and turn into a string

    for package in usn_json['update']:
        package['name'] = package['package']
        del package['package']
        new_app = { UbuntuSecurityBulletinKeys.Apps: [package], UbuntuSecurityBulletinKeys.OsString : os_string }
        app_info.append(new_app)

    cve_references = usn_json['CVEs']

    data = format_data_to_insert_into_db(bulletin_id, details, cve_references, app_info, date_posted)
    return data


def import_processed_usn_email_exports(usneasy_dump_folder=UbuntuDataDir.USN_DIR, os_string=None):
    """By using a lightly modified version of https://github.com/jameswhite/usneasy to parse dumps of the USNs into consistent JSON files,
    importing them into vFense becomes a LOT easier. If given a folder name, loop through the files, load them as JSON and import the contents. Assumes the 
    filename is the OS version (hence the modified version).

    Kwargs:
        usneasy_dump_folder (str): Folder containing JSON dumps of the USN bulletins
        os_string (str): Fallback OS string in case the folder contains various files all from the same OS

    """
    logger.debug("Beginning Ubuntu USN parse")
    
    for json_file in glob.iglob(os.path.join(usneasy_dump_folder, '*.json')):
        logger.debug("Loading USNEasy dump {0}".format(json_file))
        file_handle = open(json_file, 'r')
        json_usn = json.load(file_handle)
        if not os_string:
            os_string = os.path.splitext(os.path.basename(json_file))[0]

        logger.debug('Working with {0}'.format(os_string))

        data = []

        for usn in json_usn['security_notices']:
            data_to_update = process_usn_json(usn, os_string)
            data.extend(data_to_update)
        insert_bulletin_data(data)

    logger.info('Finished Ubuntu USN update process')
