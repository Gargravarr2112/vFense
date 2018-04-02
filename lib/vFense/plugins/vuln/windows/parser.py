import os
import re
import sys
import gc
import logging
import logging.config
from vFense import VFENSE_LOGGING_CONFIG

from time import mktime
from datetime import datetime

from xlrd import open_workbook, xldate_as_tuple

from vFense.plugins.vuln.common import build_bulletin_id
from vFense.plugins.vuln.windows import WindowsSecurityBulletinKeys
from vFense.plugins.vuln.windows._constants import WindowsDataDir, \
    WindowsBulletinStrings
from vFense.plugins.vuln.windows._db import insert_bulletin_data
from vFense.plugins.vuln.windows.downloader import download_latest_xls_from_msft
from vFense.db.client import r

logging.config.fileConfig(VFENSE_LOGGING_CONFIG)
logger = logging.getLogger('cve')

def parse_spread_sheet(bulletin_file):
    """Parse the entire microsoft excel bulleting data and 
        return the data, ready to be inserted into the database.
    Args:
        bulletin_file (str): The file location on disk
    Returns:
        List of dictionairies
    """
    bulletin_list = []
    workbook = open_workbook(bulletin_file)
    sheet = workbook.sheet_by_name(WindowsBulletinStrings.WORKBOOK_SHEET)
    rows = range(sheet.nrows)
    rows.pop(0)
    for i in rows:
        row = sheet.row_values(i)
        bulletin_dict = {}
        supercede_list = []
        if row[7] != '':
            row[7] = 'KB' + str(int(row[7]))

        if row[2] != '':
            row[2] = 'KB' + str(int(row[2]))

        rows_to_use = (
            row[1] + row[2] + row[3] + row[4] +
            row[6] + row[7] + row[8] + row[9]
        )
        rows_to_use = \
            unicode(rows_to_use).encode(sys.stdout.encoding, 'replace')
        built_id = build_bulletin_id(rows_to_use)
        bulletin_dict[WindowsSecurityBulletinKeys.Id] = built_id
        date = xldate_as_tuple(row[0], workbook.datemode)
        epoch_time = mktime(datetime(*date).timetuple())
        bulletin_dict[WindowsSecurityBulletinKeys.DatePosted] = (
            r.epoch_time(epoch_time)
        )

        # Need to see if I can pull the column names and use that instead
        # of using the row number
        bulletin_dict[WindowsSecurityBulletinKeys.BulletinId] = row[1]
        bulletin_dict[WindowsSecurityBulletinKeys.BulletinKb] = row[2]
        bulletin_dict[WindowsSecurityBulletinKeys.BulletinSeverity] = row[3]
        bulletin_dict[WindowsSecurityBulletinKeys.BulletinImpact] = row[4]
        bulletin_dict[WindowsSecurityBulletinKeys.Details] = row[5]
        bulletin_dict[WindowsSecurityBulletinKeys.AffectedProduct] = row[6]
        bulletin_dict[WindowsSecurityBulletinKeys.ComponentKb] = row[7]
        bulletin_dict[WindowsSecurityBulletinKeys.AffectedComponent] = row[8]
        bulletin_dict[WindowsSecurityBulletinKeys.ComponentImpact] = row[9]
        bulletin_dict[WindowsSecurityBulletinKeys.ComponentSeverity] = row[10]

        if len(row) == 15:
            supercedes = row[12]
            reboot = row[13]
            cve_ids = row[14]
        else:
            supercedes = row[11]
            reboot = row[12]
            cve_ids = row[13]

        info = supercedes.split(',')
        for j in info:
            bulletin_data = j.split('[')
            if len(bulletin_data) > 1:
                bulletin_id = bulletin_data[0]
                bulletin_kb = re.sub('^', 'KB', bulletin_data[1][:-1])
            else:
                bulletin_id = bulletin_data[0]
                bulletin_kb = None

            supercede_list.append(
                {
                    WindowsSecurityBulletinKeys.SupersedesBulletinId:
                        bulletin_id,
                    WindowsSecurityBulletinKeys.SupersedesBulletinKb:
                        bulletin_kb
                }
            )
        bulletin_dict[WindowsSecurityBulletinKeys.Supersedes] = supercede_list
        bulletin_dict[WindowsSecurityBulletinKeys.Reboot] = reboot
        bulletin_dict[WindowsSecurityBulletinKeys.CveIds] = cve_ids.split(',')
        bulletin_list.append(bulletin_dict)

    return(bulletin_list)

def parse_bulletin_and_updatedb():
    """Download the Bulletin and parse it and insert into the database
    """
    logger.info('starting microsoft security bulletin update process')
    if not os.path.exists(WindowsDataDir.XLS_DIR):
        os.makedirs(WindowsDataDir.XLS_DIR, 0755)
    downloaded, xls_file = download_latest_xls_from_msft()
    if downloaded:
        bulletin_data = parse_spread_sheet(xls_file)
        insert_bulletin_data(bulletin_data)

    logger.info('finished microsoft security bulletin update process')
    gc.collect()

#parse_bulletin_and_updatedb()
