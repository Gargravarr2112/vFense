import os

from vFense import VFENSE_VAR_PATH

class WindowsDataDir():
    XLS_DIR = os.path.join(VFENSE_VAR_PATH, 'plugins', 'vuln', 'windows', 'xls')

class WindowsBulletinStrings():
    XLS_DOWNLOAD_URL = \
        'http://www.microsoft.com/en-us/download/confirmation.aspx?id=36982'
    WORKBOOK_SHEET = 'Bulletin Search'
