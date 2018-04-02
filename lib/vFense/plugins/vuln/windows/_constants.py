import os

class WindowsDataDir():
    PLUGIN_DIR = os.path.abspath(os.path.dirname(__file__))
    XLS_DIR = os.path.join(PLUGIN_DIR, 'data/xls')

class WindowsBulletinStrings():
    XLS_DOWNLOAD_URL = \
        'http://www.microsoft.com/en-us/download/confirmation.aspx?id=36982'
    WORKBOOK_SHEET = 'Bulletin Search'
