import os
from vFense import VFENSE_VAR_PATH

class UbuntuDataDir():
    PLUGIN_DIR = os.path.join(VFENSE_VAR_PATH, 'vuln', 'ubuntu')
    HTML_DIR = os.path.join(PLUGIN_DIR, 'data/html')


class UbuntuUSNStrings():
    MAIN_URL = 'http://www.ubuntu.com'
    MAIN_USN_URL = 'http://www.ubuntu.com/usn'
    USR_URI = '/usn/usn-[0-9]+[0-9]+'
    NEXT_PAGE = '\?page=[0-9]+'
