import os

from vFense import VFENSE_VAR_PATH

class UbuntuDataDir():
    USN_DIR = os.path.join(VFENSE_VAR_PATH, 'plugins', 'vuln', 'ubuntu', 'usn')


class UbuntuUSNStrings():
    MAIN_URL = 'http://www.ubuntu.com'
