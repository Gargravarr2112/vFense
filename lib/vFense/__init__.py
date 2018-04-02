import os
import logging, logging.config
from vFense.supported_platforms import *

VFENSE_BASE_SRC_PATH = os.path.dirname(os.path.realpath(__file__))
VFENSE_BASE_PATH = (
    os.path.realpath(
        os.path.join(
            VFENSE_BASE_SRC_PATH, '..', '..'
        )
    )
)
BIN_DIR = '/usr/local/bin'
VFENSE_INIT_D = '/etc/init.d/vFense'
VFENSED = os.path.join(VFENSE_BASE_SRC_PATH, 'daemon', 'vFensed')
VFENSED_SYMLINK = os.path.join(BIN_DIR, 'vFensed')
VFENSE_TP_PATH = os.path.join(VFENSE_BASE_PATH, 'tp')
VFENSE_TEMPLATE_PATH = os.path.join(VFENSE_TP_PATH, 'templates')
VFENSE_WWW_PATH = os.path.join(VFENSE_TP_PATH, 'wwwstatic')
VFENSE_SSL_PATH = os.path.join(VFENSE_TP_PATH, 'data', 'ssl')
VFENSE_PLUGINS_PATH = os.path.join(VFENSE_BASE_SRC_PATH, 'plugins')
VFENSE_VULN_PATH = os.path.join(VFENSE_PLUGINS_PATH, 'vuln')
VFENSE_VAR_PATH = os.path.join(VFENSE_BASE_PATH, 'var')
VFENSE_TMP_PATH = os.path.join(VFENSE_VAR_PATH, 'tmp')
VFENSE_LOG_PATH = os.path.join(VFENSE_VAR_PATH, 'log')
VFENSE_APP_PATH = os.path.join(VFENSE_VAR_PATH, 'packages')
VFENSE_SCHEDULER_PATH = os.path.join(VFENSE_VAR_PATH, 'scheduler')
VFENSE_APP_TMP_PATH = os.path.join(VFENSE_APP_PATH, 'tmp')
VFENSE_APP_DEP_PATH = os.path.join(VFENSE_APP_PATH, 'dependencies')
VFENSE_CONF_PATH = os.path.join(VFENSE_BASE_PATH, 'conf')
VFENSE_LOGGING_CONFIG = os.path.join(VFENSE_CONF_PATH, 'logging.config')
VFENSE_DB_CONFIG = os.path.join(VFENSE_CONF_PATH, 'database.conf')
###RETHINKDB SPECIFIC CONFIG
RETHINK_SOURCE_CONF = os.path.join(VFENSE_CONF_PATH ,'rethinkdb_vFense.conf')
RETHINK_PATH = '/usr/share/rethinkdb'
RETHINK_USER = 'rethinkdb'
RETHINK_INSTANCES_PATH = '/etc/rethinkdb/instances.d'
RETHINK_DATA_PATH = '/var/lib/rethinkdb/vFense/data'
RETHINK_CONF = '/etc/rethinkdb/instances.d/vFense.conf'
RETHINK_WEB = '/usr/share/rethinkdb/web'
RETHINK_PID_FILE = '/var/run/rethinkdb/vFense/pid_file'
SCHEDULER_PY = 'apscheduler/scheduler.py'

def get_nginx_config_location():
    config_dir = None
    config = None
    if get_distro() in DEBIAN_DISTROS:
        config_dir = '/etc/nginx/sites-enabled/'
    elif get_distro() in REDHAT_DISTROS:
        config_dir = '/etc/nginx/conf.d/'

    if config_dir:
        config = os.path.join(config_dir, 'vFense.conf')

    return config


def get_sheduler_location():
    sched_location = ''
    for site in site_packages:
        sched_location = site + '/' + SCHEDULER_PY
        if os.path.exists(sched_location):
            return(sched_location)
    return(sched_location)

