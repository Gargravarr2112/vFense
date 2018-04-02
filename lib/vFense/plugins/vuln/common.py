import logging
import logging.config
from vFense import VFENSE_LOGGING_CONFIG
from hashlib import sha256


logging.config.fileConfig(VFENSE_LOGGING_CONFIG)
logger = logging.getLogger('cve')

def build_bulletin_id(data):
    return (sha256(data).hexdigest())
