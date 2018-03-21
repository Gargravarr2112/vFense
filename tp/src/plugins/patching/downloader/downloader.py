import logging
import logging.config
from vFense import (
    VFENSE_LOGGING_CONFIG, VFENSE_APP_PATH,
    VFENSE_APP_DEP_PATH
)
import os
import re

from urlgrabber import urlgrab

from vFense.errorz.status_codes import PackageCodes
from vFense.utils.common import hash_verify

from vFense.plugins.patching import AppsKeys, AppCollections
from vFense.plugins.patching._constants import CommonFileKeys
from vFense.plugins.patching._db import update_app_data_by_app_id

logging.config.fileConfig(VFENSE_LOGGING_CONFIG)
logger = logging.getLogger('rvapi')


def create_necessary_dirs():
    if not os.path.exists(VFENSE_APP_PATH):
        os.mkdir(VFENSE_APP_PATH)
    if not os.path.exists(VFENSE_APP_DEP_PATH):
        os.mkdir(VFENSE_APP_DEP_PATH)


def check_if_redhat(os_string):
    REDHAT = 'Red Hat Enterprise Linux Server'
    if re.search(REDHAT, os_string, re.IGNORECASE):
        return True

    return False


def download_file(uri, dl_path, throttle):
    if uri.startswith('https://api.github.com/'):
        # TODO: handle 200 and 302 response
        headers = (("Accept", "application/octet-stream"),)
        urlgrab(uri, filename=dl_path, throttle=throttle, http_headers=headers)

    else:
        urlgrab(uri, filename=dl_path, throttle=throttle)


def download_all_files_in_app(app_id, os_code, os_string=None, file_data=None,
        throttle=0, collection=AppCollections.UniqueApplications):

    create_necessary_dirs()
    throttle *= 1024

    if not file_data and check_if_redhat(os_string):
        download_status = {
            AppsKeys.FilesDownloadStatus: \
                PackageCodes.AgentWillDownloadFromVendor
        }
        update_app_data_by_app_id(app_id, download_status, collection)

    elif len(file_data) > 0:
        app_path = os.path.join(VFENSE_APP_PATH, str(app_id))
        if not os.path.exists(app_path):
            os.mkdir(app_path)

        num_of_files_to_download = len(file_data)
        num_of_files_downloaded = 0
        num_of_files_mismatch = 0
        num_of_files_failed = 0
        num_of_files_invalid_uri = 0

        new_status = {
            AppsKeys.FilesDownloadStatus: PackageCodes.FileIsDownloading
        }

        for file_info in file_data:
            uri = str(file_info[CommonFileKeys.PKG_URI])
            lhash = str(file_info[CommonFileKeys.PKG_HASH])
            fname = str(file_info[CommonFileKeys.PKG_NAME])
            fsize = file_info[CommonFileKeys.PKG_SIZE]

            if os_code == 'linux':
                file_path = os.path.join(VFENSE_APP_DEP_PATH, fname)
            else:
                file_path = os.path.join(app_path, fname)

            symlink_path = os.path.join(app_path, fname)
            cmd = 'ln -s %s %s' % (file_path, symlink_path)

            try:
                if uri and not os.path.exists(file_path):
                    download_file(uri, file_path, throttle)

                    if os.path.exists(file_path):
                        if lhash:
                            hash_match = hash_verify(
                                orig_hash=lhash, file_path=file_path
                            )

                            if hash_match:
                                num_of_files_downloaded += 1

                                if os_code == 'linux':
                                    if not os.path.islink(file_path):
                                        os.system(cmd)
                            else:
                                num_of_files_mismatch += 1

                        elif fsize and not lhash:
                            if os.path.getsize(file_path) == fsize:
                                num_of_files_downloaded += 1
                            else:
                                num_of_files_mismatch += 1
                    else:
                        num_of_files_failed += 1

                elif os.path.exists(file_path) and os_code == 'linux':

                    if not os.path.islink(symlink_path):
                        os.system(cmd)

                    num_of_files_downloaded += 1

                elif os.path.exists(file_path) and os_code != 'linux':
                    num_of_files_downloaded += 1

                elif uri:
                    num_of_files_invalid_uri += 1

            except Exception as e:
                logger.exception(e)

        if num_of_files_downloaded == num_of_files_to_download:
            new_status[AppsKeys.FilesDownloadStatus] = (
                PackageCodes.FileCompletedDownload
            )

        elif num_of_files_mismatch > 0:
            new_status[AppsKeys.FilesDownloadStatus] = (
                PackageCodes.FileSizeMisMatch
            )

        elif num_of_files_failed > 0:
            new_status[AppsKeys.FilesDownloadStatus] = (
                PackageCodes.FileFailedDownload
            )

        elif num_of_files_invalid_uri > 0:
            new_status[AppsKeys.FilesDownloadStatus] = (
                PackageCodes.InvalidUri
            )

        db_update_response = update_app_data_by_app_id(
            app_id, new_status, collection
        )

        logger.info(
            '%s, %s, %s, %s' %
            (collection, app_id, str(new_status), db_update_response)
        )
