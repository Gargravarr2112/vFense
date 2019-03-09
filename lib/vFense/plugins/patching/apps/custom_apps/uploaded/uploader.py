from uuid import uuid4
import logging
import os
import shutil
from vFense import VFENSE_LOGGING_CONFIG, VFENSE_APP_TMP_PATH
from vFense.db.client import db_create_close, r
from vFense.errorz.error_messages import GenericResults
from vFense.errorz.status_codes import PackageCodes
from vFense.utils.common import date_parser, timestamp_verifier
from vFense.plugins.patching import *
from vFense.plugins.patching.apps.custom_apps.custom_apps import add_custom_app_to_agents


logging.config.fileConfig(VFENSE_LOGGING_CONFIG)
logger = logging.getLogger('rvapi')

TMP_DIR = VFENSE_APP_TMP_PATH

if not os.path.exists(TMP_DIR):
    os.mkdir(TMP_DIR)


def gen_uuid():
    return(str(uuid4()))


@db_create_close
def move_packages(username, customer_name, uri, method,
                  name=None, path=None, size=None, md5=None,
                  uuid=None, conn=None):

    files_stored = list()
    PKG_DIR = None
    FILE_PATH = None

    if name and uuid and path and size and md5:
        PKG_DIR = TMP_DIR + uuid + '/'
        FILE_PATH = PKG_DIR + name

        if not os.path.exists(PKG_DIR):
            try:
                os.mkdir(PKG_DIR)
            except Exception as e:
                logger.error(e)
        try:
            shutil.move(path, FILE_PATH)
            files_stored.append(
                {
                    'uuid': uuid,
                    'name': name,
                    'size': int(size),
                    'md5': md5,
                    'file_path': FILE_PATH
                }
            )

            results = (
                GenericResults(
                    username, uri, method
                ).file_uploaded(name, files_stored)
            )

        except Exception as e:
            results = (
                GenericResults(
                    username, uri, method
                ).file_failed_to_upload(name, e)
            )
            logger.error(e)

    return(results)


@db_create_close
def store_package_info_in_db(
        username, customer_name, uri, method,
        size, md5, operating_system,
        uuid, name, severity, arch, major_version,
        minor_version, release_date=0.0,
        vendor_name=None, description=None,
        cli_options=None, support_url=None,
        kb=None, conn=None):

    PKG_FILE = TMP_DIR + uuid + '/' + name
    URL_PATH = 'https://localhost/packages/tmp/' + uuid + '/'
    url = URL_PATH + name

    if os.path.exists(PKG_FILE):
        if (isinstance(release_date, str) or
            isinstance(release_date, str)):

            orig_release_date = release_date
            if (len(release_date.split('-')) == 3 or len(release_date.split('/')) == 3):
                release_date = (
                    r
                    .epoch_time(date_parser(release_date))
                )

            else:
                release_date = (
                    r
                    .epoch_time(
                        timestamp_verifier(release_date)
                    )
                )

        data_to_store = {
            CustomAppsKeys.Name: name,
            CustomAppsPerAgentKeys.Dependencies: [],
            CustomAppsKeys.RvSeverity: severity,
            CustomAppsKeys.VendorSeverity: severity,
            CustomAppsKeys.ReleaseDate: release_date,
            CustomAppsKeys.VendorName: vendor_name,
            CustomAppsKeys.Description: description,
            CustomAppsKeys.MajorVersion: major_version,
            CustomAppsKeys.MinorVersion: minor_version,
            CustomAppsKeys.Version: major_version + '.' + minor_version,
            CustomAppsKeys.OsCode: operating_system,
            CustomAppsKeys.Kb: kb,
            CustomAppsKeys.Hidden: 'no',
            CustomAppsKeys.CliOptions: cli_options,
            CustomAppsKeys.Arch: arch,
            CustomAppsKeys.RebootRequired: 'possible',
            CustomAppsKeys.SupportUrl: support_url,
            CustomAppsKeys.Customers: [customer_name],
            CustomAppsPerAgentKeys.Update: PackageCodes.ThisIsNotAnUpdate,
            CustomAppsKeys.FilesDownloadStatus: PackageCodes.FileCompletedDownload,
            CustomAppsKeys.AppId: uuid
        }
        file_data = (
            [
                {
                    FilesKeys.FileUri: url,
                    FilesKeys.FileSize: int(size),
                    FilesKeys.FileHash: md5,
                    FilesKeys.FileName: name
                }
            ]
        )
        try:
            updated = (
                r
                .table(AppCollections.CustomApps)
                .insert(data_to_store, conflict="replace")
                .run(conn)
            )

            add_custom_app_to_agents(
                username, customer_name,
                uri, method, file_data,
                app_id=uuid
            )

            data_to_store['release_date'] = orig_release_date
            results = (
                GenericResults(
                    username, uri, method
                ).object_created(uuid, 'custom_app', data_to_store)
            )
            logger.info(results)

        except Exception as e:
            results = (
                GenericResults(
                    username, uri, method
                ).something_broke(uuid, 'custom_app', e)
            )
            logger.exception(e)
    else:
        results = (
            GenericResults(
                username, uri, method
            ).file_doesnt_exist(name)
        )
        logger.info(results)

    return(results)
