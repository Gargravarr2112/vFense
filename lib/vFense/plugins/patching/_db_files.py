import logging
import logging.config
from vFense import VFENSE_LOGGING_CONFIG

from vFense.db.client import db_create_close, r
from vFense.core.decorators import time_it, return_status_tuple
from vFense.plugins.patching import FileCollections, FilesKeys

logging.config.fileConfig(VFENSE_LOGGING_CONFIG)
logger = logging.getLogger('rvapi')

@time_it
@db_create_close
def file_data_exists(file_name, conn=None):
    """Check if file exists in the data base.
    Args:
        file_name (str): The name of the file you are searching.

    Basic Usage:
        >>> from vFense.plugins.patching._db_files import file_data_exists
        >>> file_name = 'libmagic1_5.09-2ubuntu0.3_amd64.deb'

    Returns:
        Boolean
    """
    exist = False
    try:
        is_empty = (
            r
            .table(FileCollections.Files)
            .get_all(file_name)
            .is_empty()
            .run(conn)
        )
        if not is_empty:
            exist = True

    except Exception as e:
        logger.exception(e)

    return exist

@time_it
@db_create_close
def fetch_file_data(app_id, agent_id=None, conn=None):
    """Fetch file data for app id or app id and agent id
    Args:
        app_id (str): The 64 character ID of the application.

    Kwargs:
        agent_id (str): The 32 character UUID of the agent

    Basic Usage:
        >>> from vFense.plugins.patching._db_files import fetch_file_data
        >>> app_id = '922bcb88f6bd75c1e40fcc0c571f603cd59cf7e05b4a192bd5d69c974acc1457'
        >>> agent_id = '7f242ab8-a9d7-418f-9ce2-7bcba6c2d9dc'
        >>> fetch_file_data(app_id, agent_id)

    Returns:
        List of dictionaries
        [
            {
                "file_hash": "d9af1cb42d87235d83aadeb014a542105ee7eea99fe45bed594b27008bb2c10c",
                "file_name": "gwibber-service-facebook_3.4.2-0ubuntu2.4_all.deb",
                "file_uri": "http://us.archive.ubuntu.com/ubuntu/pool/main/g/gwibber/gwibber-service-facebook_3.4.2-0ubuntu2.4_all.deb",
                "file_size": 7782
            }
        ]
    """
    try:
        if agent_id:
            data = list(
                r
                .table(FileCollections.Files)
                .filter(
                    lambda x: (
                        x[FilesKeys.AppIds].contains(app_id)
                        &
                        x[FilesKeys.AgentIds].contains(agent_id)
                    )
                )
                .without(FilesKeys.AppIds, FilesKeys.AgentIds,)
                .run(conn)
            )

        else:
            data = list(
                r
                .table(FileCollections.Files)
                .filter(
                    lambda x: (
                        x[FilesKeys.AppIds].contains(app_id)
                    )
                )
                .without(FilesKeys.AppIds, FilesKeys.AgentIds,)
                .run(conn)
            )

    except Exception as e:
        logger.exception(e)

    return data

@time_it
@db_create_close
def fetch_all_file_data(conn=None):
    """Retrieve all the files in our database
    Basic Usage:
        >>> from vFense.plugins.patching._db_files import fetch_all_file_data
        >>> fetch_all_file_data()

    Returns:
        List
        [
            {
                "file_hash": "f4cbc8e6a3e49001e2079bd697c91c20cd85f1a0471cdfe660ba7a4b5238f487",
                "file_uri": "http://us.archive.ubuntu.com/ubuntu/pool/main/b/bluez/bluez-cups_4.98-2ubuntu7.1_amd64.deb",
                "file_size": 70284
            },
            {
                "file_hash": "9259166bac143ed6ce1a224ea5b519017f8b81afbbfb0a654ea1a068ca8d8e71",
                "file_uri": "http://us.archive.ubuntu.com/ubuntu/pool/main/d/deja-dup/deja-dup_22.0-0ubuntu5_amd64.deb",
                "file_size": 596854
            }
        ]
    """
    data = []
    try:
        data = list(
            r
            .table(FileCollections.Files)
            .pluck(
                FilesKeys.FileHash, FilesKeys.FileSize,
                FilesKeys.FileUri, FilesKeys.FileName
            )
            .run(conn)
        )

    except Exception as e:
        logger.exception(e)

    return data


@time_it
@db_create_close
@return_status_tuple
def insert_file_data(app_id, file_data, agent_id=None, conn=None):
    """Insert file data into the database.
    Args:
        app_id (str): 64 character hex digest of the application.
        file_data (list): List of dictionaries.

    Kwargs:
        agent_id (str): 36 character UUID of the agent.

    Basic Usage:
        >>> from vFense.plugins.patching._db_files import insert_file_data
        >>> app_id = '3e480d178a945e8c35479c60a398da3d16a0f8c2aecf3306b2341466b5e897ae'
        >>> agent_id = '272ce70a-6cb1-4903-b395-bba4386a5171'
        >>> file_data = [
            {
                "file_hash": "d9af1cb42d87235d83aadeb014a542105ee7eea99fe45bed594b27008bb2c10c",
                "file_name": "gwibber-service-facebook_3.4.2-0ubuntu2.4_all.deb",
                "file_uri": "http://us.archive.ubuntu.com/ubuntu/pool/main/g/gwibber/gwibber-service-facebook_3.4.2-0ubuntu2.4_all.deb",
                "file_size": 7782
            }
        ]

    Returns:
        Tuple (status_code, count, error, generated ids)
        >>> (2001, 1, None, [])
    """
    data = {}
    try:
        if agent_id:
            data = (
                r
                .expr(file_data)
                .for_each(
                    lambda file_info:
                    r
                    .table(FileCollections.Files)
                    .insert(
                        {
                            FilesKeys.AppIds: [app_id],
                            FilesKeys.AgentIds: [agent_id],
                            FilesKeys.FileName: file_info[FilesKeys.FileName],
                            FilesKeys.FileSize: file_info[FilesKeys.FileSize],
                            FilesKeys.FileUri: file_info[FilesKeys.FileUri],
                            FilesKeys.FileHash: file_info[FilesKeys.FileHash],
                        }
                    )
                )
                .run(conn)
            )

        else:
            data = (
                r
                .expr(file_data)
                .for_each(
                    lambda file_info:
                    r
                    .table(FileCollections.Files)
                    .insert(
                        {
                            FilesKeys.AppIds: [app_id],
                            FilesKeys.AgentIds: [],
                            FilesKeys.FileName: file_info[FilesKeys.FileName],
                            FilesKeys.FileSize: file_info[FilesKeys.FileSize],
                            FilesKeys.FileUri: file_info[FilesKeys.FileUri],
                            FilesKeys.FileHash: file_info[FilesKeys.FileHash],
                        }
                    )
                )
                .run(conn)
            )

    except Exception as e:
        logger.exception(e)

    return data

@time_it
@db_create_close
@return_status_tuple
def update_file_data(app_id, file_data, agent_id=None, conn=None):
    """Update the file data in the database.
    Args:
        app_id (str): 64 character hex digest of the application.
        file_data (list): List of dictionaries.

    Kwargs:
        agent_id (str): 36 character UUID of the agent.

    Basic Usage:
        >>> app_id = '3e480d178a945e8c35479c60a398da3d16a0f8c2aecf3306b2341466b5e897ae'
        >>> agent_id = '272ce70a-6cb1-4903-b395-bba4386a5171'
        >>> file_data = [
            {
                "file_hash": "d9af1cb42d87235d83aadeb014a542105ee7eea99fe45bed594b27008bb2c10c",
                "file_name": "gwibber-service-facebook_3.4.2-0ubuntu2.4_all.deb",
                "file_uri": "http://us.archive.ubuntu.com/ubuntu/pool/main/g/gwibber/gwibber-service-facebook_3.4.2-0ubuntu2.4_all.deb",
                "file_size": 7782
            }
        ]

    Returns:
        Tuple (status_code, count, error, generated ids)
        >>> (2001, 1, None, [])
    """
    data = {}
    try:
        if agent_id:
            data = (
                r
                .expr(file_data)
                .for_each(
                    lambda file_info:
                    r
                    .table(FileCollections.Files)
                    .get(file_info[FilesKeys.FileName])
                    .update(
                        lambda fd:
                        {
                            FilesKeys.AppIds: (
                                fd[FilesKeys.AppIds]
                                .set_insert(app_id)
                            ),
                            FilesKeys.AgentIds: (
                                fd[FilesKeys.AgentIds]
                                .set_insert(agent_id)
                            )
                        }
                    )
                )
                .run(conn)
            )

        else:
            data = (
                r
                .expr(file_data)
                .for_each(
                    lambda file_info:
                    r
                    .table(FileCollections.Files)
                    .get(file_info[FilesKeys.FileName])
                    .update(
                        {
                            FilesKeys.AppIds: (
                                file_info[FilesKeys.AppIds]
                                .set_insert(app_id)
                            ),
                            FilesKeys.AgentIds: []
                        }
                    )
                )
                .run(conn)
            )

    except Exception as e:
        logger.exception(e)

    return data
