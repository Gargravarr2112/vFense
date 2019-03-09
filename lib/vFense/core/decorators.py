import logging, logging.config
from vFense import VFENSE_LOGGING_CONFIG
import json
from datetime import datetime
from functools import wraps

from tornado.web import HTTPError

from vFense.errorz._constants import ApiResultKeys
from vFense.errorz.status_codes import DbCodes, \
    GenericCodes, GenericFailureCodes
from vFense.errorz.results import Results


logging.config.fileConfig(VFENSE_LOGGING_CONFIG)
logger = logging.getLogger('vFense_stats')


def return_status_tuple(fn):
    """Return the status of the db_call, plus the number of documents"""
    def db_wrapper(*args, **kwargs):
        status = fn(*args, **kwargs)
        if status['deleted'] > 0:
            return_code = (DbCodes.Deleted, status['deleted'], None, [])

        elif status['errors'] > 0:
            return_code = (
                DbCodes.Errors, status['errors'], status['first_error'], []
            )

        elif status['inserted'] > 0 and status['replaced'] < 1:
            if status.get('generated_keys'):
                return_code = (
                    DbCodes.Inserted, status['inserted'],
                    None, status['generated_keys']
                )
            else:
                return_code = (
                    DbCodes.Inserted, status['inserted'],
                    None, []
                )

        elif status['inserted'] > 0 and status['replaced'] > 0:
            if status.get('generated_keys'):
                return_code = (
                    DbCodes.Inserted, (status['inserted'], status['replaced']),
                    None, status['generated_keys']
                )
            else:
                return_code = (
                    DbCodes.Inserted, (status['inserted'], status['replaced']),
                    None, []
                )

        elif status['replaced'] > 0 and status['inserted'] < 1:
            return_code = (DbCodes.Replaced, status['replaced'], None, [])

        elif status['skipped'] > 0:
            return_code = (DbCodes.Skipped, status['skipped'], None, [])

        elif status['unchanged'] > 0:
            return_code = (DbCodes.Unchanged, status['unchanged'], None, [])

        else:
            return_code = (DbCodes.DoesNotExist, 0, None, [])

        return(return_code)

    return wraps(fn)(db_wrapper)


def results_message(fn):
    """Return the results in the vFense API standard"""
    def db_wrapper(*args, **kwargs):
        data = fn(*args, **kwargs)
        status_code = data.get(ApiResultKeys.DB_STATUS_CODE, None)
        generic_status_code = data.get(ApiResultKeys.GENERIC_STATUS_CODE, None)
        uri = data.get(ApiResultKeys.URI)
        method = data.get(ApiResultKeys.HTTP_METHOD)
        username = data.get(ApiResultKeys.USERNAME)
        status = None


        if generic_status_code == GenericCodes.InformationRetrieved:
            status = (
                Results(
                    username, uri, method
                ).data_retrieved(**data)
            )

        elif generic_status_code == GenericCodes.ObjectCreated:
            status = (
                Results(
                    username, uri, method
                ).objects_created(**data)
            )

        elif generic_status_code == GenericFailureCodes.FailedToCreateObject:
            status = (
                Results(
                    username, uri, method
                ).objects_failed_to_create(**data)
            )

        elif generic_status_code == GenericCodes.ObjectUpdated:
            status = (
                Results(
                    username, uri, method
                ).objects_updated(**data)
            )

        elif generic_status_code == GenericFailureCodes.FailedToUpdateObject:
            status = (
                Results(
                    username, uri, method
                ).objects_failed_to_update(**data)
            )

        elif generic_status_code == GenericCodes.ObjectDeleted:
            status = (
                Results(
                    username, uri, method
                ).objects_deleted(**data)
            )

        elif generic_status_code == GenericFailureCodes.FailedToDeleteObject:
            status = (
                Results(
                    username, uri, method
                ).objects_failed_to_delete(**data)
            )

        elif generic_status_code == GenericCodes.ObjectUnchanged:
            status = (
                Results(
                    username, uri, method
                ).objects_unchanged(**data)
            )


        elif (
                generic_status_code == GenericCodes.InvalidId or
                generic_status_code == GenericFailureCodes.InvalidId):

            status = (
                Results(
                    username, uri, method
                ).invalid_id(**data)
            )

        elif generic_status_code == GenericCodes.DoesNotExist:
            status = (
                Results(
                    username, uri, method
                ).does_not_exist(**data)
            )


        elif generic_status_code == GenericCodes.ObjectExists:
            status = (
                Results(
                    username, uri, method
                ).does_not_exist(**data)
            )

        elif status_code == DbCodes.Errors:
            status = (
                Results(
                    username, uri, method
                ).something_broke(**data)
            )


        return status

    return wraps(fn)(db_wrapper)


def time_it(fn):
    """Return the status of the db_call, plus the number of documents"""
    def db_wrapper(*args, **kwargs):
        start_time = datetime.now()
        output = fn(*args, **kwargs)
        end_time = datetime.now()
        total_time_to_complete = end_time - start_time
        message = (
            ':%s: took %s seconds to run' %
            (fn.__name__, total_time_to_complete.total_seconds())
        )
        logger.debug(message)

        return(output)

    return wraps(fn)(db_wrapper)


def authenticated_request(method):
    """ Decorator that handles authenticating the request. Uses secure cookies.
    In the spirit of the tornado.web.authenticated decorator.
    """
    @wraps(method)
    def wrapper(self, *args, **kwargs):

        # Get the access token argument. If nothing is provided, string will be
        # "Invalid". Chose this way instead of using "try" and catching
        # HttpError 400 which get_argument throws
        #access_token = str(self.get_argument("access_token", default="Invalid"))

        # Check if an access token is legit.
        # if access_token != "Invalid":
        #     return method(self, *args, **kwargs)

        # If the access token is not provided, assumes is the main ui client.
        if not self.current_user:     
            if self.request.method in ("GET", "HEAD", "POST"):
                url = self.get_login_url()
                # if "?" not in url:
                #     if urlparse.urlsplit(url).scheme:
                #         if login url is absolute, make next absolute too
                        # next_url = {'next': self.request.full_url()}
                    # else:
                    #     next_url = {'next': self.request.uri}
                    # url += "?" + urllib.urlencode(next_url)
                self.redirect(url)
                return
            raise HTTPError(403)

        return method(self, *args, **kwargs)

    return wrapper


def agent_authenticated_request(method):
    """ Decorator that handles authenticating the request. Uses secure cookies.
    In the spirit of the tornado.web.authenticated decorator.
    """
    @wraps(method)
    def wrapper(self, *args, **kwargs):

        # Get the access token argument. If nothing is provided, string will be
        # "Invalid". Chose this way instead of using "try" and catching
        # HttpError 400 which get_argument throws
        #access_token = str(self.get_argument("access_token", default="Invalid"))

        # Check if an access token is legit.
        # if access_token != "Invalid":
        #     return method(self, *args, **kwargs)

        # If the access token is not provided, assumes is the main ui client.
        if not self.current_user:
            raise HTTPError(403)

        return method(self, *args, **kwargs)

    return wrapper

def convert_json_to_arguments(fn):

    @wraps(fn)
    def wrapper(self, *args, **kwargs):

        content_type = self.request.headers.get("Content-Type", "")

        if content_type.startswith("application/json"):
            try:
                self.arguments = json.loads(self.request.body)
            except Exception as e:
                self.arguments = {}

            return fn(self, *args, **kwargs)

        else:

            self.set_status(415)
            self.write("Content-type application/json is expected.")

    return wrapper
