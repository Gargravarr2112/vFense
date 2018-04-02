from vFense.errorz._constants import *
from vFense.errorz.status_codes import *



class Results(object):
    def __init__(self, username, uri, method):
        self.uri = uri
        self.method = method
        self.username = username

    def data_retrieved(self, **kwargs):
        msg = (
            kwargs.get(
                ApiResultKeys.MESSAGE,
                '%s - data was retrieved' % (self.username)
            )
        )
        data = kwargs.get(ApiResultKeys.DATA, [])
        count = kwargs.get(ApiResultKeys.COUNT, 0)
        status_code = (
            kwargs.get(
                ApiResultKeys.VFENSE_STATUS_CODE,
                GenericCodes.InformationRetrieved
            )
        )
        return(
            {
                ApiResultKeys.HTTP_STATUS_CODE: 200,
                ApiResultKeys.VFENSE_STATUS_CODE: status_code,
                ApiResultKeys.URI: self.uri,
                ApiResultKeys.HTTP_METHOD: self.method,
                ApiResultKeys.MESSAGE: msg,
                ApiResultKeys.DATA: data,
                ApiResultKeys.COUNT: count
            }
        )

    def objects_created(self, **kwargs):
        generated_ids = kwargs.get(ApiResultKeys.GENERATED_IDS, [])
        unchanged_ids = kwargs.get(ApiResultKeys.UNCHANGED_IDS, [])
        msg = kwargs.get(ApiResultKeys.MESSAGE, '')
        data = kwargs.get(ApiResultKeys.DATA, [])
        status_code = (
            kwargs.get(
                ApiResultKeys.VFENSE_STATUS_CODE,
                GenericCodes.ObjectCreated
            )
        )
        return(
            {
                ApiResultKeys.HTTP_STATUS_CODE: 200,
                ApiResultKeys.VFENSE_STATUS_CODE: status_code,
                ApiResultKeys.URI: self.uri,
                ApiResultKeys.HTTP_METHOD: self.method,
                ApiResultKeys.GENERATED_IDS: generated_ids,
                ApiResultKeys.UNCHANGED_IDS: unchanged_ids,
                ApiResultKeys.MESSAGE: msg,
                ApiResultKeys.DATA: data,
            }
        )


    def objects_failed_to_create(self, **kwargs):
        generated_ids = kwargs.get(ApiResultKeys.GENERATED_IDS, [])
        unchanged_ids = kwargs.get(ApiResultKeys.UNCHANGED_IDS, [])
        msg = kwargs.get(ApiResultKeys.MESSAGE, '')
        data = kwargs.get(ApiResultKeys.DATA, [])
        status_code = (
            kwargs.get(
                ApiResultKeys.VFENSE_STATUS_CODE,
                GenericFailureCodes.FailedToCreateObject
            )
        )
        return(
            {
                ApiResultKeys.HTTP_STATUS_CODE: 409,
                ApiResultKeys.VFENSE_STATUS_CODE: status_code,
                ApiResultKeys.URI: self.uri,
                ApiResultKeys.HTTP_METHOD: self.method,
                ApiResultKeys.GENERATED_IDS: generated_ids,
                ApiResultKeys.UNCHANGED_IDS: unchanged_ids,
                ApiResultKeys.MESSAGE: msg,
                ApiResultKeys.DATA: data,
            }
        )


    def objects_updated(self, **kwargs):
        updated_ids = kwargs.get(ApiResultKeys.UPDATED_IDS, [])
        unchanged_ids = kwargs.get(ApiResultKeys.UNCHANGED_IDS, [])
        msg = kwargs.get(ApiResultKeys.MESSAGE, '')
        data = kwargs.get(ApiResultKeys.DATA, [])
        status_code = (
            kwargs.get(
                ApiResultKeys.VFENSE_STATUS_CODE,
                GenericCodes.ObjectUpdated
            )
        )
        return(
            {
                ApiResultKeys.HTTP_STATUS_CODE: 200,
                ApiResultKeys.VFENSE_STATUS_CODE: status_code,
                ApiResultKeys.URI: self.uri,
                ApiResultKeys.HTTP_METHOD: self.method,
                ApiResultKeys.UPDATED_IDS: updated_ids,
                ApiResultKeys.UNCHANGED_IDS: unchanged_ids,
                ApiResultKeys.MESSAGE: msg,
                ApiResultKeys.DATA: data,
            }
        )


    def objects_failed_to_update(self, **kwargs):
        unchanged_ids = kwargs.get(ApiResultKeys.UNCHANGED_IDS, [])
        msg = kwargs.get(ApiResultKeys.MESSAGE, '')
        data = kwargs.get(ApiResultKeys.DATA, [])
        status_code = (
            kwargs.get(
                ApiResultKeys.VFENSE_STATUS_CODE,
                GenericFailureCodes.FailedToUpdateObject
            )
        )
        return(
            {
                ApiResultKeys.HTTP_STATUS_CODE: 409,
                ApiResultKeys.VFENSE_STATUS_CODE: status_code,
                ApiResultKeys.URI: self.uri,
                ApiResultKeys.HTTP_METHOD: self.method,
                ApiResultKeys.UNCHANGED_IDS: unchanged_ids,
                ApiResultKeys.MESSAGE: msg,
                ApiResultKeys.DATA: data,
            }
        )


    def objects_deleted(self, **kwargs):
        deleted_ids = kwargs.get(ApiResultKeys.DELETED_IDS, [])
        unchanged_ids = kwargs.get(ApiResultKeys.UNCHANGED_IDS, [])
        msg = kwargs.get(ApiResultKeys.MESSAGE, '')
        data = kwargs.get(ApiResultKeys.DATA, [])
        status_code = (
            kwargs.get(
                ApiResultKeys.VFENSE_STATUS_CODE,
                GenericCodes.ObjectDeleted
            )
        )
        return(
            {
                ApiResultKeys.HTTP_STATUS_CODE: 200,
                ApiResultKeys.VFENSE_STATUS_CODE: status_code,
                ApiResultKeys.DELETED_IDS: deleted_ids,
                ApiResultKeys.UNCHANGED_IDS: unchanged_ids,
                ApiResultKeys.URI: self.uri,
                ApiResultKeys.HTTP_METHOD: self.method,
                ApiResultKeys.MESSAGE: msg,
                ApiResultKeys.DATA: data,
            }
       )


    def objects_failed_to_delete(self, **kwargs):
        unchanged_ids = kwargs.get(ApiResultKeys.UNCHANGED_IDS, [])
        msg = kwargs.get(ApiResultKeys.MESSAGE, '')
        data = kwargs.get(ApiResultKeys.DATA, [])
        status_code = (
            kwargs.get(
                ApiResultKeys.VFENSE_STATUS_CODE,
                GenericFailureCodes.FailedToDeleteObject
            )
        )
        return(
            {
                ApiResultKeys.HTTP_STATUS_CODE: 409,
                ApiResultKeys.VFENSE_STATUS_CODE: status_code,
                ApiResultKeys.URI: self.uri,
                ApiResultKeys.HTTP_METHOD: self.method,
                ApiResultKeys.UNCHANGED_IDS: unchanged_ids,
                ApiResultKeys.MESSAGE: msg,
                ApiResultKeys.DATA: data,
            }
        )


    def invalid_id(self, **kwargs):
        invalid_id = kwargs.get(ApiResultKeys.INVALID_ID, '')
        msg = kwargs.get(ApiResultKeys.MESSAGE, '')
        status_code = (
            kwargs.get(
                ApiResultKeys.VFENSE_STATUS_CODE,
                GenericCodes.InvalidId
            )
        )
        data = kwargs.get(ApiResultKeys.DATA, [])
        return(
            {
                ApiResultKeys.HTTP_STATUS_CODE: 404,
                ApiResultKeys.VFENSE_STATUS_CODE: status_code,
                ApiResultKeys.INVALID_ID: invalid_id,
                ApiResultKeys.URI: self.uri,
                ApiResultKeys.HTTP_METHOD: self.method,
                ApiResultKeys.MESSAGE: msg,
                ApiResultKeys.DATA: data,
            }
       )


    def does_not_exist(self, **kwargs):
        msg = kwargs.get(ApiResultKeys.MESSAGE, '')
        status_code = (
            kwargs.get(
                ApiResultKeys.VFENSE_STATUS_CODE,
                GenericCodes.DoesNotExist
            )
        )
        return(
            {
                ApiResultKeys.HTTP_STATUS_CODE: 409,
                ApiResultKeys.VFENSE_STATUS_CODE: status_code,
                ApiResultKeys.URI: self.uri,
                ApiResultKeys.HTTP_METHOD: self.method,
                ApiResultKeys.MESSAGE: msg,
            }
        )


    def objects_unchanged(self, **kwargs):
        unchanged_ids = kwargs.get(ApiResultKeys.UNCHANGED_IDS, [])
        msg = kwargs.get(ApiResultKeys.MESSAGE, '')
        data = kwargs.get(ApiResultKeys.DATA, [])
        status_code = (
            kwargs.get(
                ApiResultKeys.VFENSE_STATUS_CODE,
                GenericCodes.ObjectUnchanged
            )
        )
        return(
            {
                ApiResultKeys.HTTP_STATUS_CODE: 200,
                ApiResultKeys.VFENSE_STATUS_CODE: status_code,
                ApiResultKeys.URI: self.uri,
                ApiResultKeys.HTTP_METHOD: self.method,
                ApiResultKeys.UNCHANGED_IDS: unchanged_ids,
                ApiResultKeys.MESSAGE: msg,
                ApiResultKeys.DATA: data,
            }
        )


    def something_broke(self, **kwargs):
        msg = kwargs.get(ApiResultKeys.MESSAGE, '')
        data = kwargs.get(ApiResultKeys.DATA, [])
        status_code = (
            kwargs.get(
                ApiResultKeys.VFENSE_STATUS_CODE,
                GenericCodes.SomethingBroke
            )
        )
        return(
            {
                ApiResultKeys.HTTP_STATUS_CODE: 500,
                ApiResultKeys.VFENSE_STATUS_CODE: status_code,
                ApiResultKeys.URI: self.uri,
                ApiResultKeys.HTTP_METHOD: self.method,
                ApiResultKeys.MESSAGE: msg,
                ApiResultKeys.DATA: data,
            }
        )

    def object_exists(self, **kwargs):
        msg = kwargs.get(ApiResultKeys.MESSAGE, '')
        data = kwargs.get(ApiResultKeys.DATA, [])
        status_code = (
            kwargs.get(
                ApiResultKeys.VFENSE_STATUS_CODE,
                GenericCodes.ObjectExists
            )
        )
        return(
            {
                ApiResultKeys.HTTP_STATUS_CODE: 200,
                ApiResultKeys.VFENSE_STATUS_CODE: status_code,
                ApiResultKeys.URI: self.uri,
                ApiResultKeys.HTTP_METHOD: self.method,
                ApiResultKeys.UNCHANGED_IDS: object_id,
                ApiResultKeys.MESSAGE: msg,
                ApiResultKeys.DATA: data,
            }
        )

