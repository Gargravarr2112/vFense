import os
from vFense.core._constants import HTTPMethods, CommonKeys
from vFense.operations._constants import AgentOperations, ListenerURIs, \
    AuthenticationOperations, AuthenticationURIs, BaseURIs

from vFense.core.agent import AgentKeys
from vFense.core.agent.agents import get_agent_info
from vFense.core.decorators import results_message, time_it
from vFense.errorz._constants import ApiResultKeys
from vFense.errorz.status_codes import *


def _get_result_uris_dict(agent_id):
    base = os.path.join(BaseURIs.LISTENER, agent_id)

    result_uris = {
        AuthenticationOperations.LOGIN: {
            CommonKeys.RESPONSE_URI: AuthenticationURIs.LOGIN,
            CommonKeys.REQUEST_METHOD: HTTPMethods.POST
        },
        AuthenticationOperations.LOGOUT: {
            CommonKeys.RESPONSE_URI: AuthenticationURIs.LOGOUT,
            CommonKeys.REQUEST_METHOD: HTTPMethods.GET
        },
        AgentOperations.NEW_AGENT: {
            CommonKeys.RESPONSE_URI: os.path.join(
                BaseURIs.LISTENER, ListenerURIs.NEWAGENT
            ),
            CommonKeys.REQUEST_METHOD: HTTPMethods.POST
        },
        AgentOperations.RA: {
            CommonKeys.RESPONSE_URI: os.path.join(
                BaseURIs.LISTENER, ListenerURIs.RA
            ),
            CommonKeys.REQUEST_METHOD: HTTPMethods.POST
        },
        AgentOperations.REFRESH_APPS: {
            CommonKeys.RESPONSE_URI: os.path.join(
                base, ListenerURIs.REFRESH_APPS
            ),
            CommonKeys.REQUEST_METHOD: HTTPMethods.PUT
        },
        AgentOperations.AVAILABLE_AGENT_UPDATE: {
            CommonKeys.RESPONSE_URI: os.path.join(
                base, ListenerURIs.AVAILABLE_AGENT_UPDATE
            ),
            CommonKeys.REQUEST_METHOD: HTTPMethods.PUT
        },
        AgentOperations.CHECK_IN: {
            CommonKeys.RESPONSE_URI: os.path.join(
                base, ListenerURIs.CHECK_IN
            ),
            CommonKeys.REQUEST_METHOD: HTTPMethods.GET
        },
        AgentOperations.MONITOR_DATA: {
            CommonKeys.RESPONSE_URI: os.path.join(
                base, ListenerURIs.MONITOR_DATA
            ),
            CommonKeys.REQUEST_METHOD: HTTPMethods.POST
        },
        AgentOperations.START_UP: {
            CommonKeys.RESPONSE_URI: os.path.join(
                base, ListenerURIs.START_UP
            ),
            CommonKeys.REQUEST_METHOD: HTTPMethods.PUT
        },
        AgentOperations.REBOOT: {
            CommonKeys.RESPONSE_URI: os.path.join(
                base, ListenerURIs.REBOOT
            ),
            CommonKeys.REQUEST_METHOD: HTTPMethods.PUT
        },
        AgentOperations.SHUTDOWN: {
            CommonKeys.RESPONSE_URI: os.path.join(
                base, ListenerURIs.SHUTDOWN
            ),
            CommonKeys.REQUEST_METHOD: HTTPMethods.PUT
        },
        AgentOperations.INSTALL_OS_APPS: {
            CommonKeys.RESPONSE_URI: os.path.join(
                base, ListenerURIs.INSTALL_OS_APPS
            ),
            CommonKeys.REQUEST_METHOD: HTTPMethods.PUT
        },
        AgentOperations.INSTALL_CUSTOM_APPS: {
            CommonKeys.RESPONSE_URI: os.path.join(
                base, ListenerURIs.INSTALL_CUSTOM_APPS
            ),
            CommonKeys.REQUEST_METHOD: HTTPMethods.PUT
        },
        AgentOperations.INSTALL_SUPPORTED_APPS: {
            CommonKeys.RESPONSE_URI: os.path.join(
                base, ListenerURIs.INSTALL_SUPPORTED_APPS
            ),
            CommonKeys.REQUEST_METHOD: HTTPMethods.PUT
        },
        AgentOperations.INSTALL_AGENT_UPDATE: {
            CommonKeys.RESPONSE_URI: os.path.join(
                base, ListenerURIs.INSTALL_AGENT_UPDATE
            ),
            CommonKeys.REQUEST_METHOD: HTTPMethods.PUT
        },
        AgentOperations.UNINSTALL: {
            CommonKeys.RESPONSE_URI: os.path.join(
                base, ListenerURIs.UNINSTALL
            ),
            CommonKeys.REQUEST_METHOD: HTTPMethods.PUT
        },
        AgentOperations.UNINSTALL_AGENT: {
            CommonKeys.RESPONSE_URI: os.path.join(
                base, ListenerURIs.UNINSTALL_AGENT
            ),
            CommonKeys.REQUEST_METHOD: HTTPMethods.PUT
        }
    }

    return result_uris


@time_it
def get_agent_results_uri(agent_id, operation):
    """Return back the http method and response uri for an operation.
    Args:
        agent_id (str): 36 character UUID
        operation (str): valid vFense operation.

    Basic Usage:
        >>> from vFense.receiver.agent_uris import get_agent_results_uri
        >>> agent_id = 'd4119b36-fe3c-4973-84c7-e8e3d72a3e02'
        >>> operation = 'install_os_apps'
        >>> get_agent_results_uri(agent_id, operation)

    Returns:
        Tuple
        ('PUT', 'rvl/v1/d4119b36-fe3c-4973-84c7-e8e3d72a3e02/core/results/reboot')

    """

    result_uri_dict = _get_result_uris_dict(agent_id).get(operation, {})

    if result_uri_dict:
        return (
            result_uri_dict[CommonKeys.RESPONSE_URI],
            result_uri_dict[CommonKeys.REQUEST_METHOD]
        )

    return ('', '')



@time_it
@results_message
def get_result_uris(agent_id, user_name=None, uri=None, method=None):
    """Returns back a dictionary with all of the agent api calls for an agent.
    Args:
        agent_id (str): 36 character UUID

    Kwargs:
        user_name (str): The name of the user who called this function.
        uri (str): The uri that was used to call this function.
        method (str): The HTTP methos that was used to call this function.

    Basic Usage:
        >>> from vFense.receiver.agent_uris import get_result_uris
        >>> agent_id = 'd4119b36-fe3c-4973-84c7-e8e3d72a3e02'
        >>> get_result_uris(agent_id)

    Returns:
        Dictionary
        {
            "count": 1,
            "uri": null,
            "rv_status_code": 1001,
            "http_method": null,
            "http_status": 200,
            "message": "None - data was retrieved",
            "data": {
                "check_in": {
                    "response_uri": "rvl/v1/d4119b36-fe3c-4973-84c7-e8e3d72a3e02/core/checkin",
                    "request_method": "GET"
                },  
                "startup": {
                    "response_uri": "rvl/v1/d4119b36-fe3c-4973-84c7-e8e3d72a3e02/core/results/startup",
                    "request_method": "PUT"
                },
                "shutdown": {
                    "response_uri": "rvl/v1/d4119b36-fe3c-4973-84c7-e8e3d72a3e02/core/results/shutdown",
                    "request_method": "PUT"
                },
            }
        }
    """
    status_code = 0
    status = get_result_uris.func_name + ' - '
    result_uris = _get_result_uris_dict(agent_id)

    agent_exist = get_agent_info(agent_id, AgentKeys.AgentId)
    if agent_exist:
        generic_status_code = GenericCodes.InformationRetrieved
        vfense_status_code = GenericCodes.InformationRetrieved
        msg = 'response uris retrieved successfully for agent_id %s' % \
              (agent_id)
        count = 1

    else:
        generic_status_code = GenericCodes.InvalidId
        vfense_status_code = AgentFailureCodes.AgentsDoesNotExist
        result_uris = {}
        msg = 'invalid agent_id %s' % (agent_id)
        count = 0

    results = {
        ApiResultKeys.DB_STATUS_CODE: status_code,
        ApiResultKeys.GENERIC_STATUS_CODE: generic_status_code,
        ApiResultKeys.VFENSE_STATUS_CODE: vfense_status_code,
        ApiResultKeys.MESSAGE: status + msg,
        ApiResultKeys.COUNT: count,
        ApiResultKeys.DATA: result_uris,
        ApiResultKeys.USERNAME: user_name,
        ApiResultKeys.URI: uri,
        ApiResultKeys.HTTP_METHOD: method
    }

    return(results)
