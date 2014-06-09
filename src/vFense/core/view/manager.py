from vFense.core.view import View
from vFense.core.view._constants import DefaultViews
from vFense.core.view._db_model import ViewKeys
from vFense.core.user._db import (
    update_views_for_users, fetch_usernames, delete_users_from_view
)
from vFense.core.group._db import (
    fetch_group_ids_for_view, delete_groups_from_view
)
from vFense.core.view._db import (
    fetch_view, insert_view, update_children_for_view, delete_view,
    delete_users_in_view, update_view
)
from vFense.core.decorators import time_it
from vFense.errorz._constants import ApiResultKeys

from vFense.errorz.status_codes import (
    DbCodes, ViewCodes, GenericCodes,
    GenericFailureCodes, ViewFailureCodes
)

class ViewManager(object):
    def __init__(self, name):
        self.name = name
        self.users = []
        self.groups = []
        self.properties = self._view_properties()
        if self.properties:
            self.users = self.properties[ViewKeys.Users]
            self.groups = fetch_group_ids_for_view(self.name)

    def _view_properties(self):
        """Retrieve view information.
        Basic Usage:
            >>> from vFense.view.manager import ViewManager
            >>> view_name = 'default'
            >>> view = ViewManager(view_name)
            >>> view._view_properties()

        Returns:
            Dictionary of view properties.
            {
                u'cpu_throttle': u'normal',
                u'package_download_url_base': u'http: //10.0.0.21/packages/',
                u'operation_ttl': 10,
                u'net_throttle': 0,
                u'view_name': u'default'
            }
        """
        view_data = fetch_view(self.name)

        return view_data

    @time_it
    def create(self, view):
        """Create a new view inside of vFense

        Args:
            view (View): A view instance filled out with the
                appropriate fields.

        Kwargs:
            username (str): Name of the user that you are adding to this view.
                Default=None

        Basic Usage:
            >>> from vFense.core.view import View
            >>> from vFense.core.view.manager import ViewManager
            >>> view = View(
                'global'
                package_download_url='https://10.0.0.15/packages/'
            )
            >>> manager = ViewManager(view.name)
            >>> manager.create(view)

        Returns:
            Dictionary of the status of the operation.
            >>>
            {
                "data": [
                    {
                        "server_queue_ttl": 10,
                        "cpu_throttle": "normal",
                        "view_name": "global",
                        "ancestors": [],
                        "package_download_url_base": "https://10.0.0.15/packages/",
                        "agent_queue_ttl": 10,
                        "parent": null,
                        "net_throttle": 0,
                        "children": [],
                        "users": []
                    }
                ],
                "message": "create - view global created - ",
                "errors": [],
                "vfense_status_code": 14000,
                "generic_status_code": 1010
            }
        """
        view_exist = self.properties
        msg = ''
        results = {}
        invalid_fields = view.get_invalid_fields()
        results[ApiResultKeys.ERRORS] = invalid_fields

        if not invalid_fields and not view_exist:
            # Fill in any empty fields
            view.fill_in_defaults()
            parent_view = {}
            if view.name == DefaultViews.GLOBAL:
                view.parent = None
                view.ancestors = []
                view.children = []

            else:
                if not view.parent:
                    view.parent = DefaultViews.GLOBAL
                    view.ancestors = [view.parent]
                    parent_view = fetch_view(view.parent)

                else:
                    parent_view = fetch_view(view.parent)
                    if parent_view:
                        parent_view[ViewKeys.Children].append(view.name)
                        view.ancestors = parent_view[ViewKeys.Ancestors]
                        view.ancestors.append(view.parent)

            if not view.package_download_url:
                view.package_download_url = (
                    fetch_view(
                        DefaultViews.GLOBAL,
                        [ViewKeys.PackageUrl]
                    ).get(ViewKeys.PackageUrl)
                )

            usernames = list(set(fetch_usernames(True) + view.users))
            view.users = usernames
            object_status, _, _, generated_ids = (
                insert_view(view.to_dict())
            )

            if object_status == DbCodes.Inserted:
                generated_ids.append(view.name)
                msg = 'view %s created - ' % (view.name)
                results[ApiResultKeys.GENERIC_STATUS_CODE] = (
                    GenericCodes.ObjectCreated
                )
                results[ApiResultKeys.VFENSE_STATUS_CODE] = (
                    ViewCodes.ViewCreated
                )
                results[ApiResultKeys.MESSAGE] = msg
                results[ApiResultKeys.DATA] = [view.to_dict()]

                if usernames:
                    update_views_for_users(
                        usernames, [view.name]
                    )
                print parent_view, 'foo bar'
                if parent_view:
                    update_children_for_view(
                        parent_view[ViewKeys.ViewName], view.name
                    )

        elif view_exist:
            msg = 'view name %s already exists' % (view.name)
            results[ApiResultKeys.GENERIC_STATUS_CODE] = (
                GenericCodes.ObjectExists
            )
            results[ApiResultKeys.VFENSE_STATUS_CODE] = (
                ViewFailureCodes.ViewExists
            )
            results[ApiResultKeys.MESSAGE] = msg

        return results


    @time_it
    def remove(self, force=False):
        """Create a new view inside of vFense

        Kwargs:
            force (boolean): Forcefully remove a view, even if users
                and groups exist.
                default=False

        Basic Usage:
            >>> from vFense.core.view.manager import ViewManager
            >>> view = View('global')
            >>> manager = ViewManager(view.name)
            >>> manager.remove(view)

        Returns:
            Dictionary of the status of the operation.
            >>>
        """
        view_exist = self.properties
        msg = ''
        results = {}

        if view_exist:
            if not self.users and not self.groups and not force or force:
                object_status, _, _, generated_ids = (
                    delete_view(self.name)
                )

                if object_status == DbCodes.Deleted:
                    if force:
                        delete_users_from_view(self.name)
                        delete_groups_from_view(self.name)
                        text = (
                            'View {view_name} deleted' +
                            'and all users: {users} and groups: {groups}' +
                            'were deleted'
                        )
                        msg = text.format(
                            **{
                                'view_name': self.name,
                                'users': self.users,
                                'groups': self.groups
                            }
                        )
                    else:
                        msg = 'View %s deleted - ' % (self.name)

                    results[ApiResultKeys.GENERIC_STATUS_CODE] = (
                        GenericCodes.ObjectDeleted
                    )
                    results[ApiResultKeys.VFENSE_STATUS_CODE] = (
                        ViewCodes.ViewDeleted
                    )
                    results[ApiResultKeys.MESSAGE] = msg
                    results[ApiResultKeys.DELETED_IDS] = [self.name]

            else:
                msg = (
                    'Can not remove view %s, while users: %s'+'exist in view: %s'
                    % (self.name, users)
                )
                results[ApiResultKeys.GENERIC_STATUS_CODE] = (
                    GenericCodes.ObjectUnchanged
                )
                results[ApiResultKeys.VFENSE_STATUS_CODE] = (
                    ViewFailureCodes.UsersExistForView
                )
                results[ApiResultKeys.MESSAGE] = msg
                results[ApiResultKeys.UNCHANGED_IDS] = [self.name]

        else:
            msg = 'View %s does not exists' % (self.name)
            results[ApiResultKeys.GENERIC_STATUS_CODE] = (
                GenericCodes.ObjectExists
            )
            results[ApiResultKeys.VFENSE_STATUS_CODE] = (
                ViewFailureCodes.ViewExists
            )
            results[ApiResultKeys.MESSAGE] = msg

        return results


    def edit_net_throttle(self, throttle):
        """Edit how much traffic the agent will use while downloading
            applications from vFense.

        Args:
            throttle (int): The number in kilobytes you want to throttle
                the download from the agent.

        Basic Usage:
            >>> from vFense.view.manager import ViewManager
            >>> manager = ViewManager("global")
            >>> manager.edit_net_throttle(100)

        Returns:
            Returns the results in a dictionary
        """
        view = View(self.name, net_throttle=throttle)
        results = self.__edit_properties(view)

        return results


    def edit_cpu_throttle(self, throttle):
        """Change how much CPU will be used while installing an application.

        Args:
            throttle (str): How much cpu the agent should use while
                installing an application. Valid throttle values..
                ("idle", "below_normal", "normal", "above_normal", "high")

        Basic Usage:
            >>> from vFense.view.manager import ViewManager
            >>> manager = ViewManager("global")
            >>> manager.edit_cpu_throttle("normal")

        Returns:
            Returns the results in a dictionary
        """
        view = View(self.name, cpu_throttle=throttle)
        results = self.__edit_properties(view)

        return results


    def edit_server_queue_ttl(self, ttl):
        """Change how long until an operation is considered expired
            on the vFense server.

        Args:
            ttl (int): Number of minutes until an operation is
                considered expired on the server.

        Basic Usage:
            >>> from vFense.view.manager import ViewManager
            >>> manager = ViewManager("global")
            >>> manager.edit_server_queue_ttl(10)

        Returns:
            Returns the results in a dictionary
        """
        view = View(self.name, server_queue_ttl=ttl)
        results = self.__edit_properties(view)

        return results


    def edit_agent_queue_ttl(self, ttl):
        """Change how long until an operation is considered expired
            on the vFense agent.

        Args:
            ttl (int): Number of minutes until an operation is
                considered expired on the agent.

        Basic Usage:
            >>> from vFense.view.manager import ViewManager
            >>> manager = ViewManager("global")
            >>> manager.edit_agent_queue_ttl(10)

        Returns:
            Returns the results in a dictionary
        """
        view = View(self.name, agent_queue_ttl=ttl)
        results = self.__edit_properties(view)

        return results


    def edit_download_url(self, url):
        """Change the url that the agent will use when downloadling
            applications from the vFense server.

        Args:
            url (str): The url that the agent will use while downloading
                from the vFense server. (https://ip_address/packages/"

        Basic Usage:
            >>> from vFense.view.manager import ViewManager
            >>> manager = ViewManager("global")
            >>> manager.edit_download_url("https://10.0.0.100/packages/")

        Returns:
            Returns the results in a dictionary
        """
        view = View(self.name, package_download_url=url)
        results = self.__edit_properties(view)

        return results


    def __edit_properties(self, view):
        """Edit the properties of a view.
        Args:
            view_data (dict): The fields you want to update.

        Basic Usage:
            >>> from vFense.view import View
            >>> from vFense.view.manager import ViewManager
            >>> view_name = 'global'
            >>> view = View(view_name, net_throttle=100)
            >>> manager = ViewManager(view.name)
            >>> manager.__edit_properties(view)

        Returns:
            Returns the results in a dictionary
        """
        view_exist = self.properties
        results = {}
        if view_exist:
            if isinstance(view, View):
                invalid_fields = view.get_invalid_fields()
                view_data = view.to_dict_non_null()
                view_data.pop(ViewKeys.ViewName, None)
                if not invalid_fields:
                    status_code, _, _, _ = (
                        update_view(self.name, view_data)
                    )
                    if status_code == DbCodes.Replaced:
                        msg = (
                            'view %s updated with data: %s'
                            % (self.name, view_data)
                        )
                        results[ApiResultKeys.MESSAGE] = msg
                        results[ApiResultKeys.GENERIC_STATUS_CODE] = (
                            GenericCodes.ObjectUpdated
                        )
                        results[ApiResultKeys.VFENSE_STATUS_CODE] = (
                            ViewCodes.ViewUpdated
                        )
                        results[ApiResultKeys.UPDATED_IDS] = [self.name]

                    if status_code == DbCodes.Unchanged:
                        msg = (
                            'View data: %s is the same as the previous values'
                            % (view_data)
                        )
                        results[ApiResultKeys.MESSAGE] = msg
                        results[ApiResultKeys.GENERIC_STATUS_CODE] = (
                            GenericCodes.ObjectUnchanged
                        )
                        results[ApiResultKeys.VFENSE_STATUS_CODE] = (
                            ViewCodes.ViewUnchanged
                        )
                        results[ApiResultKeys.UNCHANGED_IDS] = [self.name]

                else:
                    msg = (
                        'View data: %s contains invalid_data'
                        % (self.name)
                    )
                    results[ApiResultKeys.MESSAGE] = msg
                    results[ApiResultKeys.GENERIC_STATUS_CODE] = (
                        GenericCodes.ObjectUnchanged
                    )
                    results[ApiResultKeys.VFENSE_STATUS_CODE] = (
                        ViewFailureCodes.InvalidFields
                    )
                    results[ApiResultKeys.UNCHANGED_IDS] = [self.name]
                    results[ApiResultKeys.ERRORS] = invalid_fields

            else:
                msg = (
                    'Argument must be an instance of View and not %s'
                    % (type(view))
                )
                results[ApiResultKeys.MESSAGE] = msg
                results[ApiResultKeys.GENERIC_STATUS_CODE] = (
                    GenericCodes.InvalidValue
                )
                results[ApiResultKeys.VFENSE_STATUS_CODE] = (
                    ViewFailureCodes.InvalidValue
                )
                results[ApiResultKeys.UNCHANGED_IDS] = [self.name]

        else:
            msg = 'view %s does not exist' % (self.name)
            results[ApiResultKeys.GENERIC_STATUS_CODE] = (
                GenericCodes.ObjectUnchanged
            )
            results[ApiResultKeys.VFENSE_STATUS_CODE] = (
                ViewCodes.ViewUnchanged
            )
            results[ApiResultKeys.MESSAGE] = msg
            results[ApiResultKeys.UNCHANGED_IDS] = [self.name]
            results[ApiResultKeys.INVALID_IDS] = [self.name]

        return results