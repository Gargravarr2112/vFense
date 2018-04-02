import json

from vFense.core.api.base import BaseHandler
from vFense.core.permissions._constants import *
from vFense.core.permissions.decorators import check_permissions, authenticated_request

from vFense.plugins import remote_assistance
from vFense.plugins.remote_assistance import creator


class RDSession(BaseHandler):

    @authenticated_request
    @check_permissions(Permissions.REMOTE_ASSISTANCE)
    def post(self):

        current_user = self.get_current_user()
        body = json.loads(self.request.body)
        agent_id = body.get('agent_id')

        results = creator.new_rd_session(
            agent_id=agent_id,
            user=current_user
        )

        self.set_header('Content-Type', 'application/json')
        self.write(json.dumps(results, indent=4))

    @authenticated_request
    @check_permissions(Permissions.REMOTE_ASSISTANCE)
    def delete(self):

        current_user = self.get_current_user()
        body = json.loads(self.request.body)
        agent_id = body.get('agent_id')

        results = creator.terminate_rd_session(
            agent_id=agent_id,
            user=current_user
        )

        self.set_header('Content-Type', 'application/json')
        self.write(json.dumps(results, indent=4))
