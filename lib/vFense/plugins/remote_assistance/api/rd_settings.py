import json

from vFense.core.api.base import BaseHandler

from vFense.plugins import remote_assistance
from vFense.plugins.remote_assistance._db import save_rd_password


class RDPassword(BaseHandler):

    def post(self, agent_id=None):

        current_user = self.get_current_user()
        body = json.loads(self.request.body)
        password = body.get('password')

        results = save_rd_password(
            password=password,
            user=current_user
        )

        self.set_header('Content-Type', 'application/json')
        self.write(json.dumps(results, indent=4))
