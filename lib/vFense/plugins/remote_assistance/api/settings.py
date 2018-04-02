import json

from vFense.core.api.base import BaseHandler

from vFense.core.user import UserKeys
from vFense.core.user.users import get_user_property

from vFense.plugins.remote_assistance._db import save_rd_password


class SetPassword(BaseHandler):

    def post(self):

        current_user = self.get_current_user()
        customer_name = (
            get_user_property(current_user, UserKeys.CurrentCustomer)
        )
        body = json.loads(self.request.body)
        password = body.get('password')

        results = save_rd_password(
            password=password,
            user=current_user,
            customer=current_customer
        )

        self.set_header('Content-Type', 'application/json')
        self.write(json.dumps(results, indent=4))
