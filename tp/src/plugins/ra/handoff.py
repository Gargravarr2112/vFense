from vFense.tunnels import ssh
from vFense.plugins import ra


def startup(agent_id, json_operation):

    if ra.RaKeys.PublicKey in json_operation:

        ssh.create_ssh_dir()
        ssh.add_authorized_key(agent_id, json_operation[ra.RaKeys.PublicKey])


def new_agent(agent_id, json_operation):

    if ra.RaKeys.PublicKey in json_operation:

        ssh.create_ssh_dir()
        ssh.add_authorized_key(agent_id, json_operation[ra.RaKeys.PublicKey])
