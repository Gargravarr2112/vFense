from vFense.tunnels import ssh
from vFense.plugins.remote_assistance import RaKeys


def startup(agent_id, json_operation):

    if RaKeys.PublicKey in json_operation:

        ssh.create_ssh_dir()
        ssh.add_authorized_key(agent_id, json_operation[RaKeys.PublicKey])


def new_agent(agent_id, json_operation):

    if RaKeys.PublicKey in json_operation:

        ssh.create_ssh_dir()
        ssh.add_authorized_key(agent_id, json_operation[RaKeys.PublicKey])
