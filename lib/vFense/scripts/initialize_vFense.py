import os
import sys
import time
import re
import pwd
import argparse
import shutil
import signal
import subprocess
from time import sleep
from vFense import (
    VFENSE_BASE_SRC_PATH, VFENSE_BASE_PATH,
    VFENSE_LOG_PATH, VFENSE_CONF_PATH,
    VFENSE_LOGGING_CONFIG, VFENSE_VULN_PATH,
    VFENSE_APP_TMP_PATH, VFENSE_SCHEDULER_PATH,
    VFENSE_TMP_PATH, VFENSED_SYMLINK, VFENSED,
    VFENSE_INIT_D
)
from vFense.core.logger.logger import vFenseLogger
vfense_logger = vFenseLogger()
vfense_logger.create_config()

import logging, logging.config

import create_indexes as ci
import nginx_config_creator as ncc
from vFense import *
from vFense.supported_platforms import *
from vFense.utils.security import generate_pass, check_password
from vFense.utils.ssl_initialize import generate_generic_certs
from vFense.utils.common import pick_valid_ip_address
from vFense.db import DB_NAME
from vFense.db.client import db_connect, r


from vFense.core.user._constants import *
from vFense.core.group._constants import *
from vFense.core.customer import Customer
from vFense.core.customer._constants import *
from vFense.core.permissions._constants import *
import vFense.core.group.groups as group
import vFense.core.customer.customers as customers
import vFense.core.user.users as user

from vFense.plugins import monit
from vFense.plugins.vuln.cve.parser import load_up_all_xml_into_db
from vFense.plugins.vuln.windows.parser import parse_bulletin_and_updatedb
from vFense.plugins.vuln.ubuntu.parser import begin_usn_home_page_processing

logging.config.fileConfig(VFENSE_LOGGING_CONFIG)
logger = logging.getLogger('rvapi')


parser = argparse.ArgumentParser(description='Initialize vFense Options')
parser.add_argument(
    '--dnsname', dest='dns_name', default=None,
    help='Pass the DNS Name of the patching Server'
)
parser.add_argument(
    '--ipaddress', dest='ip_address', default=pick_valid_ip_address(),
    help='Pass the IP Address of the patching Server'
)
parser.add_argument(
    '--password', dest='admin_password', default=generate_pass(),
    help='Pass the password to use for the admin User. Default is a random generated password'
)
parser.add_argument(
    '--listener_count', dest='listener_count', default=10,
    help='The number of vFense_listener daemons to run at once, cannot surpass 40'
)
parser.add_argument(
    '--queue_ttl', dest='queue_ttl', default=10,
    help='How many minutes until an operation for an agent is considered expired in the server queue'
)
parser.add_argument(
    '--web_count', dest='web_count', default=1,
    help='The number of vFense_web daemons to run at once, cannot surpass 40'
)
parser.add_argument(
    '--server_cert', dest='server_cert', default='server.crt',
    help='ssl certificate to use, default is to use server.crt'
)
parser.add_argument(
    '--server_key', dest='server_key', default='server.key',
    help='ssl certificate to use, default is to use server.key'
)
parser.add_argument(
    '--cve-data', dest='cve_data', action='store_true',
    help='Initialize CVE data. This is the default.'
)
parser.add_argument(
    '--no-cve-data', dest='cve_data', action='store_false',
    help='Not to initialize CVE data. This is for testing purposes.'
)
parser.set_defaults(cve_data=True)

args = parser.parse_args()

if args.dns_name:
    url = 'https://%s/packages/' % (args.dns_name)
    nginx_server_name = args.dns_name
else:
    url = 'https://%s/packages/' % (args.ip_address)
    nginx_server_name = args.ip_address

if args.admin_password:
    password_validated = check_password(args.admin_password)
    #if not password_validated[0]:
    #    print (
    #        'Password failed to meet the minimum requirements.\n' +
    #        'Uppercase, Lowercase, Numeric, Special ' +
    #        'and a minimum of 8 characters.\nYour password: %s is %s' %
    #        (args.admin_password, password_validated[1])
    #    )
    #    sys.exit(1)
else:
    args.admin_password = generate_pass()

if args.queue_ttl:
    args.queue_ttl = int(args.queue_ttl)
    if args.queue_ttl < 2:
        args.queue_ttl = 10

def initialise_web_server():
    generate_generic_certs()
    ncc.nginx_config_builder(
        nginx_server_name,
        args.server_cert,
        args.server_key,
        rvlistener_count=int(args.listener_count),
        rvweb_count=int(args.web_count)
    )


def create_folder_structure():
    if not os.path.exists(VFENSED_SYMLINK):
        subprocess.Popen(
            [
                'ln', '-s', VFENSED, VFENSED_SYMLINK
            ],
        )
    os.umask(0)
    if not os.path.exists(VFENSE_TMP_PATH):
        os.mkdir(VFENSE_TMP_PATH, 0755)

    if not os.path.exists(VFENSE_LOG_PATH):
        os.mkdir(VFENSE_LOG_PATH, 0755)
    if not os.path.exists(VFENSE_SCHEDULER_PATH):
        os.mkdir(VFENSE_SCHEDULER_PATH, 0755)
    if not os.path.exists(VFENSE_APP_PATH):
        os.mkdir(VFENSE_APP_PATH, 0755)
    if not os.path.exists(VFENSE_APP_TMP_PATH):
        os.mkdir(VFENSE_APP_TMP_PATH, 0775)
    if not os.path.exists(os.path.join(VFENSE_VULN_PATH, 'windows/data/xls')):
        os.makedirs(os.path.join(VFENSE_VULN_PATH, 'windows/data/xls'), 0755)
    if not os.path.exists(os.path.join(VFENSE_VULN_PATH, 'cve/data/xml')):
        os.makedirs(os.path.join(VFENSE_VULN_PATH,'cve/data/xml'), 0755)
    if not os.path.exists(os.path.join(VFENSE_VULN_PATH, 'ubuntu/data/html')):
        os.makedirs(os.path.join(VFENSE_VULN_PATH, 'ubuntu/data/html'), 0755)

def link_and_start_service():
    if get_distro() in DEBIAN_DISTROS:
        subprocess.Popen(
            [
                'update-rc.d', 'vFense',
                'defaults'
            ],
        )

        if not os.path.exists('/etc/init.d/vFense'):
            subprocess.Popen(
                [
                    'ln', '-s',
                    os.path.join(VFENSE_BASE_SRC_PATH,'daemon/vFense'),
                    VFENSE_INIT_D
                ],
            )

    if os.path.exists(get_sheduler_location()):
        subprocess.Popen(
            [
                'patch', '-N',
                get_sheduler_location(),
                os.path.join(VFENSE_CONF_PATH, 'patches/scheduler.patch')
            ],
        )
    try:
        tp_exists = pwd.getpwnam('vfense')

    except Exception as e:
        if get_distro() in DEBIAN_DISTROS:
            subprocess.Popen(
                [
                    'adduser', '--disabled-password', '--gecos', '--system', 'vfense',
                ],
            )
        elif get_distro() in REDHAT_DISTROS:
            subprocess.Popen(
                [
                    'useradd', 'vfense',
                ],
            )

    rethink_start = subprocess.Popen(['service', 'rethinkdb','start'])
    while not db_connect():
        print 'Sleeping until rethink starts'
        sleep(2)

def initialise_db(conn):
    print "Rethink is running, creating database"
    r.db_create(DB_NAME).run(conn)
    print "Database created successfully, creating tables and indexes"
    ci.create_tables(conn)
    ci.create_indexes(conn)
    print "Database tables created and indexed successfully"

def populate_initial_data(conn):
    print "Beginning database populate"
    default_customer = Customer(
        DefaultCustomers.DEFAULT,
        server_queue_ttl=args.queue_ttl,
        package_download_url=url
    )
    customers.create_customer(default_customer, init=True)
    print "Default customer created"

    group_data = group.get_group_by_name(DefaultGroups.ADMIN, DefaultCustomers.DEFAULT)
    if not group_data:
        group_data = group.create_group(
            DefaultGroups.ADMIN,
            DefaultCustomers.DEFAULT,
            [Permissions.ADMINISTRATOR]
        )
        admin_group_id = group_data['generated_ids']   
    else:
        admin_group_id = group_data['id']
    create_admin_user = user.create_user(
        DefaultUsers.ADMIN,
        'vFense Admin Account',
        args.admin_password,
        admin_group_id,
        DefaultCustomers.DEFAULT,
        '',
    )
    if create_admin_user['http_status'] != 200:
        msg = 'Admin user creation failed with code %d and message "%s"' % (create_admin_user['http_status'], create_admin_user['message'])
        return False, msg
    
    print 'Admin username = admin'
    print 'Admin password = %s' % (args.admin_password)
    agent_pass = generate_pass()
    while not check_password(agent_pass)[0]:
        agent_pass = generate_pass()

    user.create_user(
        DefaultUsers.AGENT,
        'vFense Agent Communication Account',
        agent_pass,
        admin_group_id,
        DefaultCustomers.DEFAULT,
        '',
    )
    print 'Agent api user = agent_api'
    print 'Agent password = %s' % (agent_pass)

    monit.monit_initialization()

    if args.cve_data:
        print "Updating CVE's (this takes a while, be patient!)..."
        cve_start = time.time()
        load_up_all_xml_into_db()
        cve_end = time.time()
        print "Done Updating CVE's (total time: {0} seconds)".format((cve_end - cve_start))
        print "Updating Microsoft Security Bulletin Ids..."
        ms_start = time.time()
        parse_bulletin_and_updatedb()
        ms_end = time.time()
        print "Done Updating Microsoft Security Bulletin Ids (total time: {0} seconds)".format((ms_end - ms_start))
        print "Updating Ubuntu Security Bulletin Ids...( This can take a couple of minutes )"
        ubuntu_start = time.time()
        begin_usn_home_page_processing(full_parse=True)
        ubuntu_end = time.time()
        print "Done Updating Ubuntu Security Bulletin Ids (total time: {0} seconds)".format((ubuntu_end - ubuntu_start))

    print 'Rethink Initialization and Table creation is now complete'

def clean_database(conn):
    r.dbDrop(DB_NAME).run(conn)

if __name__ == '__main__':
    if os.getuid() != 0:
        print 'MUST BE ROOT IN ORDER TO RUN'
        sys.exit(1)

    conn = db_connect()
    if not conn:
        print 'Rethink is not running, start RethinkDB server before attempting to initialise vFense!'
        sys.exit(1)
    
    clean_database(connected)

    create_folder_structure()

    link_and_start_service()

    initialise_web_server()

    initialize_db(conn)

    populate_initial_data(conn)

    if db_initialized:
        print 'vFense environment has been succesfully initialized\n'
        subprocess.Popen(
            [
                'chown', '-R', 'vfense.vfense', VFENSE_BASE_PATH
            ],
        )

    else:
        print 'vFense Failed to initialize, please see messages above for further information'

