import os
import socket
import logging, logging.config
from vFense import VFENSE_LOGGING_CONFIG
from OpenSSL import crypto
from vFense.utils._constants import SSLConstants

DUMP_PKEY = crypto.dump_privatekey
DUMP_CERT = crypto.dump_certificate
DUMP_CERT_REQUEST = crypto.dump_certificate_request
LOAD_PKEY = crypto.load_privatekey
LOAD_CERT = crypto.load_certificate
LOAD_CERT_REQUEST = crypto.load_certificate_request


logging.config.fileConfig(VFENSE_LOGGING_CONFIG)
logger = logging.getLogger('rvapi')

def load_private_key(privkey=SSLConstants.PRIV_KEY):
    pkey = LOAD_PKEY(SSLConstants.PEM, open(privkey, 'rb').read())
    return pkey


def load_cert(cert=SSLConstants.CERT_KEY):
    signed_cert = LOAD_CERT(SSLConstants.PEM, open(cert, 'rb').read())
    return signed_cert


def dump_pkey(pkey):
    pem_key = DUMP_PKEY(SSLConstants.PEM, pkey)
    return pem_key


def dump_cert(cert):
    pem_cert = DUMP_CERT(SSLConstants.PEM, cert)
    return pem_cert


def load_cert_request(csr):
    cert_request = LOAD_CERT_REQUEST(SSLConstants.PEM, csr)
    return cert_request


def generate_private_key(type, bits):
    pkey = crypto.PKey()
    pkey.generate_key(type, bits)
    return pkey


def save_key(location, key, key_type, name=socket.gethostname()):
    extension = SSLConstants.EXTENSION[key_type]
    name = name + extension
    path_to_key = os.path.join(location, name)
    status = False
    if type(key) == crypto.PKeyType:
        DUMP_KEY = DUMP_PKEY
    elif type(key) == crypto.X509Type:
        DUMP_KEY = DUMP_CERT
    elif type(key) == crypto.X509ReqType:
        DUMP_KEY = DUMP_CERT_REQUEST
    try:
        os.stat(location)
    except OSError as e:
        if e.errno == 2:
            logger.error('%s - ssl directory %s does not exists' %\
                    ('system_user', location)
                    )
        elif e.errno == 13:
            logger.error('%s - Do not have permission to write to %s' %\
                    ('system_user', location)
                    )
    try:
        file_exists = os.stat(path_to_key)
        if file_exists:
            logger.warn('%s - File %s already exists' %\
                    ('system_user', path_to_key))
    except OSError as e:
        if e.errno == 2:
            open(path_to_key, 'w').write(\
                    DUMP_KEY(SSLConstants.PEM, key)
                    )
            status = True
            logger.error('%s - Writing ssl cert to %s ' %\
                    ('system_user', location)
                    )
        elif e.errno == 13:
            logger.error('%s - Do not have permission to write to %s' %\
                    ('system_user', location)
                    )
    return(path_to_key, name, status)


def create_cert_request(pkey, (CN, O, OU, C, ST, L), digest="sha512"):
    csr = crypto.X509Req()
    csr.set_version(3)
    subj = csr.get_subject()
    subj.CN=CN
    subj.O=O
    subj.OU=OU
    subj.C=C
    subj.ST=ST
    subj.L=L
    csr.set_pubkey(pkey)
    csr.sign(pkey, digest)
    return csr


def create_certificate(cert, (issuerCert, issuerKey), serial,\
        (notBefore, notAfter), digest="sha512"):
    cert = crypto.X509()
    cert.set_version(3)
    cert.set_serial_number(serial)
    cert.gmtime_adj_notBefore(notBefore)
    cert.gmtime_adj_notAfter(notAfter)
    cert.set_issuer(issuerCert.get_subject())
    cert.sign(issuerKey, digest)
    return cert


def create_signed_certificate(csr, issuerKey, serial, (notBefore, notAfter), digest="sha512"):
    cert = crypto.X509()
    cert.set_version(3)
    cert.set_serial_number(serial)
    cert.gmtime_adj_notBefore(notBefore)
    cert.gmtime_adj_notAfter(notAfter)
    cert.set_subject(csr.get_subject())
    cert.set_pubkey(csr.get_pubkey())
    cert.sign(issuerKey, digest)
    return cert


def create_signing_certificate_authority(pkey, serial,\
        (CN, O, OU, C, ST, L),
        (notBefore, notAfter),
        digest=SSLConstants.SHA512):
    ca = crypto.X509()
    ca.set_version(3)
    subj = ca.get_subject()
    subj.CN=CN
    subj.O=O
    subj.OU=OU
    subj.C=C
    subj.ST=ST
    subj.L=L
    ca.set_serial_number(serial)
    ca.gmtime_adj_notBefore(notBefore)
    ca.gmtime_adj_notAfter(notAfter)
    ca.set_issuer(ca.get_subject())
    ca.set_pubkey(pkey)
    ca.sign(pkey, digest)
    return ca


def verify_valid_format(data, ssl_type):
    verified = True
    error = None
    if ssl_type == SSLConstants.TYPE_CSR:
        try:
            LOAD_CERT_REQUEST(SSLConstants.PEM, data)
        except Exception as e:
            error =  'INVALID CSR'
            verified = False
    if ssl_type == SSLConstants.TYPE_CERT:
        try:
            LOAD_CERT(SSLConstants.PEM, data)
        except Exception as e:
            error =  'INVALID CERT'
            verified = False
    if ssl_type == SSLConstants.TYPE_PKEY:
        try:
            LOAD_PKEY(SSLConstants.PEM, data)
        except Exception as e:
            error =  'INVALID PKEY'
            verified = False
    return(verified, error)
