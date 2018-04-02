import os
from OpenSSL.crypto import TYPE_RSA, TYPE_DSA, FILETYPE_PEM
from vFense import VFENSE_SSL_PATH

class SSLConstants():
    RSA = TYPE_RSA
    DSA = TYPE_DSA
    PEM = FILETYPE_PEM
    SSL_DIR = VFENSE_SSL_PATH
    SERVER = 'server'
    PRIV_NAME = 'server.key'
    CERT_NAME   = 'server.crt'
    CSR_NAME   = 'server.csr'
    SUBJECT = (
        'vFense Server', 'vFense',
        'vFense', 'US', 'FL', 'Miami'
    )
    EXPIRATION = (0, 60*60*24*365*10)
    PRIV_KEY = os.path.join(SSL_DIR, PRIV_NAME)
    CERT_KEY = os.path.join(SSL_DIR, CERT_NAME)
    CSR_KEY = os.path.join(SSL_DIR, CSR_NAME)
    SHA512 = 'sha512'
    TYPE_CSR = 1
    TYPE_CERT = 2
    TYPE_PKEY = 3
    EXTENSION = {
        1 : '.csr',
        2 : '.crt',
        3 : '.key'
    }

