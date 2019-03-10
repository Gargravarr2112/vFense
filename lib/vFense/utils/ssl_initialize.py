from vFense.utils._constants import SSLConstants
from vFense.utils.ssltools import generate_private_key, create_cert_request, create_signed_certificate, save_key

def generate_generic_certs():
	server_pkey = generate_private_key(SSLConstants.RSA, 2048)
	server_csr = create_cert_request(server_pkey, SSLConstants.SUBJECT)
	server_cert = (create_signed_certificate(server_csr, server_pkey, 1,SSLConstants.EXPIRATION, digest=SSLConstants.SHA512))
	save_key(
		SSLConstants.SSL_DIR, server_pkey,
		SSLConstants.TYPE_PKEY, name=SSLConstants.SERVER
	)
	save_key(
		SSLConstants.SSL_DIR, server_cert,
		SSLConstants.TYPE_CERT, name=SSLConstants.SERVER
	)
	save_key(
		SSLConstants.SSL_DIR, server_csr,
		SSLConstants.TYPE_CSR, name=SSLConstants.SERVER
	)
