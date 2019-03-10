import re
import bcrypt

import random


class Crypto():
	""" Helper functions to create, and verify, bcrypt encrypted strings. """

	@staticmethod
	def hash_bcrypt(password):
		return bcrypt.hashpw(password, bcrypt.gensalt())

	@staticmethod
	def verify_bcrypt_hash(password, _hash):
		try:
			if bcrypt.hashpw(password, _hash) == _hash:
				return True
		except Exception as e:
			print(e)
		return False

	@staticmethod
	def _random_salt(length):
		""" Random string to 'salt' up the hash.
		'length' shouldn't be > 255 because thats the size limit in the database where it's stored.
		"""
		if length > 255:
			length = 200    # Just in case, limited a bit more to save room for the hashes.

		return ''.join(chr(random.randint(0,255)) for i in range(length))

def check_password(password):
	suitable = False
	strength = ['Blank', 'Very Weak', 'Slightly Weak', 'Medium', 'Slightly Strong', 'Strong', 'Very Strong']
	score = 0
	mandatory = 0
	mandatory_score = 4

	if len(password) < 1:
		return(suitable, strength[0])

	if len(password) < 4:
		return(suitable, strength[1])

	if len(password) >= 8:
		score = score + 1
		mandatory += 1

	if len(password) >= 12:
		score = score + 1

	if re.search('[0-9]', password):
		score = score + 1
		mandatory += 1

	if re.search('[a-z]', password):
		score = score + 1
		mandatory += 1

	if re.search('[A-Z]', password):
		score = score + 1
		mandatory += 1

	if re.search('[ ,!,",#,\$,%,&,\',\(,\),\*\+,\,,\-,\.,/,:,;,\<,=,\>,\?,@,\[,\\,\],^,_,`,\{,|,\,},~]', password):
		score = score + 1
		mandatory += 1

	if score >= 5 and mandatory >= mandatory_score:
		suitable = True

	return(suitable, strength[score])

from os import urandom
from random import choice
import string

char_set = {
	'small': string.ascii_lowercase,
	'nums': string.digits,
	'big': string.ascii_uppercase,
	'special': '^\$/()=?{[]}+~#-_.:,;<>|\\'
}

def generate_pass(length=8):
	"""Function to generate a password"""
	char_sets = ''.join(char_set.values())
	suitable = False
	while not suitable:
		generated_password = ''.join(random.sample(char_sets, length))
		suitable, score = check_password(generated_password)
	return generated_password