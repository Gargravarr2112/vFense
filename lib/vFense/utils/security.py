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
    password = password.encode('utf-8')
    completed = False
    strength = [
        'Blank', 'Very Weak', 'Sort of Weak',
        'Medium', 'Sort of Strong', 'Strong',
        'Very Strong'
    ]
    score = 0
    mandatory = 0

    if len(password) < 1:
        return(completed, strength[0])

    if len(password) < 4:
        return(completed, strength[1])

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

    if score >= 5 and mandatory >= 4:
        completed = True

    elif score >= 5 and mandatory < 5:
        score = score - 1

    return(completed, strength[score])

from os import urandom
from random import choice

char_set = {
    'small': 'abcdefghijklmnopqrstuvwxyz',
    'nums': '0123456789',
    'big': 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
    'special': '^\$/()=?{[]}+~#-_.:,;<>|\\'
}

def check_prev_char(password, current_char_set):
    """Function to ensure that there are no consecutive 
    UPPERCASE/lowercase/numbers/special-characters."""

    index = len(password)
    if index == 0:
        return False
    else:
        prev_char = password[index - 1]
        if prev_char in current_char_set:
            return True
        else:
            return False

def generate_pass(length=8):
    """Function to generate a password"""
    password = []

    while len(password) < length:
        key = choice(list(char_set.keys()))
        a_char = urandom(1)
        if a_char in char_set[key]:
            if check_prev_char(password, char_set[key]):
                continue
            else:
                password.append(a_char)
    return ''.join(password)
