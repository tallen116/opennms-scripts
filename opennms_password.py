import sys
from hashlib import sha256
from hashlib import md5
import base64
import random
import argparse

# Default static variables for the salted digest function
SALT_SIZE = 16
HASH_ITER = 100000

def md5_digest(message):
    """
    This hashes a md5 password for OpenNMS users.
    Not recommended.  Use salted hash instead.

    """

    input = bytearray(message, 'utf_8')

    message_digest = md5(input).digest()

    return message_digest.hex().upper()



def salt_digest(message, salt_size, iter, salt_string=None):
    """
    This hashes a salted password for OpenNMS users.

    message = The string to convert to the salt hash.
    salt_size = The size of the salt to use.
    iter = The amount of times to iterate using the hash.
    salt_string = Use a predefined salt that gets hashed using MD5.

    The steps taken for creating the digest
    1. The string message is converted to byte array
    2. A random 16 byte salt is generated
    3. The salt bytes are added to the message (salt + message)
    4. The sha256 hash function is applied to the salt and message
    5. The results of the hash will be iterated 100000 times
    6. The salt and final result of the hash are concatenated (salt + hash)
    7. The concatenation is encoded in BASE64 and returned as a string

    References
    http://www.jasypt.org/api/jasypt/1.8/org/jasypt/util/password/StrongPasswordEncryptor.html#constructor_detail
    https://github.com/jboss-fuse/jasypt/blob/master/jasypt/src/main/java/org/jasypt/digest/StandardStringDigester.java
    https://github.com/jboss-fuse/jasypt/blob/master/jasypt/src/main/java/org/jasypt/digest/StandardByteDigester.java
    https://github.com/jboss-fuse/jasypt/blob/master/jasypt/src/main/java/org/jasypt/util/password/StrongPasswordEncryptor.java
    """
    # The input string is converted into bytes
    input = bytearray(message, 'utf_8')

    # Create random Salt with size of 16 bytes
    # If salt_string is undefined use a random one
    if salt_string == None:
        salt_array = bytearray()
        for i in range(0, salt_size):
            salt_array.append(random.randint(0,255))
    else:
        _salt_md5 = md5(bytes(salt_string, 'utf_8')).digest()
        salt_array = bytearray(_salt_md5)

    # Keep consistent names    
    salt = salt_array

    # Add Salt and input
    message_digest = salt + input

    # Iterate hash the digest
    _hash = message_digest
    for i in range(0, iter):
        _hash = sha256(message_digest).digest()
        message_digest = _hash

    # Add salt + digest
    final_digest = salt_array + message_digest

    # Perform final BASE64 encode
    message_base64 = base64.b64encode(final_digest)

    return message_base64.decode('utf_8')


def cmd_line():
    parser = argparse.ArgumentParser(
        description='''Create password hash for OpenNMS.
            It returns the salt hash to add to users.xml.''')
    parser.add_argument('-p', '--password', required=True, type=str, help='the password in string format.')
    parser.add_argument('-s', '--salt', type=str, help='the salt string to use in place of random.')
    parser.add_argument('--md5', default=False, action='store_true', help='use the less secure MD5 hash.')
    args = parser.parse_args()

    # If md5 switch is provided return MD5 or return salted hash by default
    if args.md5:
        password_hash = md5_digest(args.password)
    else:
        if args.salt == None:
           password_hash = salt_digest(args.password, salt_size=SALT_SIZE, iter=HASH_ITER)
        else:
            password_hash = salt_digest(args.password, salt_size=SALT_SIZE, iter=HASH_ITER, salt_string=args.salt)
    
    #print(password_hash)
    sys.stdout.write(password_hash)


if __name__ == '__main__':
    cmd_line()
