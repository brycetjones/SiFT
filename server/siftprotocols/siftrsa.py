import sys, getopt, getpass
from base64 import b64encode, b64decode
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Signature import pss
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Util import Padding
from Crypto import Random

def generate_keypair():
    # Generate the keypair
    print('Generating a key pair...')
    keypair = RSA.generate(2048)
    
    # Write keypair to file 
    f = open('../keys/keypair.pem', 'w')
    f.write(keypair.export_key(format='PEM'))