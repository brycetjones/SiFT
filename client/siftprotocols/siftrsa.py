import sys, getopt, getpass
from base64 import b64encode, b64decode
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Signature import pss
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Util import Padding
from Crypto import Random

pubkeyfile = "serverPublic.pem" 
privkeyfile = "serverPrivate.pem"
signed = False

def generate_keypair():
    # Generate the keypair
    print('Generating a key pair...')
    keypair = RSA.generate(2048)
    save_publickey(keypair.publickey(), pubkeyfile)
    save_keypair(keypair, privkeyfile)

def save_publickey(pubkey, pubkeyfile):
    with open(pubkeyfile, 'wb') as f:
        f.write(pubkey.export_key(format='PEM'))

def load_publickey():
    with open(pubkeyfile, 'rb') as f:
        pubkeystr = f.read()
    try:
        return RSA.import_key(pubkeystr)
    except ValueError:
        print('Error: Cannot import public key from file ' + pubkeyfile)

def save_keypair(keypair, privkeyfile):
    passphrase = getpass.getpass('Enter a passphrase to protect the saved private key: ')
    with open(privkeyfile, 'wb') as f:
        f.write(keypair.export_key(format='PEM', passphrase=passphrase))

def load_keypair():
    passphrase = getpass.getpass('Enter a passphrase to decode the saved private key: ')
    try: 
        f = open(privkeyfile, 'rb')
    except FileNotFoundError:
        print('Keypair not found. Generating new keypair.')
        generate_keypair()
        f = open(privkeyfile, 'rb')
    
    keypairstr = f.read()
    try:
        return RSA.import_key(keypairstr, passphrase)
    except ValueError as e:
        raise(e)
        print('Error: Cannot import private key from file ' + privkeyfile)
        sys.exit(1)

# ----------
# encryption
# ----------

def encrypt(plaintext):
    # load the public key from the public key file and 
    # create an RSA cipher object
    pubkey = load_publickey()
    RSAcipher = PKCS1_OAEP.new(pubkey)

    #encrypt the AES key with the RSA cipher
    try:
        encsymkey = RSAcipher.encrypt(plaintext)
    except Exception as e:
        raise(e)

    # compute signature if needed
    # if signed:
    #     keypair = load_keypair(privkeyfile)
    #     signer = pss.new(keypair)
    #     hashfn = SHA256.new()
    #     hashfn.update(encsymkey+iv+ciphertext)
    #     signature = signer.sign(hashfn)

    # Output the encrypted key as  bytes
    output = b64encode(encsymkey)
    # if signed:
    #     output += newline(b'--- SIGNATURE ---')
    #     output += newline(b64encode(signature))

    return output

# ----------
# decryption
# ----------

def decrypt(encrypted):
    # Convert key from bytes
    encsymkey = b64decode(encrypted)

    # if signed and (not pubkeyfile):
    #     print('Error: Public key file is missing for encrypted input')
    #     sys.exit(1)

    # verify signature if needed
    # if signed:
    #     if not pubkeyfile:
    #         print('Error: Public key file is missing, signature cannot be verified.')
    #     else:
    #         pubkey = load_publickey()
    #         verifier = pss.new(pubkey)
    #         hashfn = SHA256.new()
    #         hashfn.update(encsymkey+iv+ciphertext)
    #         try:
    #             verifier.verify(hashfn, signature)
    #             print('Signature verification is successful.')
    #         except (ValueError, TypeError):
    #             print('Signature verification failed.')

    # load the private key from the private key file, create the RSA cipher object
    keypair = load_keypair()
    RSAcipher = PKCS1_OAEP.new(keypair)

    # decrypt the AES key and create the AES cipher object
    print("Ciphertext length:")
    print(len(encrypted))
    try:
        symkey = RSAcipher.decrypt(encsymkey)  
    except Exception as e:
        raise(e)
	
    return symkey

def newline(s):
    return s + b'\n'