import sys, getopt, getpass
from base64 import b64encode, b64decode
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Signature import pss
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Util import Padding
from Crypto import Random

pubkeyfile = "serverPublic.pem" 
privkeyfile = "keyPair.pem"
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

def load_publickey(pubkeyfile):
    with open(pubkeyfile, 'rb') as f:
        pubkeystr = f.read()
    try:
        return RSA.import_key(pubkeystr)
    except ValueError:
        print('Error: Cannot import public key from file ' + pubkeyfile)
        sys.exit(1)

def save_keypair(keypair, privkeyfile):
    passphrase = getpass.getpass('Enter a passphrase to protect the saved private key: ')
    with open(privkeyfile, 'wb') as f:
        f.write(keypair.export_key(format='PEM', passphrase=passphrase))

def load_keypair(privkeyfile):
    passphrase = getpass.getpass('Enter a passphrase to decode the saved private key: ')
    with open(privkeyfile, 'rb') as f:
        keypairstr = f.read()
    try:
        return RSA.import_key(keypairstr, passphrase=passphrase)
    except ValueError:
        print('Error: Cannot import private key from file ' + privkeyfile)
        sys.exit(1)

# ----------
# encryption
# ----------

def encrypt(plaintext):
    # load the public key from the public key file and 
    # create an RSA cipher object
    pubkey = load_publickey(pubkeyfile)
    RSAcipher = PKCS1_OAEP.new(pubkey)

    # Add padding
    padded_plaintext = Padding.pad(plaintext, AES.block_size, style='pkcs7')
	
    # generate a random symmetric key and a random IV, create an AES cipher object
    symkey = Random.get_random_bytes(32) # we use a 256 bit (32 byte) AES key
    AEScipher = AES.new(symkey, AES.MODE_CBC)
    iv = AEScipher.iv

    # encrypt the padded plaintext with the AES cipher
    ciphertext = AEScipher.encrypt(padded_plaintext)

    #encrypt the AES key with the RSA cipher
    encsymkey = RSAcipher.encrypt(symkey)  

    # compute signature if needed
    if signed:
        keypair = load_keypair(privkeyfile)
        signer = pss.new(keypair)
        hashfn = SHA256.new()
        hashfn.update(encsymkey+iv+ciphertext)
        signature = signer.sign(hashfn)

    # write out the encrypted AES key, the IV, the ciphertext, and the signature
    output = newline(b'--- ENCRYPTED AES KEY ---')
    output += newline(b64encode(encsymkey))
    output += newline(b'--- IV FOR CBC MODE ---')
    output += newline(b64encode(iv))
    output += newline(b'--- CIPHERTEXT ---')
    output += newline(b64encode(ciphertext))
    if signed:
        output += newline(b'--- SIGNATURE ---')
        output += newline(b64encode(signature))

    return output

# ----------
# decryption
# ----------

def decrypt(encrypted):
    print('Decrypting...')

    # read and parse the input
    encsymkey = b''
    iv = b''
    ciphertext = b''

    encrypted = encrypted.split('\n')
    for line, i in encrypted:
        if line == b'--- ENCRYPTED AES KEY ---':
            encsymkey = b64decode(encrypted[i+1])
        elif line == b'--- IV FOR CBC MODE ---':
            iv = b64decode(encrypted[i+1])
        elif line == b'--- CIPHERTEXT ---':
            ciphertext = b64decode(encrypted[i+1])
        elif line == b'--- SIGNATURE ---':
            signature = b64decode(encrypted[i+1])
            signed = True

    if (not encsymkey) or (not iv) or (not ciphertext):
        print('Error: Could not parse content of encrypted input')
        sys.exit(1)

    if signed and (not pubkeyfile):
        print('Error: Public key file is missing for encrypted input')
        sys.exit(1)

    # verify signature if needed
    if signed:
        if not pubkeyfile:
            print('Error: Public key file is missing, signature cannot be verified.')
        else:
            pubkey = load_publickey(pubkeyfile)
            verifier = pss.new(pubkey)
            hashfn = SHA256.new()
            hashfn.update(encsymkey+iv+ciphertext)
            try:
                verifier.verify(hashfn, signature)
                print('Signature verification is successful.')
            except (ValueError, TypeError):
                print('Signature verification failed.')

    # load the private key from the private key file, create the RSA cipher object
    keypair = load_keypair(privkeyfile)
    RSAcipher = PKCS1_OAEP.new(keypair)

    # decrypt the AES key and create the AES cipher object
    symkey = RSAcipher.decrypt(encsymkey)  
    AEScipher = AES.new(symkey, AES.MODE_CBC, iv)	
	
    # decrypt the ciphertext and remove padding
    try: 
        padded_plaintext = AEScipher.decrypt(ciphertext)
        plaintext = Padding.unpad(padded_plaintext, AES.block_size, style='pkcs7')
    except Exception as e:
        raise(e)
	
    return plaintext

def newline(s):
    return s + b'\n'