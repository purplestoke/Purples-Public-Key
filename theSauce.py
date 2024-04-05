from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
import base64
import json

#GENERATE KEY PAIR
def genKeyPair(keySize=2048):
    privKey = rsa.generate_private_key(
        public_exponent=65537,
        key_size=keySize,
        backend=default_backend()
    )
    return privKey

#SAVE KEY TO FILE
def saveKey(key, filename, isPrivate=True):
    if isPrivate:
        pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
    else:
        pem = key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    with open(filename, 'wb') as pem_out:
        pem_out.write(pem)

#LOAD KEY FROM FILE
def loadKey(filename, isPrivate=True):
    with open(filename, 'rb') as pem_in:
        pemData = pem_in.read()

    if isPrivate:
        return serialization.load_pem_private_key(
            pemData, password=None, backend=default_backend()
        )
    else:
        return serialization.load_pem_public_key(
            pemData, backend=default_backend()
        )
    
#SIGN A FILE
def signFile(filePath):
    with open(filePath, 'rb') as f:
        data = f.read()
    privKey = loadKey('privateKey.pem')
    signature = privKey.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return base64.b64encode(signature)

#SIGN A MESSAGE
def signMessage(message):
    privKey = loadKey('privateKey.pem')
    message_bytes = message.encode('utf-8')
    signature = privKey.sign(
        message_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )  
    signature_base64 = base64.b64encode(signature)
    return signature_base64

#VERIFY SIGNATURE OF A FILE
def verifyFileSig(nonce):
    try:
        with open('hashes.json', 'r') as fhand:
            jData = json.load(fhand)

        if str(nonce) not in jData:
            raise ValueError("Nonce Not Found")

        signature = jData[str(nonce)]["signature"]
        msg = jData[str(nonce)]["msg"]
        with open(msg, 'rb') as f:
            data = f.read()
        
        sig = base64.b64decode(signature)
        publicKey = loadKey('publicKey.pem', isPrivate=False)
        
        publicKey.verify(
            sig,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except FileNotFoundError:
        return "File Not Found"
    except InvalidSignature:
        return False
    except Exception as e:
        return str(e)

#VERIFY THE SIGNATURE OF A MESSAGE
def verifyMsgSig(nonce):
    try:
        with open('hashes.json', 'r') as f:
            data = json.load(f)

        if str(nonce) not in data:
            return "Nonce Not Found"

        signature = data[str(nonce)]["signature"]
        msg = data[str(nonce)]["msg"]

        msgBytes = msg.encode('utf-8')
        sigBytes = base64.b64decode(signature)
        pubKey = loadKey('publicKey.pem', isPrivate=False)
        try:
            pubKey.verify(
                sigBytes,
                msgBytes,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception as e:
            return False
    except(KeyError, InvalidSignature, FileNotFoundError) as e:
        return False

#GENERATE A HASH FROM THE SIGNATURE AND A NONCE
def hashIt(signature, nonce):
    if isinstance(signature, str):
        signatureBytes = signature.encode('utf-8')
    else:
        signatureBytes = signature

    if isinstance(nonce, str):
        nonceBytes = nonce.encode('utf-8')
    else:
        nonceBytes = nonce

    # HASHING USING SHA256
    data_to_hash = signatureBytes + nonceBytes
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(data_to_hash)
    hash_bytes = digest.finalize()
    hash_hex = hash_bytes.hex()

    # UPDATE JSON FILE
    try:
        with open('hashes.json', 'r') as f:
            data = json.load(f)
    except FileNotFoundError:
        data = {}

    # UPDATE DATA WITH NONCE AND HASH
    data[str(nonce)] = {'signature': signature, 'hash': hash_hex}

    with open('hashes.json', 'w') as f:
        json.dump(data, f, indent=4)

    return hash_hex
