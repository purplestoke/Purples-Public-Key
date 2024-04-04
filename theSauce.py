from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.backends import default_backend
import base64

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
def signFile(privKey, filePath):
    with open(filePath, 'rb') as f:
        data = f.read()

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
def verifyFileSig(publicKey, signature, filePath):
    with open(filePath, 'rb') as f:
        data = f.read()
        sig = base64.b64decode(signature)
        try:
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
        except Exception as e:
            return False

#VERIFY THE SIGNATURE OF A MESSAGE
def verifyMsgSig(publicKey, signature, msg):
    msgBytes = msg.encode('utf-8')
    sigBytes = base64.b64decode(signature)
    try:
        publicKey.verify(
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






