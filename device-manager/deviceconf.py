import crypto
import emercoin

from cryptography.exceptions import InvalidSignature
from socket import *
from time import sleep
import datetime
import json
import tpm2_pytss
import tpm2_pytss.utils

DEFAULT_PORT = 12000

def getIp():
    with socket(AF_INET, SOCK_DGRAM) as s:
        try:
            s.connect(('10.255.255.255', 1))
            HOST_ADDRESS = s.getsockname()[0]
        except Exception:
            HOST_ADDRESS = '127.0.0.1'
        finally:
            s.close()
    return HOST_ADDRESS
    

def select_days_exp():
    days_exp = input("Select expiration time [days] (MAX: 2): ")
    try:
        days_exp = int(days_exp)
        if (days_exp > 2):
            "Please, choose a number of days less than 2."
            select_days_exp()
    except ValueError:
        print("Please, type a number")
        select_days_exp()
    return days_exp


def generate_mInit():
    print("\nGenerating the initialization message M_init...")
    days_exp = select_days_exp()
    private_key = crypto.gen_rsa_key()
    pubkey_serialized = crypto.get_pubkey_bytes(crypto.get_pubkey_from_privkey(private_key))
    trusted_bnodes = [
        crypto.get_message_digest(pubkey_serialized).hex()
    ]
    exp_date = datetime.datetime.utcnow() + datetime.timedelta(days=days_exp)
    mInit = {
        'command': 'INIT',
        'pubkey': pubkey_serialized.hex(),
        #'trusted_bnodes': trusted_bnodes,
        'exp_date': exp_date.strftime("%d/%m/%Y, %H:%M"),
    }
    signature = crypto.sign_message(private_key, json.dumps(mInit).encode())
    mInit['signature'] = signature.hex()
    print("[OK]\n")
    return mInit

def verify_idevid(idevid):
    print("\n[   TCG Device Identification Procedure   ]\n\n")
    print("Extracting information from the TCG_CSR_IDEVID structure...\n")
    obj = json.loads(idevid, strict=False)
    csrContent = idevid.decode()[idevid.decode().find('{"hashAlgoId') : idevid.decode().find(', "signature"')]
    ekCert = idevid.decode()[idevid.decode().find("-----BEGIN") : idevid.decode().find('", "attestPub"')]
    prodModel = obj['csrContents']['prodModel']
    prodSerial = obj['csrContents']['prodSerial']
    identity = prodModel + '-' + str(int(prodSerial, 16))
    print(f"Device model name and serial number: {identity}\n")
    print(f"Verifying Endorsement Key certificate matching for {identity}...")
    with open(f'devices/{identity}/ek_cert.pem', 'rb') as f:
        storedEkCert = f.read()
    if storedEkCert != ekCert.encode():
        print("\nNon matching Endorsement Key Certificate\n")
        return
    print("[OK]\n")
    ectx = tpm2_pytss.ESAPI(tcti=None)
    iakPub, numBytes = tpm2_pytss.types.TPM2B_PUBLIC.unmarshal(bytes.fromhex(obj['csrContents']['attestPub']))    
    iakPem = iakPub.to_pem()
    iakPubkey = crypto.get_pubkey_from_bytes(iakPem)
    signature = bytes.fromhex(obj['signature'])    
    plaintext = csrContent.encode()

    ## Hashing with TSS2 ##
    seqHandle = ectx.hash_sequence_start(b'1234', tpm2_pytss.TPM2_ALG.SHA256)
    ectx.tr_set_auth(seqHandle, b'1234')
    payloadSize = len(plaintext)
    index = 0
    while payloadSize > 1024:
        ectx.sequence_update(seqHandle, plaintext[index : index + 1024])
        index = index + 1024
        payloadSize = payloadSize - 1024
    digest, ticket = ectx.sequence_complete(seqHandle, plaintext[index : index + payloadSize])
    print("Verifying TCG_CSR_IDEVID message signature using the provided public Attestation Key...")
    crypto.verify_signature(iakPubkey, signature, digest.__bytes__(), 'digest')
    print("[OK]\n")

    print(identity)
    return (iakPub, obj, identity)


def make_credential(iakPub, idevidObj):
    ectx = tpm2_pytss.ESAPI(tcti=None)
    ##iakPubCast = tpm2_pytss.types.TPM2B_PUBLIC(iakPub)
    iakPubName =  iakPub.get_name()
    #ekHandle = ectx.tr_deserialize(bytes.fromhex(idevidObj['csrContents']['serializedEk']))
    #print(ekHandle)
    print("Generating the credential for the challenge...")
    ek, numBytes = tpm2_pytss.types.TPM2B_PUBLIC.unmarshal(bytes.fromhex(idevidObj['csrContents']['serializedEk']))
    credential = tpm2_pytss.types.TPM2B_DIGEST(b'12345678912345678912345678912312')
    print(f"Generated credential: {credential}\n")
    #credentialBlob, secret = ectx.make_credential(ekHandle, credential, iakPubName)
    print("Generating encrypted credential blob using TPM2_MakeCredential...")
    credentialBlob, secret = tpm2_pytss.utils.make_credential(ek, credential, iakPubName)
    print("[OK]\n")
    credentialBytes = tpm2_pytss.TPM2B_ID_OBJECT.marshal(credentialBlob)  
    secretBytes = tpm2_pytss.TPM2B_ENCRYPTED_SECRET.marshal(secret)
    result = {
        "credentialBlob" : credentialBytes.hex(),
        "secret" : secretBytes.hex()
    }
    return (credential.buffer, result)


def verify_encrypted_identity(message, deviceIakPem):
    print("\n[   Encrypted identity message verification   ]\n\n")
    obj = json.loads(message)
    print("Extracting information from the received message...\n")
    encrypted_SN = obj['encrypted_SN']
    msg_signature = obj['signature']
    serialized_device_pubkey = obj['device_pubkey']
    dm_private_key = crypto.load_privkey_from_file('keys/privkey.pem')
    print("Decrypting the ciphered generated identity using the provided public key...")
    plaintext = crypto.asym_decrypted_message(dm_private_key, bytes.fromhex(encrypted_SN))
    print("[OK]\nRetrieving the public Attestation Key associated to the device...")
    deviceIak = crypto.get_pubkey_from_bytes(deviceIakPem)
    print("[OK]\n")
    signedMessage = json.dumps({
        'encrypted_SN': encrypted_SN,
        'cert_digest': obj['cert_digest'],
        'device_pubkey': serialized_device_pubkey
    }).encode()

    ectx = tpm2_pytss.ESAPI(tcti=None)
    ## Hashing with TSS2 ##
    seqHandle = ectx.hash_sequence_start(b'1234', tpm2_pytss.TPM2_ALG.SHA256)
    ectx.tr_set_auth(seqHandle, b'1234')
    payloadSize = len(signedMessage)
    index = 0 
    while payloadSize > 1024:
        ectx.sequence_update(seqHandle, signedMessage[index : index + 1024])
        index = index + 1024
        payloadSize = payloadSize - 1024
    digest, ticket = ectx.sequence_complete(seqHandle, signedMessage[index : index + payloadSize])

    print("Verifying signature using device's public Attestation Key...")
    crypto.verify_signature(
        deviceIak,
        bytes.fromhex(msg_signature),
        digest.__bytes__(),
        'digest'
    )

    print("[OK]\nCorrect signature! (Verified using device IAK)\n")
    return hex(int(plaintext.decode(), 16))[2:].zfill(64)
    ##fill to 64


def reg_confirmation(identity):
    command = input(f'Please confirm registration for {identity} [y/n]: ')
    if (command.lower() == 'y'):
        return True
    elif (command.lower() == 'n'):
        return False
    else:
        return reg_confirmation(identity)


def check_confirmations():
    confirmations = emercoin.getTransactionConfirmations()
    while (confirmations < 6):
        print(f'Current confirmations: {confirmations}/6')
        print('(Number of mined blocks necessary to your transaction block to be considered secure is 6)\nAnother check will be performed in 5 minutes...')
        sleep(60*5)
        confirmations = emercoin.getTransactionConfirmations()
    print('Your block has reached 6 confirmations. Your device has been successfully registered.')


def gen_cReg(dm_privkey):
    message = {
        'command': 'REGACK',
        'nonce': '1'
    }
    signature = crypto.sign_message(dm_privkey, json.dumps(message).encode())
    message['signature'] = signature.hex()
    return json.dumps(message).encode()

def update_device_list(identity, iakPub, pseudonym, exp_date, pubkey, nonce):
    with open(f'devices/{identity}/local_pubkey.pem', 'wb') as f:
        f.write(pubkey)
    with open(f'devices/{identity}/nonce', 'wb') as f:
        f.write(nonce.encode())
    with open(f'devices/{identity}/iak.pem', 'wb') as f:
        f.write(iakPub.to_pem())
    with open(f'devices/{identity}/configuration', 'w') as f:
        f.write(f"status=RUNNING\nid={pseudonym}\nexp_date={exp_date}\n")

def deviceconf():
    try: 
        deviceIP = input('Insert the IP address of a device in your network: ')
        s = socket(AF_INET, SOCK_STREAM)
        s.connect((deviceIP, DEFAULT_PORT))
    except error:
        print(f'{deviceIP} not found on your network')
        return

    minit = generate_mInit()
    s.send(json.dumps(minit).encode())

    idevid = b''
    end = False
    while not end:
        idevidTmp = s.recv(512)
        while len(idevidTmp) == 512:
            idevid = idevid + idevidTmp
            idevidTmp = s.recv(512)
        try:
            idevid = idevid + idevidTmp
            json.loads(idevid, strict=False)
            end = True
        except Exception:
            end = False

    try:
        iakPub, idevidObj, identity = verify_idevid(idevid)
    except InvalidSignature:
        print("Invalid idevid signature received!")
        s.close()
        return
    except Exception as e:
        print(e)
        s.close()
        return

    originalCredential, credentialMsg = make_credential(iakPub, idevidObj)
    print("Sending the encrypted credential blob to the device...")
    s.sendall(json.dumps(credentialMsg).encode())
    print("[OK]\nWaiting for the solution of the challenge from the device...\n")
    returnedCredential =  s.recv(128)
    print(f"Received challenge solution: {returnedCredential}\n")
    if originalCredential == returnedCredential:
        print("Correct credential. Successful TPM key attestation!")
    else:
        print("Invalid credential. TPM key attestation failure. Closing...")
        s.close()
        return
     
    encrypted_identity_message = b''
    end = False
    while not end:
        tmp = s.recv(512)
        while len(tmp) == 512:
            encrypted_identity_message = encrypted_identity_message + tmp
            tmp = s.recv(512)
        try:
            encrypted_identity_message = encrypted_identity_message + tmp
            json.loads(encrypted_identity_message, strict=False)
            end = True
        except Exception:
            end = False

    try:
        cert_SN = verify_encrypted_identity(encrypted_identity_message, iakPub.to_pem())
    except InvalidSignature:
        print(f'Received invalid signature from {deviceIP}. Closing connection...')
        s.close()
        
    identity_obj = json.loads(encrypted_identity_message.decode())

    ## Saving received identity on Emercoin NVS
    try:            
        if (reg_confirmation(cert_SN)):
            print(f'Trying to register {cert_SN} on Emercoin NVS...')
            emercoin.registerDevice(cert_SN, identity_obj['cert_digest'], 1)
            print('Registration request accepted. You should wait for transaction confirmation.')
        else:
            print('Registration process aborted. Closing connection...')
            s.close()
            exit()
    except emercoin.JSONRPCException as exc:
        print(f'Name-value registration failed...\nError:\n {exc.error}')
        print('Closing connection...')
        s.close()
        exit()

    ## Wait for block confirmation...
    ##check_confirmations()
        
    ## Send registration acknowledgment back to the iot-device
    print('Sending back registration acknowledgment...')
    message = gen_cReg(crypto.load_privkey_from_file('keys/privkey.pem'))
    s.sendall(message)

    update_device_list(identity, iakPub, cert_SN, minit['exp_date'], bytes.fromhex(identity_obj['device_pubkey']), '1')
