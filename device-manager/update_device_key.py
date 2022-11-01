import crypto
import emercoin

from cryptography.exceptions import InvalidSignature
import socket
import json
import tpm2_pytss
import tpm2_pytss.utils

DEFAULT_PORT = 12000

def gen_new_keypair():
    new_privkey = crypto.gen_rsa_key()
    new_pubkey = crypto.get_pubkey_from_privkey(new_privkey)
    return new_pubkey

def gen_mUpdt(old_privkey, new_pubkey):
    message = {
        'command': 'UPDT',
        'new_pubkey': crypto.get_pubkey_bytes(new_pubkey).hex()
    }
    signature = crypto.sign_message(
        old_privkey,
        json.dumps(message).encode()
    )
    message['signature'] = signature.hex()
    return message

def new_key_verify(msg):
    identity = msg['identity']
    signature = bytes.fromhex(msg['signature'])
    new_pubkey_bytes = bytes.fromhex(msg['new_pubkey'])
    new_pubkey = crypto.get_pubkey_from_bytes(new_pubkey_bytes)
    deviceIak = crypto.load_pubkey_from_file('devices/rasp-pi-4-1/iak.pem') #Modificare inserimento iniziale: anzichè IP mettere prod model e seriale, e all'interno del folder memorizzare l'IP corrispondente
    signedMessage = json.dumps({
        'identity': msg['identity'],
        'new_pubkey': msg['new_pubkey'],
        'cert_digest': msg['cert_digest']
    }).encode()


    ## Hashing with TSS2 ##
    ectx = tpm2_pytss.ESAPI(tcti=None)
    seqHandle = ectx.hash_sequence_start(b'1234', tpm2_pytss.TPM2_ALG.SHA256)
    ectx.tr_set_auth(seqHandle, b'1234')
    payloadSize = len(signedMessage)
    index = 0 
    while payloadSize > 1024:
        ectx.sequence_update(seqHandle, signedMessage[index : index + 1024])
        index = index + 1024
        payloadSize = payloadSize - 1024
    digest, ticket = ectx.sequence_complete(seqHandle, signedMessage[index : index + payloadSize])

    crypto.verify_signature(
        deviceIak,
        signature,
        digest.__bytes__(),
        'digest'
    )
    return identity, msg['cert_digest']

def update_device_key(identity, cert_digest):
    emercoin.updateValue(identity, cert_digest)

def store_new_key(identity, new_pubkey):
    with open(f'devices/{identity}/pubkey.pem', 'wb') as f:
        f.write(new_pubkey)


def check_confirmations():
    confirmations = emercoin.getTransactionConfirmations()
    while (confirmations < 6):
        print(f'Current confirmations: {confirmations}/6')
        print('(Number of mined blocks necessary to your transaction block to be considered secure is 6)\nAnother check will be performed in 5 minutes...')
        sleep(60*5)
        confirmations = emercoin.getTransactionConfirmations()
    print('Your block has reached 6 confirmations. Your device has been successfully registered.')

def gen_cReg():
    dm_privkey = crypto.load_privkey_from_file('keys/privkey.pem')
    with open('devices/rasp-pi-4-1/nonce', 'r') as f:
        nonce = int(f.read())
    with open('devices/rasp-pi-4-1/nonce', 'w') as f:
        f.write(str(nonce + 1))
    message = {
        'command': 'REGACK',
        'nonce': f'{nonce + 1}'
    }
    signature = crypto.sign_message(dm_privkey, json.dumps(message).encode())
    message['signature'] = signature.hex()
    return json.dumps(message).encode()

def update_key():
    device_address = input("Type device's IP address: ")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((device_address, DEFAULT_PORT))
    except socket.error:
        print('Device not connected. Closing...')
        return
    old_privkey = crypto.load_privkey_from_file('keys/privkey.pem')
    new_pubkey = gen_new_keypair()
    print('Sending UPDT command to the device...')
    msg = gen_mUpdt(old_privkey, new_pubkey)
    s.send(json.dumps(msg).encode())
    new_key_msg = s.recv(2048).decode()
    if not new_key_msg:
        print('Nothing received from device. Closing connection...')
        s.close()
        return
    msg_obj = json.loads(new_key_msg)
    try:
        new_key_verify(msg_obj)
        #update_device_key(msg_obj['identity'], msg_obj['cert_digest'])
    except InvalidSignature:
        print('Invalid signature from device. Closing connection')
        s.close()
        return
    except emercoin.JSONRPCException:
        print('UPDATE transaction failed. Closing connection...')
        s.close()
        return
    ## TODO: send REGACK, wait for device verification and finally update local data
    ##check_confirmations()
    print("New identity message signature verification [OK]")
    creg = gen_cReg()
    s.send(creg)
    s.recv(1)
    #store_new_key(msg_obj['identity'], bytes.fromhex(msg_obj['new_pubkey']))
    s.close()
    
