import emercoin
import crypto

from time import sleep
from cryptography.exceptions import InvalidSignature
import socket
import json

DEFAULT_PORT = 12000

def load_new_owner_pubkey(keyfile_abs_path):
    with open(keyfile_abs_path, 'rb') as input:
        pem_lines = input.read()
    new_pubkey = crypto.get_pubkey_from_bytes(pem_lines)
    return new_pubkey

def gen_mOwnr(new_pubkey):
    old_privkey = crypto.load_privkey_from_file('keys/privkey.pem')
    command = 'OWNR'
    message = {
        'command': command,
        'new_pubkey': crypto.get_pubkey_bytes(new_pubkey).hex(),
    }
    signature = crypto.sign_message(
        old_privkey,
        json.dumps(message).encode()
    )
    message['signature'] = signature.hex()
    return message


def verify_identity_signature(signed_identity):
    identity = signed_identity['id']
    nonce = int(signed_identity['nonce'])
    
    with open(f'devices/{identity}/nonce', 'r') as f:
        stored_nonce = f.read()
        if (int(stored_nonce) >= nonce):
            print("Nonce error: old nonce")
            return -1
    
    with open(f'devices/{identity}/nonce', 'w') as f:
        f.write(f'{nonce}')
        
    with open(f'devices/{identity}/pubkey.pem', 'rb') as f:
        pem_lines = f.read()

    pubkey = crypto.get_pubkey_from_bytes(pem_lines)
    signature = bytes.fromhex(signed_identity['signature'])
    signed_message = json.dumps({
        'id': identity,
        'nonce': f'{nonce}'
    })
    crypto.verify_signature(
        pubkey,
        signature,
        signed_message.encode()
    )
    return identity

def update_transaction(deviceId, address):
    emercoin.transferOwnership(deviceId, address)

def check_confirmations():
    confirmations = emercoin.getTransactionConfirmations()
    while (confirmations < 6):
        print(f'Current confirmations: {confirmations}/6')
        print('(Number of mined blocks necessary to your transaction block to be considered secure is 6)\nAnother check will be performed in 5 minutes...')
        sleep(60*5)
        confirmations = emercoin.getTransactionConfirmations()
    print('Your block has reached 6 confirmations. Your device has been successfully registered.')


def gen_message(identity):
    privkey = crypto.load_privkey_from_file('keys/privkey.pem')
    with open(f'devices/{identity}/nonce', 'r') as f:
        stored_nonce = f.read()
    
    with open(f'devices/{identity}/nonce', 'w') as f:
        f.write(f'{int(stored_nonce) + 1}')

    message = {
        'command': 'REGACK',
        'nonce': f'{int(stored_nonce) + 1}'
    }
    signature = crypto.sign_message(privkey, json.dumps(message).encode())
    message['signature'] = signature.hex()
    return message

def ownership_transfer():
    keyfile_abs_path = input("Absolute path of the new owner's public key: ")
    try:
        new_owner_pubkey = load_new_owner_pubkey(keyfile_abs_path)
    except IOError:
        print('New public key file not found. Closing...')
        return
    ##new_owner_address = input("New owner's address: ")
    device_address = input("Device IP address: ")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((device_address, DEFAULT_PORT))
    except socket.error:
        print('Device not connected. Closing...')
        return
    
    mOwnr = gen_mOwnr(new_owner_pubkey)
    s.send(json.dumps(mOwnr).encode())
    identity_signed = s.recv(4096)
    identity_signed_obj = json.loads(identity_signed)
    try:
        identity = verify_identity_signature(identity_signed_obj)
        print('Ack message successfully verified!\n')
    except InvalidSignature:
        print('Identity signature not valid. Closing connection...')
        s.close()
        return
    except IOError:
        print('Error: device not registered. Closing connection...')
        s.close()
        return

    cmd = input(f'Are you sure to transfer the ownership of device: {identity} ? [y/n]\n')
    while (cmd != 'n' and cmd != 'y'):
        print('Unidentified option, please select [y/n]\n')
        cmd = input()
    if (cmd == 'n'):
        print('Canceling current operation...')
        s.close()
    elif (cmd == 'y'):
                
        ##update_transaction(identity, new_owner_address)
        ##check_confirmations()
        message = gen_message(identity)
        s.send(json.dumps(message).encode())

        ## Wait for IoT device ack verification and channel closure
        s.recv(1)
