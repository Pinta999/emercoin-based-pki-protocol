import emercoin

def revoke_key():
    device_id = input('Type the ID of the device you want to revoke name of: ')
    try:
        emercoin.revokeName(device_id)
    except emercoin.JSONRPCExceptions:
        print('Transaction failed.')