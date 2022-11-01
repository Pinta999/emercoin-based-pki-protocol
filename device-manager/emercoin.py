from bitcoinrpc.authproxy import AuthServiceProxy, JSONRPCException
import json


def registerDevice(deviceId, certHash, exptime):
    rpc_connection = AuthServiceProxy("http://user:psw@127.0.0.1:9092")
    rpc_connection.name_new(deviceId, certHash, exptime, "", "hex")
    

## You have to wait for the block to be mined, before the call to 'name_show' ##
def getDeviceValue(deviceId):
    rpc_connection = AuthServiceProxy("http://user:psw@127.0.0.1:9092")
    rpc_connection.name_show(deviceId, "hex")

def transferOwnership(deviceId, newOwnerAddress):
    rpc_connection = AuthServiceProxy("http://user:psw@127.0.0.1:9092")
    rpc_connection.name_update(deviceId, "", 0, newOwnerAddress, "hex")

def updateValue(deviceId, value):
    ##ToDo
    rpc_connection = AuthServiceProxy("http://user:psw@127.0.0.1:9092")
    rpc_connection.name_update(deviceId, value, 0, "", "hex")

def revokeName(deviceId):
    rpc_connection = AuthServiceProxy("http://user:psw@127.0.0.1:9092")
    rpc_connection.name_delete(deviceId)

def getTransactionConfirmations():
    rpc_connection = AuthServiceProxy("http://user:psw@127.0.0.1:9092")
    transaction = rpc_connection.listtransactions("*", 1, 0, True)[0]
    return transaction['confirmations']

