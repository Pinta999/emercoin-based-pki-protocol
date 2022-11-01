from decouple import config

def gen_mConf():
    nonce = config('NONCE')
    message = {
        'command': 'CONF',
        'nonce': int(nonce),
        
    }