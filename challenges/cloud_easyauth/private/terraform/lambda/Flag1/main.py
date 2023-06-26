import os
from Crypto.Cipher import AES

hkey = os.environ.get('KEY', '0000000000000000')
hnonce = os.environ.get('NONCE', '0000000000000000')

def lambda_handler(event, context):
    key = bytes.fromhex(hkey)
    nonce = bytes.fromhex(hnonce)
    flag = event['flag']
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(flag)
    event_resp = tag.hex() + ciphertext.hex()

    return  {
        "statusCode": 200,
        "body": event_resp,
        "headers": {
            "Content-Type": "text/html"
        }
    }