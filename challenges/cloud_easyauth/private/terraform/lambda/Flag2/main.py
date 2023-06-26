import boto3
import os
from Crypto.Cipher import AES

BUCKET_NAME = os.environ.get('BUCKET_NAME', 'secrets')
s3 = boto3.client('s3')

def get_value(name):
    if os.path.isfile(f'/tmp/{name}'):
        with open(f'/tmp/{name}', 'r') as f:
            var = f.read()
    else:
        var_resp = s3.get_object(Bucket=BUCKET_NAME, Key=name)
        var = var_resp['Body'].read().decode('utf-8')
        with open(f'/tmp/{name}', 'w+') as f:
            f.write(var)

    print(f'{name}: {var}')

    if name == 'flag':
        return var.encode()
    
    var = bytes.fromhex(var)
    return var

def lambda_handler(event, context):
    key = get_value('key')
    nonce = get_value('nonce')
    flag = get_value('flag')

    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(flag)
    event_resp = tag.hex() + ciphertext.hex()
    print(event_resp)
    return  {
        "statusCode": 200,
        "body": event_resp,
        "headers": {
            "Content-Type": "text/html"
        }
    }