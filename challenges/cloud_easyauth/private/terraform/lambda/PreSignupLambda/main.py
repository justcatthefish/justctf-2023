import boto3
import secrets
import datetime
import os
from hashlib import sha256

TABLE_NAME = os.environ.get('TABLE_NAME')
DIFFICULTY = int(os.environ.get('DIFFICULTY', '26'))
PREFIX_LEN = int(os.environ.get('PREFIX_LEN', '22'))
VALID_TIME = int(os.environ.get('VALID_TIME', '3600'))

dynamodb = boto3.resource('dynamodb')
chall_table = dynamodb.Table(TABLE_NAME)

def verify_hash(prefix, answer):
    h = sha256((prefix + answer).encode())
    bits = ''.join(bin(i)[2:].zfill(8) for i in h.digest())
    return bits.startswith('0' * DIFFICULTY)

def get_prefix():
    return secrets.token_urlsafe(PREFIX_LEN)[:PREFIX_LEN].replace('-', 'b').replace('_', 'a')

def check_if_valid(creation_timestamp):
    timestamp_now = int(datetime.datetime.utcnow().timestamp())
    return timestamp_now - creation_timestamp < VALID_TIME

def get_challenge(username):
    try:
        resp = chall_table.get_item(
            Key={
                'username': username
            }
        )
    except Exception as err:
        print(f"Error when getting {username} from DynamoDB: {err}")
    
    return resp

def check_if_exists(item):
    if 'Item' in item:
        if 'challenge' in item['Item']:
            if item['Item']['challenge']:
                return True
    return False

def create_challenge(username):
    challenge = get_prefix()
    try:
        chall_table.put_item(
            Item={
                'username': username,
                'challenge': challenge,
                'timestamp': str(int(datetime.datetime.utcnow().timestamp()))
            }
        )
    except Exception as err:
        print(f"Error when creating {username} from DynamoDB: {err}")

    return challenge

def update_challenge(username):
    new_challenge = get_prefix()
    try:
        chall_table.update_item(
            Key={
                'username': username
            },
            UpdateExpression='SET challenge = :new_challenge, #ts = :new_timestamp',
            ExpressionAttributeValues={
                ':new_challenge': new_challenge,
                ':new_timestamp': str(int(datetime.datetime.utcnow().timestamp()))
            },
            ExpressionAttributeNames={
                '#ts': 'timestamp'
            }
        )
    except Exception as err:
        print(f"Error when updating {username} from DynamoDB: {err}")

    return new_challenge

def delete_challenge(username):
    try:
        chall_table.delete_item(
            Key={
                'username': username
            }
        )
    except Exception as err:
        print(f"Error when deleting {username} from DynamoDB: {err}")

def lambda_handler(event, context):
    print("Before modification: ")
    print(event)
    info = "One account should be enough, don't bruteforce it. PoW is a heavy one, so brace yourself (~10 minutes). Your password has to be 10+ characters, with at least 1 uppercase, 1 lowercase, 1 special character and 1 number (or you will have to solve new challenge)."

    username = event['userName']
    item = get_challenge(username)

    if 'request' in event and 'userAttributes' in event['request'] and 'custom:proof_of_work' in event['request']['userAttributes']:
        if check_if_exists(item):
            if check_if_valid(int(item['Item']['timestamp'])):
                prefix = item['Item']['challenge']
                answer = event['request']['userAttributes']['custom:proof_of_work']

                if verify_hash(prefix, answer):
                    # Correct PoW, continue with register
                    print("Successful PoW! After modification: ")
                    event['response']['autoConfirmUser'] = True
                    event['request']['userAttributes']['custom:Role'] = 'default_user'
                    print(event)
                    delete_challenge(username)
                    return event
                else:
                    print("Unsuccessful PoW - incorrect answer")
                    raise Exception(f"{info} {answer} is not correct for challenge: {prefix} - and difficulty: {DIFFICULTY}.")
            else:
                print("Unsuccessful PoW - chall expired")
                new_challenge = update_challenge(username)
                raise Exception(f'{info} Challenge expired, generated new challenge: {new_challenge} - difficulty: {DIFFICULTY}')
        else:
            print("Unsuccessful PoW - lack of chall for given user")
            new_challenge = create_challenge(username)
            raise Exception(f'{info} Lack of challenge for given username, generated new challenge: {new_challenge} - difficulty: {DIFFICULTY}')
    else:
        if check_if_exists(item):
            if check_if_valid(int(item['Item']['timestamp'])):
                print("Unsuccessful PoW - lack of correct attribute for existing chall")
                challenge = item['Item']['challenge']
                
            else:
                print("Unsuccessful PoW - lack of correct attribute for expired chall")
                challenge = update_challenge(username)
        else:
            print("Unsuccessful PoW - lack of correct attribute & chall")
            challenge = create_challenge(username)
        raise Exception(f'{info} Lack of attribute \'custom:proof_of_work\' in request. As value give answer for challenge: {challenge} - difficulty: {DIFFICULTY}')

