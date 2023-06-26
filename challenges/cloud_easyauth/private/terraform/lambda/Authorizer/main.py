import os
import re
import jwt
import json
import boto3
import urllib3

REGION = os.environ.get('REGION', 'eu-west-1')
USER_POOL_ID = os.environ.get('USER_POOL_ID')
KEYS_URL = f'https://cognito-idp.{REGION}.amazonaws.com/{USER_POOL_ID}/.well-known/jwks.json'
MOD_ROLE = os.environ.get('MOD_ROLE', 'fishy_moderator')

cognito = boto3.client('cognito-idp')

class HttpVerb:
    GET = 'GET'
    POST = 'POST'
    PUT = 'PUT'
    PATCH = 'PATCH'
    HEAD = 'HEAD'
    DELETE = 'DELETE'
    OPTIONS = 'OPTIONS'
    ALL = '*'

class AuthPolicy():
    awsAccountId = ''
    principalId = ''
    version = '2012-10-17'
    pathRegex = '^[/.a-zA-Z0-9-\*]+$'
    allowMethods = []
    denyMethods = []
    restApiId = '*'
    region = '*'
    stage = '*'

    def __init__(self, principal, awsAccountId):
        self.awsAccountId = awsAccountId
        self.principalId = principal
        self.allowMethods = []
        self.denyMethods = []

    def _addMethod(self, effect, verb, resource, conditions):
        if verb != '*' and not hasattr(HttpVerb, verb):
            raise NameError('Invalid HTTP verb ' + verb + '. Allowed verbs in HttpVerb class')
        resourcePattern = re.compile(self.pathRegex)
        if not resourcePattern.match(resource):
            raise NameError('Invalid resource path: ' + resource + '. Path should match ' + self.pathRegex)

        if resource[:1] == '/':
            resource = resource[1:]

        resourceArn = 'arn:aws:execute-api:{}:{}:{}/{}/{}/{}'.format(self.region, self.awsAccountId, self.restApiId, self.stage, verb, resource)

        if effect.lower() == 'allow':
            self.allowMethods.append({
                'resourceArn': resourceArn,
                'conditions': conditions
            })
        elif effect.lower() == 'deny':
            self.denyMethods.append({
                'resourceArn': resourceArn,
                'conditions': conditions
            })

    def _getEmptyStatement(self, effect):
        statement = {
            'Action': 'execute-api:Invoke',
            'Effect': effect[:1].upper() + effect[1:].lower(),
            'Resource': []
        }

        return statement

    def _getStatementForEffect(self, effect, methods):
        statements = []

        if len(methods) > 0:
            statement = self._getEmptyStatement(effect)

            for curMethod in methods:
                if curMethod['conditions'] is None or len(curMethod['conditions']) == 0:
                    statement['Resource'].append(curMethod['resourceArn'])
                else:
                    conditionalStatement = self._getEmptyStatement(effect)
                    conditionalStatement['Resource'].append(curMethod['resourceArn'])
                    conditionalStatement['Condition'] = curMethod['conditions']
                    statements.append(conditionalStatement)

            if statement['Resource']:
                statements.append(statement)

        return statements

    def allowAllMethods(self):
        self._addMethod('Allow', HttpVerb.ALL, '*', [])

    def denyAllMethods(self):
        self._addMethod('Deny', HttpVerb.ALL, '*', [])

    def allowMethod(self, verb, resource):
        self._addMethod('Allow', verb, resource, [])

    def denyMethod(self, verb, resource):
        self._addMethod('Deny', verb, resource, [])

    def allowMethodWithConditions(self, verb, resource, conditions):
        self._addMethod('Allow', verb, resource, conditions)

    def denyMethodWithConditions(self, verb, resource, conditions):
        self._addMethod('Deny', verb, resource, conditions)

    def build(self):
        if ((self.allowMethods is None or len(self.allowMethods) == 0) and
                (self.denyMethods is None or len(self.denyMethods) == 0)):
            raise NameError('No statements defined for the policy')

        policy = {
            'principalId': self.principalId,
            'policyDocument': {
                'Version': self.version,
                'Statement': []
            }
        }

        policy['policyDocument']['Statement'].extend(self._getStatementForEffect('Allow', self.allowMethods))
        policy['policyDocument']['Statement'].extend(self._getStatementForEffect('Deny', self.denyMethods))

        return policy

def get_public_keys():
    try:
        http = urllib3.PoolManager()
        resp = http.request('GET', KEYS_URL)
        jwks = json.loads(resp.data.decode())
    except Exception as err:
        print(f'Requesting JWKS failed: {err}')

    public_keys = {}
    for jwk in jwks['keys']:
        kid = jwk['kid']
        public_keys[kid] = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(jwk))
    
    return public_keys

def get_jwt_payload(token):
    public_keys = get_public_keys()
    kid = jwt.get_unverified_header(token)['kid']
    try:
        key = public_keys[kid]
    except KeyError as err:
        print(f'Lack of public key with given kid: {err}')
    try:
        payload = jwt.decode(token, key=key, algorithms=['RS256'])
    except Exception as err:
        print(f'Invalid signature: {err}')
    return payload
    
def get_user_role(token):
    resp = cognito.get_user(AccessToken=token)
    role = None
    for attr in resp['UserAttributes']:
        if attr['Name'] == 'custom:role':
            role = attr['Value'] 
    if role is None:
        raise Exception(f'Lack of Role attribute')
    return role

def check_if_allowed(role, path):
    if role == MOD_ROLE:
        return True
    elif role == 'default_role':
        if path == 'home':
            return True
        else:
            return False
    else:
        return False

def lambda_handler(event, context):
    print(event)
    if 'authorization' in event['headers']:
        token = event['headers']['authorization']
    elif 'Authorization' in event['headers']:
        token = event['headers']['Authorization']
    else:
        print('Lack of authorization token')
        raise Exception('Lack of authorization token')

    if 'Bearer' in token:
        token = token.split('Bearer')[1].strip()
    
    methodArn = event['methodArn']
    tmp = methodArn.split(':')
    api_gw_arn_tmp = tmp[5].split('/')
    awsAccountId = tmp[4]

    payload = get_jwt_payload(token)
    role = get_user_role(token)
    principalId = f'{payload["username"]}:{role}'

    policy = AuthPolicy(principalId, awsAccountId)
    policy.restApiId = api_gw_arn_tmp[0]
    policy.region = tmp[3]
    policy.stage = api_gw_arn_tmp[1]
    
    print(f'User: {payload["username"]} Role: {role} methodArn: {methodArn} apiGw: {api_gw_arn_tmp}')

    if check_if_allowed(role, api_gw_arn_tmp[3]):
        policy.allowAllMethods()
    else:
        policy.denyAllMethods()

    authResponse = policy.build()
    print(f'Policy: {authResponse}')

    return authResponse