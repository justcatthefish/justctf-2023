import boto3

cognito_idp = boto3.client('cognito-idp')

def lambda_handler(event, context):
    print(event)

    resp = cognito_idp.admin_update_user_attributes(
        UserPoolId=event['userPoolId'],
        Username=event['userName'],
        UserAttributes=[{
            'Name': 'custom:role',
            'Value': 'default_role'
        }]
    )
    print(resp)
    return event