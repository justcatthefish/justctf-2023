def lambda_handler(event, context):
    return {
        "statusCode": 200,
        "body": "<html><body><h2>Was it even worth? Well, you are for sure close, but the flag is not here</h2></body></html>",
        "headers": {
            "Content-Type": "text/html"
        }
    }